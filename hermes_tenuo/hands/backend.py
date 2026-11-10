"""The Hermes terminal backend named `hands`: commands and file tools run on a device.

Loaded only inside Hermes. The base class supplies cwd tracking and the file tools;
this class only decides where one bash command runs.
"""

from __future__ import annotations

import collections
import threading
from typing import Any, Optional

from agent.terminal_env_provider import TerminalEnvironmentProvider
from tools.environments.base import BaseEnvironment
from tools.environments.base_output import _ThreadedProcessHandle

from hermes_tenuo.hands.hub import HandsUnavailable, get_hub

NAME = "hands"


class HandsEnvironment(BaseEnvironment):
    def __init__(self, cwd: str, timeout: int, device: str = "", task_id: str = ""):
        hub = get_hub()
        if hub is None:
            raise HandsUnavailable("hands: Hands isn't running in this Hermes process. Set hands.listen in the "
                                   "hermes-tenuo plugin config and restart Hermes.")
        self._hub = hub
        self._task = task_id
        self._device = device
        self._session = hub.pick(device)
        self._folder = self._session.folder
        self._wrapped: "collections.deque[tuple]" = collections.deque(maxlen=32)
        super().__init__(cwd=self._folder, timeout=timeout)
        self.init_session()

    def get_temp_dir(self) -> str:
        # Hermes keeps this session's small files (shell snapshot, background logs) in the
        # device's own temp folder, the only place outside the shared folder it can write.
        return self._session.tmp or "/tmp"

    def _current(self):
        """The device session to use now. A device that came back (new time window, restart)
        has a new session; this conversation follows it instead of holding on to the old one."""
        session = self._hub.pick(self._device)
        if session is not self._session:
            moved = session.device != self._session.device or session.tmp != self._session.tmp
            self._session, self._folder = session, session.folder
            if not self._inside(self.cwd):
                self.cwd = self._folder
            if moved:
                # Another machine: this session's files are not there, so set it up again.
                temp_dir = self.get_temp_dir().rstrip("/") or "/"
                if hasattr(self, "_snapshot_path"):
                    self._snapshot_path = f"{temp_dir}/hermes-snap-{self._session_id}.sh"
                if hasattr(self, "_cwd_file"):
                    self._cwd_file = f"{temp_dir}/hermes-cwd-{self._session_id}.txt"
                self.cwd = self._folder
                self.init_session()
        return session

    def _inside(self, path: str) -> bool:
        return bool(path) and (path == self._folder or path.startswith(self._folder + "/"))

    def execute(self, command: str, cwd: str = "", **kwargs: Any) -> dict:
        try:
            self._current()
        except HandsUnavailable:
            pass  # the command itself reports the missing device
        # Hermes passes its own default directory until the session has one on the
        # device; anything outside the granted folder starts in the folder.
        if not self._inside(cwd):
            cwd = self.cwd if self._inside(self.cwd) else self._folder
        return super().execute(command, cwd, **kwargs)

    def _wrap_command(self, command: str, cwd: str) -> str:
        # Remember which plain command each wrapped script came from, for the device's log.
        wrapped = super()._wrap_command(command, cwd)
        self._wrapped.append((wrapped, command))
        return wrapped

    def _run_bash(self, cmd_string: str, *, login: bool = False, timeout: int = 120,
                  stdin_data: Optional[str] = None):
        shown = self._plain(cmd_string)
        stopped = threading.Event()  # set when Hermes interrupts the call
        # Who is asking is known here, in the call's own context, not in the thread that
        # waits for the device. This is checked again where the command leaves the server,
        # so it holds on a Hermes that cannot wrap tool calls and for a whole-profile backend.
        from hermes_tenuo.hands import chat
        asking = chat._owner()

        def run() -> tuple:
            try:
                session = self._hub.pick(self._device)
                if session.owner and session.owner != asking:
                    return (f"hands: '{session.name}' belongs to the person who paired it; this command was "
                            "not run\n"), 126
                return self._hub.run(session, cmd_string, login=login, timeout=timeout,
                                     stdin=stdin_data, shown=shown, cancelled=stopped)
            except HandsUnavailable as e:
                return f"{e}\n", 127

        return _ThreadedProcessHandle(run, cancel_fn=stopped.set)

    def _plain(self, script: str) -> str:
        """The command as Hermes was asked to run it. Hermes wraps each command in session
        bookkeeping, may add stdin handling, and may spawn it from another thread, so the
        plain text is looked up by the wrapped script it produced."""
        for wrapped, command in reversed(self._wrapped):
            if wrapped in script:
                return command
        return ""

    def cleanup(self) -> None:
        pass


class HandsProvider(TerminalEnvironmentProvider):
    name = NAME
    display_name = "Hands (your own machine)"
    is_remote = True
    is_container = True  # its own filesystem: file tools resolve paths on the device

    @property
    def description(self) -> str:
        return "Run commands and file tools on a paired machine of yours, in one folder, for a set time."

    @property
    def env_description(self) -> str:
        return ("Commands and file tools run on the user's own machine through Hands, inside the one folder "
                "they shared. Writes outside that folder fail.")

    @property
    def skip_container_guards(self) -> bool:
        return False  # it is the user's real machine: keep the dangerous-command checks on

    def is_available(self) -> bool:
        return get_hub() is not None

    def create_environment(self, *, cwd: str, timeout: int, task_id: str = "default", **kwargs: Any):
        from hermes_tenuo.hands import chat
        # The device chosen for the call in progress; Hermes's key for the environment is
        # not always the conversation's task id, so it is not looked up by that alone.
        chosen = chat.current_device()
        return HandsEnvironment(cwd, timeout, device=chosen if chosen is not None else chat.device_for(task_id),
                                task_id=task_id)
