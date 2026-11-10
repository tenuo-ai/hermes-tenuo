"""The Hermes terminal backend named `hands`: commands and file tools run on a device.

Loaded only inside Hermes. The base class supplies cwd tracking and the file tools;
this class only decides where one bash command runs.
"""

from __future__ import annotations

import threading
from typing import Any, Optional

from agent.terminal_env_provider import TerminalEnvironmentProvider
from tools.environments.base import BaseEnvironment
from tools.environments.base_output import _ThreadedProcessHandle

from hermes_tenuo.hands.hub import HandsUnavailable, get_hub

NAME = "hands"


class HandsEnvironment(BaseEnvironment):
    def __init__(self, cwd: str, timeout: int, device: str = ""):
        hub = get_hub()
        if hub is None:
            raise HandsUnavailable("hands: Hands isn't running in this Hermes process. Set hands.listen in the "
                                   "hermes-tenuo plugin config and restart Hermes.")
        self._hub = hub
        self._session = hub.pick(device)
        self._folder = self._session.folder
        self._shown = threading.local()
        super().__init__(cwd=self._folder, timeout=timeout)
        self.init_session()

    def _inside(self, path: str) -> bool:
        return bool(path) and (path == self._folder or path.startswith(self._folder + "/"))

    def execute(self, command: str, cwd: str = "", **kwargs: Any) -> dict:
        # Hermes passes its own default directory until the session has one on the
        # device; anything outside the granted folder starts in the folder.
        if not self._inside(cwd):
            cwd = self.cwd if self._inside(self.cwd) else self._folder
        self._shown.text = command
        try:
            return super().execute(command, cwd, **kwargs)
        finally:
            self._shown.text = ""

    def _run_bash(self, cmd_string: str, *, login: bool = False, timeout: int = 120,
                  stdin_data: Optional[str] = None):
        shown = getattr(self._shown, "text", "")

        def run() -> tuple:
            try:
                return self._hub.run(self._session, cmd_string, login=login, timeout=timeout,
                                     stdin=stdin_data, shown=shown)
            except HandsUnavailable as e:
                return f"{e}\n", 127

        return _ThreadedProcessHandle(run)

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
        return HandsEnvironment(cwd, timeout, device=chat.device_for(task_id))
