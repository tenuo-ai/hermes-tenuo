"""
Tenuo Cloud integration for hermes-tenuo.

Provides:
- connect token parsing
- trigger-based warrant minting (POST /v1/triggers/{id}/fire)
- Cloud-backed approval handler (POST /v1/approvals/requests + polling)
"""

from __future__ import annotations

import base64
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hermes_tenuo._cloud")

DEFAULT_BASE_URL = "https://api.tenuo.ai"
CONNECT_TOKEN_PREFIX = "tenuo_ct_"
_POLL_INTERVAL = 3.0   # seconds between approval status polls
_POLL_TIMEOUT = 300.0  # 5 minutes max wait for approval


# ---------------------------------------------------------------------------
# Connect token
# ---------------------------------------------------------------------------

@dataclass
class ConnectTokenData:
    endpoint: str    # e.g. https://api.tenuo.ai/v1
    api_key: str     # tc_...
    agent_id: str = ""
    registration_token: str = ""


def parse_connect_token(token: str) -> Optional[ConnectTokenData]:
    """Parse a Tenuo Cloud connect token into its components.

    Connect token format: ``tenuo_ct_`` + RawURLBase64(JSON)
    JSON fields: v (version), e (endpoint), k (api_key),
                 a (agent_id, optional), t (registration_token, optional)
    """
    if not token:
        return None
    raw = token
    if raw.startswith(CONNECT_TOKEN_PREFIX):
        raw = raw[len(CONNECT_TOKEN_PREFIX):]
    try:
        # RawURL base64 (no padding) — add padding if needed
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
        endpoint = payload.get("e", DEFAULT_BASE_URL)
        # Normalize: ensure /v1 suffix
        endpoint = endpoint.rstrip("/")
        if not endpoint.endswith("/v1"):
            endpoint = f"{endpoint}/v1"
        return ConnectTokenData(
            endpoint=endpoint,
            api_key=payload.get("k", ""),
            agent_id=payload.get("a", ""),
            registration_token=payload.get("t", ""),
        )
    except Exception as exc:
        logger.debug("Failed to parse connect token: %s", exc)
        return None


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _api_request(
    method: str,
    url: str,
    api_key: str,
    body: Optional[Dict[str, Any]] = None,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """Make an authenticated API request to Tenuo Cloud."""
    data = json.dumps(body, separators=(",", ":")).encode() if body else None
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode())
        except Exception:
            err_body = {"error": e.reason or str(e.code)}
        code = err_body.get("code") or err_body.get("error", {}).get("code", "")
        msg = (
            (err_body.get("error", {}).get("message") if isinstance(err_body.get("error"), dict) else None)
            or err_body.get("message")
            or str(e)
        )
        raise CloudAPIError(f"HTTP {e.code} {code}: {msg}", status_code=e.code) from e
    except urllib.error.URLError as e:
        raise CloudAPIError(f"Cannot reach {url}: {e.reason}") from e


class CloudAPIError(Exception):
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


# ---------------------------------------------------------------------------
# Trigger-based warrant minting
# ---------------------------------------------------------------------------

@dataclass
class FireTriggerResult:
    warrant_b64: str      # base64-encoded signed warrant CBOR
    warrant_id: str
    expires_at: str
    trusted_root_b64: str  # base64 issuer public key extracted from the warrant


def fire_trigger(
    trigger_id: str,
    *,
    api_key: str,
    endpoint: str,
    event_data: Optional[Dict[str, Any]] = None,
    initiator_identity: str = "",
) -> FireTriggerResult:
    """Fire a trigger to get a Cloud-issued warrant.

    POST {endpoint}/triggers/{trigger_id}/fire
    Returns FireTriggerResult with the signed warrant and its issuer public key.
    """
    body: Dict[str, Any] = {}
    if event_data:
        body["event_data"] = event_data
    if initiator_identity:
        body["initiator"] = {"type": "api_key", "identity": initiator_identity}

    url = f"{endpoint}/triggers/{trigger_id}/fire"
    resp = _api_request("POST", url, api_key, body=body)

    warrant_b64 = resp.get("warrant", "")
    if not warrant_b64:
        raise CloudAPIError("trigger fire response missing 'warrant' field")

    # Extract trusted_root from the warrant's issuer public key
    trusted_root_b64 = _extract_issuer_b64(warrant_b64)

    return FireTriggerResult(
        warrant_b64=warrant_b64,
        warrant_id=resp.get("warrant_id", ""),
        expires_at=resp.get("expires_at", ""),
        trusted_root_b64=trusted_root_b64,
    )


def _extract_issuer_b64(warrant_b64: str) -> str:
    """Extract the issuer public key from a warrant as base64."""
    try:
        from tenuo_core import Warrant
        w = Warrant.from_bytes(base64.b64decode(warrant_b64))
        issuer = w.issuer
        if issuer is None:
            return ""
        # issuer may be PublicKey object or bytes
        if hasattr(issuer, "to_bytes"):
            return base64.b64encode(issuer.to_bytes()).decode()
        return base64.b64encode(bytes(issuer)).decode()
    except Exception as exc:
        logger.debug("Could not extract issuer from warrant: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Cloud approval handler
# ---------------------------------------------------------------------------

def make_cloud_approval_handler(
    api_key: str,
    endpoint: str,
    signing_key: Optional[Any] = None,
    poll_interval: float = _POLL_INTERVAL,
    poll_timeout: float = _POLL_TIMEOUT,
):
    """Return an ApprovalHandler that routes approval gates through Tenuo Cloud.

    When a warrant approval gate fires, the handler:
    1. Submits POST /v1/approvals/requests to Cloud
    2. Polls until status != "pending" (approved/denied/expired)
    3. Returns signed approvals to the enforcement layer

    This is a synchronous handler suitable for Hermes's pre_tool_call hook.
    The poll_timeout (default 5min) limits how long the hook can block.
    """

    def handler(request: Any) -> List[Any]:
        """Synchronous Cloud approval handler for Hermes pre_tool_call."""
        from tenuo_core import py_compute_request_hash as _compute_hash

        try:
            warrant_id = getattr(request, "warrant_id", None) or ""
            tool = getattr(request, "tool", "") or ""
            holder_key_raw = getattr(request, "holder_key", None)
            request_hash = getattr(request, "request_hash", None)

            if holder_key_raw is None or request_hash is None:
                logger.warning("cloud approval handler: incomplete request, skipping Cloud submission")
                raise _ApprovalRequired(request)

            # Serialize holder_key to bytes
            if hasattr(holder_key_raw, "to_bytes"):
                holder_key_bytes = holder_key_raw.to_bytes()
            else:
                holder_key_bytes = bytes(holder_key_raw)

            # Serialize args
            args_cbor_b64 = _serialize_args_cbor_b64(request)

            # Build attestation if signing key available
            attestation = None
            if signing_key is not None:
                try:
                    from tenuo_core import py_build_approval_context_attestation as _build_attest
                    attest_bytes = _build_attest(request_hash, signing_key)
                    attestation = {
                        "version": "cbor-canonical-v1",
                        "data": base64.b64encode(bytes(attest_bytes)).decode(),
                    }
                except Exception as exc:
                    logger.debug("Could not build attestation: %s", exc)

            # Create approval request
            url = f"{endpoint}/approvals/requests"
            body: Dict[str, Any] = {
                "warrant_id": warrant_id,
                "tool": tool,
                "request_hash": bytes(request_hash).hex() if not isinstance(request_hash, str) else request_hash,
                "holder_key": holder_key_bytes.hex(),
                "args_canonical_cbor_b64": args_cbor_b64,
            }
            if attestation:
                body["approval_context_attestation"] = attestation

            resp = _api_request("POST", url, api_key, body=body)
            request_id = resp.get("id", "")
            if not request_id:
                raise CloudAPIError("approval request response missing 'id'")

            logger.info(
                "hermes-tenuo: approval request submitted for tool '%s' (id=%s)",
                tool, request_id,
            )

            # Poll until resolved
            deadline = time.monotonic() + poll_timeout
            status = resp.get("status", "pending")
            while status == "pending":
                if time.monotonic() > deadline:
                    raise _ApprovalTimeout(f"Approval for '{tool}' timed out after {poll_timeout}s")
                time.sleep(poll_interval)
                poll_resp = _api_request("GET", f"{endpoint}/approvals/requests/{request_id}", api_key)
                status = poll_resp.get("status", "pending")
                resp = poll_resp

            if status == "denied":
                reason = resp.get("denial_reason") or "Approval denied"
                raise _ApprovalDenied(f"Approval for '{tool}' was denied: {reason}")

            if status == "expired":
                raise _ApprovalExpired(f"Approval request for '{tool}' expired")

            # Extract signed approvals from responses
            responses = resp.get("responses") or []
            approvals = []
            for r in responses:
                signed_hex = r.get("signed_approval")
                if signed_hex:
                    try:
                        from tenuo_core import SignedApproval
                        sa = SignedApproval.from_bytes(bytes.fromhex(signed_hex))
                        approvals.append(sa)
                    except Exception as exc:
                        logger.warning("Could not deserialize SignedApproval: %s", exc)

            logger.info(
                "hermes-tenuo: approval granted for tool '%s' (%d signature(s))",
                tool, len(approvals),
            )
            return approvals

        except (_ApprovalDenied, _ApprovalExpired, _ApprovalTimeout):
            raise
        except CloudAPIError as exc:
            logger.warning("hermes-tenuo: Cloud approval failed: %s", exc)
            # Re-raise as ApprovalRequired so enforcement can handle it
            raise _ApprovalRequired(request) from exc
        except Exception as exc:
            logger.warning("hermes-tenuo: unexpected approval error: %s", exc)
            raise _ApprovalRequired(request) from exc

    return handler


def _serialize_args_cbor_b64(request: Any) -> str:
    """Serialize tool args to canonical CBOR base64 for the approval request."""
    try:
        from tenuo_core import py_canonical_cbor_b64 as _cbor_b64
        tool_args = getattr(request, "tool_args", {}) or {}
        return _cbor_b64(tool_args)
    except Exception:
        # Fallback: JSON-encoded base64
        import json
        tool_args = getattr(request, "tool_args", {}) or {}
        return base64.b64encode(json.dumps(tool_args).encode()).decode()


# Minimal exception shims (mirror tenuo.approval without importing it)
class _ApprovalRequired(Exception):
    def __init__(self, request: Any):
        self.request = request
        super().__init__("Approval required")


class _ApprovalDenied(Exception):
    pass


class _ApprovalExpired(Exception):
    pass


class _ApprovalTimeout(Exception):
    pass
