"""
helpers.py — Shared utility functions for the NF-MSL project.

Every function here was extracted from main.py to eliminate code duplication.
No behaviour was changed; all original logic is preserved.
"""

from __future__ import annotations

import base64
import json
import logging
import random
import re
import uuid
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# ---------------------------------------------------------------------------
# Directory / file helpers
# ---------------------------------------------------------------------------

def ensure_output_dir(platform_name, base_dir: Optional[Path] = None) -> Path:
    """Create (if needed) and return the ``output`` directory under *base_dir*.

    If *base_dir* is ``None`` it defaults to the directory that contains the
    calling script (i.e. ``Path(__file__).resolve().parent``).
    """
    if base_dir is None:
        base_dir = Path(__file__).resolve().parent
    output_dir = base_dir / "output" / platform_name
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def save_json(path: Path, data: Any, log: Optional[logging.Logger] = None) -> None:
    """Write *data* as pretty-printed JSON to *path*."""
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        if log:
            log.info("Saved %s", path.name)
    except Exception:
        if log:
            log.exception("Failed to save %s", path)
        raise


# ---------------------------------------------------------------------------
# Session / cookie helpers
# ---------------------------------------------------------------------------

def restore_auth_cookies(
    session: requests.Session,
    cookies_path: Path,
    log: logging.Logger,
) -> None:
    """Load previously saved cookies from *cookies_path* into *session*."""
    if not cookies_path.exists():
        return
    try:
        cached = json.loads(cookies_path.read_text(encoding="utf-8"))
        if isinstance(cached, dict):
            session.cookies.update(cached)
    except Exception as exc:
        log.warning("Saved auth cookies could not be restored: %s", exc)


def get_cookie_value(session: requests.Session, name: str) -> str:
    """Return the value of the first cookie named *name*, or empty string."""
    for cookie in session.cookies:
        if cookie.name == name:
            return cookie.value
    return ""


def get_nfvdid(session: requests.Session, response: Optional[requests.Response] = None) -> str:
    """Extract the ``nfvdid`` cookie from *session* (or *response* as fallback).

    Raises ``RuntimeError`` when the cookie cannot be found.
    """
    nfvdid = ""
    for cookie in session.cookies:
        if cookie.name == "nfvdid":
            nfvdid = cookie.value
            break
    if not nfvdid and response is not None:
        nfvdid = response.cookies.get("nfvdid", "")
    if not nfvdid:
        raise RuntimeError("The initial nfvdid cookie was not returned")
    return nfvdid


def get_flow_session_cookies(session: requests.Session) -> Tuple[str, str]:
    """Return ``(nfvdid, flowSessionId)`` from the session cookie jar."""
    nfvdid = ""
    flow_session_id = ""
    for cookie in session.cookies:
        if cookie.name == "nfvdid":
            nfvdid = cookie.value
        elif cookie.name == "flwssn":
            flow_session_id = cookie.value
    return nfvdid, flow_session_id


def save_session_cookies(
    session: requests.Session,
    path: Path,
    log: logging.Logger,
) -> Dict[str, str]:
    """Save all session cookies to *path* as JSON and return the dict."""
    auth_cookies: Dict[str, str] = {}
    for cookie in session.cookies:
        auth_cookies[cookie.name] = cookie.value
    try:
        path.write_text(json.dumps(auth_cookies, indent=2), encoding="utf-8")
        log.info("Authentication cookies saved to: %s", path)
    except Exception:
        log.exception("Failed to save cookies")
        raise
    return auth_cookies


def build_cookie_header(
    session: requests.Session,
    important_names: Tuple[str, ...],
) -> str:
    """Build a ``Cookie`` header string from *important_names* cookies in *session*.

    Only the first occurrence of each name is included.
    """
    seen: Dict[str, str] = {}
    for cookie in session.cookies:
        if cookie.name in important_names and cookie.value and cookie.name not in seen:
            seen[cookie.name] = cookie.value
    return "; ".join(f"{n}={seen[n]}" for n in important_names if n in seen)


def apply_set_cookie_headers(
    session: requests.Session,
    response: requests.Response,
    cookie_values: Optional[List[str]] = None,
) -> None:
    """Parse ``Set-Cookie`` headers from *response* and apply them to *session*.

    *cookie_values* is an optional list that will also be processed (useful
    when the caller already extracted raw ``Set-Cookie`` strings from
    ``response.raw.headers``).
    """
    values: List[str] = list(cookie_values) if cookie_values else []

    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "get_all"):
        values.extend(raw_headers.get_all("Set-Cookie") or [])
    header_value = response.headers.get("Set-Cookie")
    if header_value and header_value not in values:
        values.append(header_value)

    for raw_cookie in values:
        jar = SimpleCookie()
        try:
            jar.load(raw_cookie)
        except Exception:
            continue
        for morsel in jar.values():
            cookie_domain = morsel["domain"] or None
            cookie_path = morsel["path"] or "/"
            if morsel.value == "":
                try:
                    session.cookies.clear(domain=cookie_domain, path=cookie_path, name=morsel.key)
                except Exception:
                    pass
                continue
            try:
                session.cookies.clear(domain=cookie_domain, path=cookie_path, name=morsel.key)
            except Exception:
                pass
            session.cookies.set(
                morsel.key, morsel.value,
                domain=cookie_domain, path=cookie_path,
                secure=bool(morsel["secure"]),
            )


def dedupe_important_cookies(
    session: requests.Session,
    important_names: Tuple[str, ...],
) -> None:
    """Remove duplicate cookies so only the best-scoring one per name remains.

    Scoring prefers ``.netflix.com`` domain, ``/`` path, and non-empty value.
    """
    preferred: Dict[str, Any] = {}
    for cookie in session.cookies:
        if cookie.name not in important_names:
            continue
        current = preferred.get(cookie.name)
        score = (cookie.domain == ".netflix.com", cookie.path == "/", bool(cookie.value))
        if current is None or score >= current[0]:
            preferred[cookie.name] = (score, cookie)

    for cookie in list(session.cookies):
        winner = preferred.get(cookie.name)
        if not winner:
            continue
        winner_cookie = winner[1]
        if (cookie.domain, cookie.path, cookie.value) != (
            winner_cookie.domain, winner_cookie.path, winner_cookie.value,
        ):
            try:
                session.cookies.clear(domain=cookie.domain, path=cookie.path, name=cookie.name)
            except Exception:
                pass


def collect_important_cookies(
    session: requests.Session,
    important_names: Tuple[str, ...],
) -> Dict[str, str]:
    """Return a flat dict of important cookie name → value (first seen wins)."""
    cookies: Dict[str, str] = {}
    for cookie in session.cookies:
        if cookie.name in important_names and cookie.value and cookie.name not in cookies:
            cookies[cookie.name] = cookie.value
    return cookies


# ---------------------------------------------------------------------------
# ID / random-string generators
# ---------------------------------------------------------------------------

def generate_hex_id(length: int = 32, uppercase: bool = False) -> str:
    """Return a random hex string of the given *length*."""
    charset = "0123456789ABCDEF" if uppercase else "0123456789abcdef"
    return "".join(random.choice(charset) for _ in range(length))


def generate_netflix_uuid() -> str:
    """Return a UUID in the Netflix ``8-4-4-4-12`` hex format."""
    return (
        generate_hex_id(8) + "-"
        + generate_hex_id(4) + "-"
        + generate_hex_id(4) + "-"
        + generate_hex_id(4) + "-"
        + generate_hex_id(12)
    )


def generate_request_id() -> str:
    """Shorthand for a 32-char lowercase hex request ID."""
    return generate_hex_id(32)


def generate_esn_random_suffix(length: int = 64) -> str:
    """Return a random alphanumeric suffix for ESN generation."""
    return "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(length))


# ---------------------------------------------------------------------------
# MSL crypto helpers
# ---------------------------------------------------------------------------

def _resolve_key(raw_key: Any) -> bytes:
    """Convert a key value (hex-str, bytes, or raw) to ``bytes``."""
    if isinstance(raw_key, str):
        try:
            return bytes.fromhex(raw_key)
        except ValueError:
            return raw_key.encode("utf-8")
    return raw_key


def decrypt_msl_header(
    headerdata_b64: str,
    encryption_key_value: Any,
    sign_key_value: Any,
) -> Dict[str, Any]:
    """Decrypt an MSL encrypted header and return the parsed JSON dict.

    *encryption_key_value* and *sign_key_value* may be hex-strings or bytes.
    Raises ``RuntimeError`` when either key is missing.
    """
    encryption_key = _resolve_key(encryption_key_value)
    sign_key = _resolve_key(sign_key_value)

    if not encryption_key:
        raise RuntimeError("The encryption key is missing")
    if not sign_key:
        raise RuntimeError("The sign key is missing")

    encrypted_header = json.loads(base64.b64decode(headerdata_b64))
    iv = base64.b64decode(encrypted_header["iv"])
    ciphertext = base64.b64decode(encrypted_header["ciphertext"])

    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return json.loads(decrypted.decode("utf-8"))


# ---------------------------------------------------------------------------
# HTML / response parsing helpers
# ---------------------------------------------------------------------------

def extract_first_match(html: str, patterns: List[str]) -> Optional[str]:
    """Try each regex *pattern* against *html* and return the first captured group."""
    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    return None


CLCS_SESSION_ID_PATTERNS = [
    r'"clcsSessionId"\s*:\s*"([0-9a-f\-]{36})"',
    r'\\"clcsSessionId\\"\s*:\s*\\"([0-9a-f\-]{36})\\"',
    r'"serverState"\s*:\s*"[^\"]*clcsSessionId\\":\\"([0-9a-f\-]{36})',
    r'"trackingInfo"\s*:\s*"[^\"]*clcsSessionId\\":\\"([0-9a-f\-]{36})',
    r'"sessionId"\s*:\s*"([0-9a-f\-]{36})"',
]

RENDITION_ID_PATTERNS = [
    r'"renditionId"\s*:\s*"([0-9a-f\-]{36})"',
    r'\\"renditionId\\"\s*:\s*\\"([0-9a-f\-]{36})\\"',
]


def extract_clcs_session_id(html: str) -> str:
    """Extract ``clcsSessionId`` from login page HTML.

    Raises ``RuntimeError`` when not found.
    """
    result = extract_first_match(html, CLCS_SESSION_ID_PATTERNS)
    if not result:
        raise RuntimeError("Could not extract clcsSessionId from the login page HTML")
    return result


def extract_rendition_id(html: str) -> str:
    """Extract ``renditionId`` from login page HTML.

    Raises ``RuntimeError`` when not found.
    """
    result = extract_first_match(html, RENDITION_ID_PATTERNS)
    if not result:
        raise RuntimeError("Could not extract the initial renditionId from the login page HTML")
    return result


def parse_flow_data(response_data: Dict[str, Any]) -> Dict[str, str]:
    """Walk a GraphQL response tree and extract flow metadata.

    Returns a dict that may contain keys:
    ``clcsSessionId``, ``renditionId``, ``flowSessionId``, ``mode``,
    ``flow``, ``membershipStatus``.
    """
    flow: Dict[str, str] = {}
    data = response_data.get("data", {})
    operation_key = next(iter(data.keys()), "")
    inner = data.get(operation_key, {})
    screen = inner.get("screen", inner) if isinstance(inner, dict) else {}

    stack = [screen]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            tracking_info = value.get("trackingInfo")
            if isinstance(tracking_info, str) and tracking_info:
                try:
                    tracking = json.loads(tracking_info)
                except Exception:
                    tracking = {}
                if tracking.get("clcsSessionId") and not flow.get("clcsSessionId"):
                    flow["clcsSessionId"] = tracking.get("clcsSessionId", "")
                if tracking.get("clcsRenditionId") and not flow.get("renditionId"):
                    flow["renditionId"] = tracking.get("clcsRenditionId", "")
            payload_json = value.get("payloadJson")
            if isinstance(payload_json, str) and payload_json:
                try:
                    payload = json.loads(payload_json)
                except Exception:
                    payload = {}
                if payload.get("flwssn") and not flow.get("flowSessionId"):
                    flow["flowSessionId"] = payload.get("flwssn", "")
                if payload.get("mode") and not flow.get("mode"):
                    flow["mode"] = payload.get("mode", "")
                if payload.get("flow") and not flow.get("flow"):
                    flow["flow"] = payload.get("flow", "")
            if value.get("membershipStatus"):
                flow["membershipStatus"] = value.get("membershipStatus", "")
            for child in value.values():
                stack.append(child)
        elif isinstance(value, list):
            for item in value:
                stack.append(item)

    return flow


# ---------------------------------------------------------------------------
# MSL payload parsing helpers (used by run_tv / run_tv_otp)
# ---------------------------------------------------------------------------

def parse_msl_payload(payload: Any) -> Tuple[str, Optional[Dict], Optional[str]]:
    """Classify an MSL payload and return ``(type_str, parsed_dict, text_str)``.

    *type_str* is one of ``"msl_payload"``, ``"json_array"``, or ``"text"``.
    """
    payload_type = type(payload).__name__
    parsed_payload: Optional[Dict] = None
    text_payload: Optional[str] = None

    if isinstance(payload, dict):
        payload_type = "msl_payload"
        parsed_payload = payload
    elif isinstance(payload, list):
        payload_type = "json_array"
        parsed_payload = {"items": payload}
    elif isinstance(payload, str):
        cleaned = payload.rstrip(
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        )
        text_payload = cleaned
        try:
            maybe_json = json.loads(cleaned)
            if isinstance(maybe_json, dict):
                parsed_payload = maybe_json
                payload_type = "text"
            else:
                payload_type = "text"
        except Exception:
            payload_type = "text"

    return payload_type, parsed_payload, text_payload


def extract_useridtoken_from_payload(
    parsed_payload: Optional[Dict], raw_payload: Any,
) -> Optional[Dict[str, Any]]:
    """Walk the payload tree and return the first dict with both
    ``tokendata`` and ``signature`` keys (the useridtoken)."""
    useridtoken: Optional[Dict[str, Any]] = None
    stack = [parsed_payload if parsed_payload is not None else raw_payload]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            if useridtoken is None and set(current.keys()) >= {"tokendata", "signature"}:
                useridtoken = current
            for child in current.values():
                stack.append(child)
        elif isinstance(current, list):
            for item in current:
                stack.append(item)
    return useridtoken


def build_msl_trace_event(
    msl_message_id: Any,
    key_id: str,
    payload_type: str,
    parsed_payload: Optional[Dict],
    text_payload: Optional[str],
    extra_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a single MSL trace event dict (used for debug logging)."""
    from datetime import datetime, timezone

    event: Dict[str, Any] = {
        "_type": "decrypt",
        "_mslId": msl_message_id,
        "_timestamp": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "_keyId": key_id,
        "_dataType": payload_type,
    }
    if extra_fields:
        event.update(extra_fields)
    if text_payload is not None:
        event["_text"] = text_payload
    if parsed_payload is not None:
        event["_payload"] = parsed_payload
    return event


def extract_key_id_from_mastertoken(mastertoken: Dict[str, Any]) -> str:
    """Extract the hex key ID from a master token's ``tokendata``."""
    if not mastertoken:
        return ""
    token_data = json.loads(base64.b64decode(mastertoken["tokendata"]).decode("utf-8"))
    return str(token_data.get("sequencenumber", "")).encode("utf-8").hex()


# ---------------------------------------------------------------------------
# Request-args helpers (TV platform)
# ---------------------------------------------------------------------------

def request_args_to_dict(request_args: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert a list of ``{"name":…, "value": {"stringValue"|"booleanValue":…}}``
    dicts into a plain ``{name: value}`` mapping."""
    result: Dict[str, Any] = {}
    for arg in request_args:
        value = arg["value"]
        if "stringValue" in value:
            result[arg["name"]] = value["stringValue"]
        elif "booleanValue" in value:
            result[arg["name"]] = value["booleanValue"]
    return result
