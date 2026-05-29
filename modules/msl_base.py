
from __future__ import annotations

import base64
import gzip
import json
import random
import re
import zlib

import jsonpickle
import requests
from io import BytesIO
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import Padding


# ---------------------------------------------------------------------------
# Core data objects
# ---------------------------------------------------------------------------

class MSLObject:
    """Base class providing a compact JSON repr for debugging."""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {jsonpickle.encode(self, unpicklable=False)}>"


class MSLKeys(MSLObject):
    """Holds the negotiated encryption / signing keys and master token."""

    def __init__(
        self,
        encryption: Optional[bytes] = None,
        sign: Optional[bytes] = None,
        mastertoken: Optional[dict] = None,
    ) -> None:
        self.encryption = encryption
        self.sign = sign
        self.mastertoken = mastertoken


# ---------------------------------------------------------------------------
# Widevine key helper (shared by Android, iOS, TV)
# ---------------------------------------------------------------------------

def get_widevine_key(kid: bytes, keys: List[Any], permissions: List[str]) -> Optional[bytes]:
    """Find the Widevine operator-session key whose permissions are a
    superset of *permissions*.  Permission names are normalised from
    CamelCase to snake_case before comparison."""
    normalized_perms = {re.sub(r'(?<!^)(?=[A-Z])', '_', p).lower() for p in permissions}
    for key in keys:
        if key.type != "OPERATOR_SESSION":
            continue
        key_perms = {p.lower() for p in (getattr(key, "permissions", None) or [])}
        if normalized_perms <= key_perms:
            return key.key
    return None


# ---------------------------------------------------------------------------
# MSLBase – the shared foundation for all platform MSL classes
# ---------------------------------------------------------------------------

class MSLBase:
    """
    Base class encapsulating the common MSL protocol logic shared by every
    platform variant (Android, iOS, TV, Web).

    Subclasses override:
      - class-level DEFAULT_* constants
      - ``build_request_headers()`` (platform-specific header set)
      - ``handshake()`` (key-exchange / DRM negotiation)
      - optionally ``generate_msg_header()`` for platform quirks
    """

    # --- Subclasses must override these ------------------------------------
    DEFAULT_HANDSHAKE_ENDPOINT: str = ""
    DEFAULT_USER_AGENT: str = ""
    DEFAULT_REQUEST_CONTEXT: str = "{}"

    # --- Shared protocol constants -----------------------------------------
    DEFAULT_PBO_VERSION: int = 2
    DEFAULT_PBO_LANGUAGES: List[str] = ["en-US", "en"]

    # -----------------------------------------------------------------------
    # Constructor
    # -----------------------------------------------------------------------

    def __init__(
        self,
        session: requests.Session,
        keys: MSLKeys,
        message_id: int,
        sender: str,
        **_kwargs: Any,
    ) -> None:
        self.session = session
        self.keys = keys
        self.sender = sender
        self.message_id = message_id

    # -----------------------------------------------------------------------
    # JSON helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def parse_concatenated_json(message: str) -> List[Dict[str, Any]]:
        """Parse concatenated JSON objects from a single string (MSL wire format)."""
        decoder = json.JSONDecoder()
        items: List[Dict[str, Any]] = []
        index = 0
        length = len(message)
        while index < length:
            while index < length and message[index].isspace():
                index += 1
            if index >= length:
                break
            item, next_index = decoder.raw_decode(message, index)
            items.append(item)
            index = next_index
        return items

    @staticmethod
    def stable_json(obj: Dict[str, Any]) -> str:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    # -----------------------------------------------------------------------
    # Base64 helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def b64_encode_bytes(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def base64key_decode(payload: str) -> bytes:
        """Decode a URL-safe base64 JWK key, padding if necessary."""
        remainder = len(payload) % 4
        if remainder == 2:
            payload += "=="
        elif remainder == 3:
            payload += "="
        elif remainder != 0:
            raise ValueError("Invalid base64 string")
        return base64.urlsafe_b64decode(payload.encode("utf-8"))

    # -----------------------------------------------------------------------
    # Compression
    # -----------------------------------------------------------------------

    @staticmethod
    def gzip_compress(data: bytes) -> bytes:
        out = BytesIO()
        with gzip.GzipFile(fileobj=out, mode="w") as gz:
            gz.write(data)
        return base64.standard_b64encode(out.getvalue())

    # -----------------------------------------------------------------------
    # Encryption / Signing
    # -----------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        if not self.keys.encryption:
            raise ValueError("Encryption key is not available")
        if not self.keys.mastertoken:
            raise ValueError("Master token is not available")

        iv = get_random_bytes(16)
        tokendata = json.loads(
            base64.standard_b64decode(self.keys.mastertoken["tokendata"]).decode("utf-8")
        )
        ciphertext = AES.new(self.keys.encryption, AES.MODE_CBC, iv).encrypt(
            Padding.pad(plaintext.encode("utf-8"), 16)
        )
        return json.dumps(
            {
                "ciphertext": base64.standard_b64encode(ciphertext).decode("utf-8"),
                "keyid": f"{self.sender}_{tokendata['sequencenumber']}",
                "sha256": "AA==",
                "iv": base64.standard_b64encode(iv).decode("utf-8"),
            },
            separators=(",", ":"),
        )

    def sign(self, text: str) -> bytes:
        if not self.keys.sign:
            raise ValueError("Sign key is not available")
        return base64.standard_b64encode(
            HMAC.new(self.keys.sign, text.encode("utf-8"), SHA256).digest()
        )

    # -----------------------------------------------------------------------
    # AES-CBC convenience (used by MGK branch)
    # -----------------------------------------------------------------------

    @staticmethod
    def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(Padding.pad(plaintext, AES.block_size))

    @staticmethod
    def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        return Padding.unpad(
            AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext),
            AES.block_size,
        )

    # -----------------------------------------------------------------------
    # Message creation
    # -----------------------------------------------------------------------

    @staticmethod
    def generate_msg_header(
        message_id: int,
        sender: str,
        is_handshake: bool,
        userauthdata: Optional[dict] = None,
        keyrequestdata: Optional[dict] = None,
        compression: Optional[str] = "GZIP",
        languages: Optional[List[str]] = None,
        recipient: Optional[str] = "Netflix",
    ) -> str:
        header_data: Dict[str, Any] = {
            "messageid": message_id,
            "renewable": True,
            "handshake": is_handshake,
            "capabilities": {
                "compressionalgos": [compression] if compression else [],
                "languages": languages or ["en-US", "en"],
                "encoderformats": ["JSON"],
            },
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "sender": sender,
            "nonreplayable": False,
        }
        if recipient:
            header_data["recipient"] = recipient
        if userauthdata:
            header_data["userauthdata"] = userauthdata
        if keyrequestdata:
            header_data["keyrequestdata"] = [keyrequestdata]
        return jsonpickle.encode(header_data, unpicklable=False)

    def create_message(
        self,
        application_data: Dict[str, Any],
        userauthdata: Optional[dict] = None,
    ) -> str:
        self.message_id += 1

        headerdata = self.encrypt(
            self.generate_msg_header(
                message_id=self.message_id,
                sender=self.sender,
                is_handshake=False,
                userauthdata=userauthdata,
            )
        )

        message = json.dumps(
            {
                "headerdata": base64.standard_b64encode(headerdata.encode("utf-8")).decode("utf-8"),
                "signature": self.sign(headerdata).decode("utf-8"),
                "mastertoken": self.keys.mastertoken,
            },
            separators=(",", ":"),
        )

        compressed_application_data = self.gzip_compress(
            json.dumps(application_data, separators=(",", ":")).encode("utf-8")
        ).decode("utf-8")

        payload_dicts = [
            {
                "sequencenumber": 1,
                "messageid": self.message_id,
                "compressionalgo": "GZIP",
                "data": compressed_application_data,
            },
            {
                "sequencenumber": 2,
                "messageid": self.message_id,
                "endofmsg": True,
                "data": "",
            },
        ]

        for payload_dict in payload_dicts:
            payload_chunk = self.encrypt(json.dumps(payload_dict, separators=(",", ":")))
            message += json.dumps(
                {
                    "payload": base64.standard_b64encode(payload_chunk.encode("utf-8")).decode("utf-8"),
                    "signature": self.sign(payload_chunk).decode("utf-8"),
                },
                separators=(",", ":"),
            )
        return message

    # -----------------------------------------------------------------------
    # Message parsing / decryption
    # -----------------------------------------------------------------------

    def decrypt_payload_chunks(self, payload_chunks: List[Dict[str, str]]) -> Any:
        if not self.keys.encryption:
            raise ValueError("Encryption key is not available")

        raw_data = ""
        for payload_chunk in payload_chunks:
            chunk_json = json.loads(
                base64.standard_b64decode(payload_chunk["payload"]).decode("utf-8")
            )
            decrypted = AES.new(
                key=self.keys.encryption,
                mode=AES.MODE_CBC,
                iv=base64.standard_b64decode(chunk_json["iv"]),
            ).decrypt(base64.standard_b64decode(chunk_json["ciphertext"]))
            decrypted = Padding.unpad(decrypted, 16)
            payload_json = json.loads(decrypted.decode("utf-8"))

            payload_data = base64.standard_b64decode(payload_json["data"])
            if payload_json.get("compressionalgo") == "GZIP":
                payload_data = zlib.decompress(payload_data, 16 + zlib.MAX_WBITS)
            raw_data += payload_data.decode("utf-8")

        if not raw_data:
            return None

        try:
            data = json.loads(raw_data)
        except Exception:
            return raw_data

        if "error" in data:
            return None
        if "result" not in data:
            return data
        return data["result"]

    def parse_message(self, message: str) -> Tuple[Dict[str, Any], Any]:
        parsed = self.parse_concatenated_json(message)
        header = parsed[0]
        encrypted_chunks = parsed[1:] if len(parsed) > 1 else []
        payload = self.decrypt_payload_chunks(encrypted_chunks) if encrypted_chunks else {}
        return header, payload

    # -----------------------------------------------------------------------
    # Send message (common path – subclasses may override for extra checks)
    # -----------------------------------------------------------------------

    def send_message(
        self,
        endpoint: str,
        params: Dict[str, str],
        application_data: Dict[str, Any],
        userauthdata: Optional[dict] = None,
        headers: Optional[dict] = None,
        proxy: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> Tuple[Dict[str, Any], Any]:
        message = self.create_message(application_data, userauthdata)
        request_kwargs: Dict[str, Any] = {
            "url": endpoint,
            "data": message,
            "params": params,
            "headers": headers,
            "timeout": timeout,
        }
        if proxy:
            request_kwargs["proxies"] = proxy

        res = self.session.post(**request_kwargs)

        if res.status_code != 200:
            raise RuntimeError(
                f"MSL request failed with HTTP {res.status_code}: {res.text[:500]}"
            )

        response_text = res.text or ""
        stripped = response_text.lstrip()
        if not stripped:
            raise RuntimeError("MSL request failed: empty response body")
        if not stripped.startswith("{"):
            raise RuntimeError(
                "MSL request failed: the server did not return concatenated MSL JSON. "
                f"Content-Type: {res.headers.get('content-type', '')!r}. "
                f"Body preview: {response_text[:500]!r}"
            )

        header, payload_data = self.parse_message(response_text)
        if not header:
            raise RuntimeError(
                f"MSL request failed: parsed response does not contain a header. "
                f"Body preview: {response_text[:500]!r}"
            )
        if "errordata" in header:
            decoded_error = json.loads(
                base64.standard_b64decode(header["errordata"].encode("utf-8")).decode("utf-8")
            )
            raise RuntimeError(f"MSL response contains an error: {decoded_error}")

        return header, payload_data

    # -----------------------------------------------------------------------
    # PBO payload normalisation (shared by Android, iOS, TV)
    # -----------------------------------------------------------------------

    @classmethod
    def normalize_application_data(cls, endpoint: str, application_data: Any) -> Any:
        if not isinstance(application_data, dict):
            return application_data
        if cls._looks_like_wrapped_pbo_payload(application_data):
            return application_data

        route = cls._extract_pbo_route(application_data, endpoint)
        if route is None:
            return application_data

        common = dict(getattr(cls, "DEFAULT_PBO_COMMON", {}))
        if isinstance(application_data.get("common"), dict):
            common.update(application_data["common"])

        wrapped: Dict[str, Any] = {
            "version": application_data.get("version", cls.DEFAULT_PBO_VERSION),
            "common": common,
            "url": route,
            "languages": application_data.get("languages", list(cls.DEFAULT_PBO_LANGUAGES)),
            "params": application_data.get("params", {}),
        }

        for key in ("path", "method", "route", "endpoint"):
            wrapped.pop(key, None)

        for key, value in application_data.items():
            if key in wrapped or key in {
                "version", "common", "languages", "params",
                "path", "method", "route", "endpoint",
            }:
                continue
            wrapped[key] = value
        return wrapped

    @staticmethod
    def _looks_like_wrapped_pbo_payload(application_data: Dict[str, Any]) -> bool:
        return (
            "version" in application_data
            and "common" in application_data
            and "url" in application_data
            and "languages" in application_data
            and "params" in application_data
        )

    @staticmethod
    def _extract_pbo_route(application_data: Dict[str, Any], endpoint: str) -> Optional[str]:
        for key in ("url", "path", "route", "method", "endpoint"):
            value = application_data.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            value = value.strip()
            return value if value.startswith("/") else f"/{value}"

        endpoint_lower = endpoint.lower()
        if "manifest" in endpoint_lower:
            return "/manifest"
        if "pbo_tokens" in endpoint_lower or "pbo_config" in endpoint_lower:
            return None
        return None

    # -----------------------------------------------------------------------
    # Cache I/O
    # -----------------------------------------------------------------------

    @staticmethod
    def load_cache_data(msl_keys_path: Optional[Path] = None) -> Optional[MSLKeys]:
        """Load cached MSL keys from disk.  Returns ``None`` if the cache is
        missing, corrupt, or the token is about to expire (< 10 h remaining)."""
        if not msl_keys_path or not msl_keys_path.is_file():
            return None

        msl_keys = jsonpickle.decode(msl_keys_path.read_text(encoding="utf-8"))
        if msl_keys.mastertoken:
            tokendata = json.loads(
                base64.standard_b64decode(msl_keys.mastertoken["tokendata"]).decode("utf-8")
            )
            renewal_window = datetime.fromtimestamp(
                int(tokendata["renewalwindow"]), tz=timezone.utc
            )
            remaining_hours = (renewal_window - datetime.now(timezone.utc)).total_seconds() / 3600
            if remaining_hours < 10:
                return None
        return msl_keys

    @staticmethod
    def cache_keys(msl_keys: MSLKeys, msl_keys_path: Path) -> None:
        """Persist *msl_keys* to *msl_keys_path*."""
        msl_keys_path.parent.mkdir(parents=True, exist_ok=True)
        msl_keys_path.write_text(jsonpickle.encode(msl_keys, indent=4), encoding="utf-8")
