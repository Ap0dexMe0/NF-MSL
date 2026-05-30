from __future__ import annotations

import base64
import json
import logging
import os
import random
import re

_log = logging.getLogger(__name__)
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import jsonpickle
import requests
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256, SHA384
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

from .base import MSLBase, MSLKeys as _BaseMSLKeys


# ---------------------------------------------------------------------------
# MGK-specific Enums
# ---------------------------------------------------------------------------

class Scheme(Enum):
    def __str__(self) -> str:
        return str(self.value)


class EntityAuthenticationSchemes(Scheme):
    ModelGroup = "MGK"


class UserAuthenticationSchemes(Scheme):
    EmailPassword = "EMAIL_PASSWORD"
    NetflixIDCookies = "NETFLIXID"
    UserIDToken = "USER_ID_TOKEN"


# ---------------------------------------------------------------------------
# MGK Entity / User Authentication data classes
# ---------------------------------------------------------------------------

class EntityAuthentication:
    def __init__(self, scheme: EntityAuthenticationSchemes, authdata: Dict[str, Any]) -> None:
        self.scheme = str(scheme)
        self.authdata = authdata

    @classmethod
    def ModelGroup(cls, identity: str) -> "EntityAuthentication":
        return cls(EntityAuthenticationSchemes.ModelGroup, {"identity": identity})


class UserAuthentication:
    def __init__(self, scheme: UserAuthenticationSchemes, authdata: Dict[str, Any]) -> None:
        self.scheme = str(scheme)
        self.authdata = authdata

    @classmethod
    def EmailPassword(cls, email: str, password: str) -> "UserAuthentication":
        return cls(
            UserAuthenticationSchemes.EmailPassword,
            {"email": email, "password": password},
        )

    @classmethod
    def UserIDToken(
        cls,
        token_data: str,
        signature: str,
        master_token: dict,
    ) -> "UserAuthentication":
        return cls(
            UserAuthenticationSchemes.UserIDToken,
            {
                "useridtoken": {
                    "tokendata": token_data,
                    "signature": signature,
                },
                "mastertoken": master_token,
            },
        )

    @classmethod
    def NetflixIDCookies(
        cls,
        netflixid: Optional[str],
        securenetflixid: Optional[str],
    ) -> "UserAuthentication":
        return cls(
            UserAuthenticationSchemes.NetflixIDCookies,
            {
                "netflixid": netflixid,
                "securenetflixid": securenetflixid,
            },
        )


# ---------------------------------------------------------------------------
# Platform-specific key container
# ---------------------------------------------------------------------------

class MSLKeys(_BaseMSLKeys):
    """MGK MSL keys -- extends the base with wrapdata, derivation key, and DH fields."""

    def __init__(
        self,
        encryption: Optional[bytes] = None,
        sign: Optional[bytes] = None,
        mastertoken: Optional[dict] = None,
        wrapdata: Optional[bytes] = None,
        derivation_key: Optional[bytes] = None,
        key_scheme: Optional[str] = None,
        key_mechanism: Optional[str] = None,
        server_public_key_b64: Optional[str] = None,
        userauthdata: Optional[dict] = None,
        useridtoken: Optional[dict] = None,
    ) -> None:
        super().__init__(encryption=encryption, sign=sign, mastertoken=mastertoken)
        self.wrapdata = wrapdata
        self.derivation_key = derivation_key
        self.key_scheme = key_scheme
        self.key_mechanism = key_mechanism
        self.server_public_key_b64 = server_public_key_b64
        self.userauthdata = userauthdata
        self.useridtoken = useridtoken


# ---------------------------------------------------------------------------
# MSL_MGK -- Netflix MSL client for MGK (Model Group Key) devices
# ---------------------------------------------------------------------------

class MSL_MGK(MSLBase):
    """Netflix MSL client for MGK (Model Group Key) authenticated devices.

    Unlike the other platform clients (Android / iOS / TV / Web) which use
    Widevine or RSA key exchange, the MGK client uses an AUTHENTICATED_DH
    scheme with entity authentication.  The KpeKph (entity encryption + HMAC
    keys) are provided by the caller rather than derived from a CDM.

    This class extends :class:`MSLBase` and inherits all shared protocol
    logic (encrypt, sign, create_message, send_message, parse_message, etc.)
    while adding MGK-specific crypto (DH key exchange, KDF, wrap key
    derivation) and overriding ``handshake()`` and ``build_request_headers()``.
    """

    # -- Platform constants --------------------------------------------------
    DEFAULT_HANDSHAKE_ENDPOINT: str = (
        "https://www.netflix.com/msl/playapi/cadmium/licensedmanifest/1"
    )
    DEFAULT_MANIFEST_ENDPOINT: str = (
        "https://api-global.netflix.com/playapi/nrdjs/manifest/1"
    )
    DEFAULT_MANIFEST_PARAMS: Dict[str, str] = {
        "ab_ui_ver": "darwin",
        "nrdapp_version": "2025.2.2.0",
    }
    DEFAULT_USER_AGENT: str = (
        "Netflix/2025.2.2.0 "
        "(DEVTYPE=NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019; "
        "Milo=1.0.6315; build_number=6315; build_sha=a1b915de)"
    )
    DEFAULT_REQUEST_CONTEXT: str = '{"appstate":"foreground","reason":"unknown"}'
    DEFAULT_NRDJS_VERSION: str = "v3.11.512"
    DEFAULT_NETJS_VERSION: str = "3.0.5"
    DEFAULT_PBO_VERSION: int = 2
    DEFAULT_PBO_COMMON: Dict[str, str] = {
        "sdk": "2025.2.2.0",
        "platform": "2025.2.2.0",
        "application": (
            "12.1.6-23045 R 2025.2 android-30-JPLAYER2 "
            "ninja_6==NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4040.2147:user/release-keys"
        ),
        "uiversion": "UI-release-20260303_43809-gibbon-r100-darwinql-69067=5,78214=2,78929=8,80045=1,80048=2",
        "uiPlatform": "tv_ui",
        "clientVersion": "v3.11.512",
        "apkVersion": "12.1.6",
    }
    DEFAULT_PBO_LANGUAGES: List[str] = ["en-CA", "en-US", "en"]

    # -- MGK DH constants ----------------------------------------------------
    WRAP_SALT: bytes = bytes.fromhex("027617984f6227539a630b897c017d69")
    WRAP_INFO: bytes = bytes.fromhex("809f82a7addf548d3ea9dd067ff9bb91")
    DH_PRIME: bytes = bytes(
        [
            0x96, 0x94, 0xE9, 0xD8, 0xD9, 0x3A, 0x5A, 0xC7,
            0x4C, 0x50, 0x9B, 0x4B, 0xBC, 0xE8, 0x5E, 0x92,
            0x13, 0x2C, 0xD1, 0x9C, 0xCE, 0x47, 0x7D, 0x1A,
            0x7E, 0x47, 0xD5, 0x27, 0xD9, 0xEC, 0x29, 0x15,
            0x15, 0xF0, 0xB8, 0xB3, 0xE1, 0xEA, 0xED, 0x50,
            0x06, 0xE1, 0xB1, 0xB9, 0x1E, 0xA2, 0x5B, 0x91,
            0xA0, 0x1B, 0x10, 0xE2, 0xE8, 0x34, 0xB8, 0xD6,
            0x60, 0xB2, 0xE3, 0x21, 0xAD, 0x64, 0x4C, 0xE1,
            0xA8, 0x3B, 0x32, 0x8D, 0x90, 0x14, 0xEE, 0x7E,
            0x16, 0xF1, 0xE4, 0x4F, 0xFE, 0x89, 0x57, 0x9A,
            0xC3, 0xEE, 0x47, 0xD6, 0x68, 0xB6, 0xB7, 0x66,
            0x87, 0xC2, 0xFE, 0x90, 0xA3, 0x5B, 0x5E, 0x60,
            0x28, 0xFD, 0x04, 0xEF, 0xEA, 0x88, 0x23, 0x73,
            0xEC, 0xF6, 0x0B, 0xA2, 0xF6, 0x37, 0xE4, 0xCD,
            0xAA, 0x1B, 0x60, 0x89, 0xD6, 0xC0, 0xB5, 0x61,
            0xA8, 0xE5, 0x20, 0xE7, 0x96, 0xDE, 0x27, 0xDF,
        ]
    )
    DH_P: int = 0  # computed at class body end
    DH_G: int = 5

    # -- Constructor ---------------------------------------------------------

    def __init__(
        self,
        session: requests.Session,
        keys: MSLKeys,
        message_id: int,
        sender: str,
        user_auth: Optional[dict] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(session=session, keys=keys, message_id=message_id, sender=sender, proxy=proxy)
        self.user_auth = user_auth
        self.cookies = cookies

    # =======================================================================
    # MGK-specific crypto helpers
    # =======================================================================

    @classmethod
    def derive_wrapping_key(cls, encryption_key_16: bytes, hmac_key_32: bytes) -> bytes:
        """Derive a 16-byte wrapping key from the entity encryption + HMAC keys."""
        if len(encryption_key_16) != 16:
            raise ValueError("encryptionKey must be 16 bytes")
        if len(hmac_key_32) != 32:
            raise ValueError("hmacKey must be 32 bytes")

        inner = HMAC.new(cls.WRAP_SALT, digestmod=SHA256)
        inner.update(encryption_key_16 + hmac_key_32)

        outer = HMAC.new(inner.digest(), digestmod=SHA256)
        outer.update(cls.WRAP_INFO)

        return outer.digest()[:16]

    @staticmethod
    def int_to_unsigned_bytes(value: int) -> bytes:
        """Convert a non-negative integer to big-endian bytes (minimal length)."""
        if value < 0:
            raise ValueError("value must be non-negative")
        if value == 0:
            return b"\x00"
        return value.to_bytes((value.bit_length() + 7) // 8, "big", signed=False)

    @staticmethod
    def correct_null_bytes(value: bytes) -> bytes:
        """Normalise leading null bytes: keep exactly one leading 0x00 if present."""
        count = 0
        for byte in value:
            if byte == 0:
                count += 1
            else:
                break
        if count == 1:
            return value
        trimmed = value[count:]
        return b"\x00" + trimmed

    @classmethod
    def dh_generate_keypair(cls) -> Tuple[int, bytes]:
        """Generate a DH keypair.  Returns ``(private_key, public_key_wire)``."""
        private_key = int.from_bytes(os.urandom(len(cls.DH_PRIME)), "big") % (cls.DH_P - 3) + 2
        public_key = pow(cls.DH_G, private_key, cls.DH_P)
        public_key_bytes = cls.int_to_unsigned_bytes(public_key)
        return private_key, cls.correct_null_bytes(public_key_bytes)

    @classmethod
    def dh_compute_shared_secret_bytes(cls, dh_private_key: int, server_public_key_wire: bytes) -> bytes:
        """Compute the DH shared secret from our private key and the server's public key."""
        normalized_server_public_key = cls.correct_null_bytes(server_public_key_wire)
        server_public_key_raw = (
            normalized_server_public_key[1:]
            if normalized_server_public_key[:1] == b"\x00"
            else normalized_server_public_key
        )
        server_public_key = int.from_bytes(server_public_key_raw, "big", signed=False)
        shared_secret = pow(server_public_key, dh_private_key, cls.DH_P)
        return cls.correct_null_bytes(cls.int_to_unsigned_bytes(shared_secret))

    @classmethod
    def kdf_authenticated_dh(
        cls, derivation_key: bytes, shared_secret_bytes: bytes
    ) -> Tuple[bytes, bytes, bytes]:
        """Derive encryption, HMAC, and wrapping keys from the DH shared secret.

        Returns ``(encryption_key, hmac_key, wrapping_key)``.
        """
        if derivation_key is None:
            raise ValueError("derivation key is required for AUTHENTICATED_DH")

        salt_key = SHA384.new(derivation_key).digest()
        hmac_value = HMAC.new(salt_key, digestmod=SHA384)
        hmac_value.update(shared_secret_bytes)
        raw_key_material = hmac_value.digest()

        encryption_key = raw_key_material[:16]
        hmac_key = raw_key_material[16:48]
        wrapping_key = cls.derive_wrapping_key(encryption_key, hmac_key)

        return encryption_key, hmac_key, wrapping_key

    # =======================================================================
    # MGK v1 encrypt / sign (entity-level, used during handshake only)
    # =======================================================================

    @staticmethod
    def msl_encrypt_v1(key_id: str, encryption_key_16: bytes, plaintext_bytes: bytes) -> bytes:
        """AES-CBC encrypt with MSL v1 envelope.  Returns JSON-encoded bytes."""
        iv = get_random_bytes(16)
        ciphertext = AES.new(encryption_key_16, AES.MODE_CBC, iv).encrypt(
            pad(plaintext_bytes, AES.block_size)
        )
        envelope = {
            "keyid": key_id,
            "iv": base64.b64encode(iv).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "sha256": "AA==",
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def msl_decrypt_v1(encryption_key_16: bytes, envelope_bytes: bytes) -> bytes:
        """AES-CBC decrypt an MSL v1 envelope.  Returns unpadded plaintext bytes."""
        envelope = json.loads(envelope_bytes.decode("utf-8"))
        iv = base64.b64decode(envelope["iv"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        padded_plaintext = AES.new(encryption_key_16, AES.MODE_CBC, iv).decrypt(ciphertext)
        return unpad(padded_plaintext, AES.block_size)

    @staticmethod
    def msl_sign_b64(hmac_key_32: bytes, data_bytes: bytes) -> str:
        """HMAC-SHA256 sign *data_bytes* and return base64-encoded signature."""
        signer = HMAC.new(hmac_key_32, digestmod=SHA256)
        signer.update(data_bytes)
        return base64.b64encode(signer.digest()).decode("ascii")

    @staticmethod
    def msl_verify_sig(hmac_key_32: bytes, data_bytes: bytes, signature_b64: str) -> None:
        """Verify an MSL HMAC signature.  Raises ``ValueError`` on mismatch."""
        signer = HMAC.new(hmac_key_32, digestmod=SHA256)
        signer.update(data_bytes)
        expected_signature = signer.digest()
        received_signature = base64.b64decode(signature_b64)
        if expected_signature != received_signature:
            raise ValueError("Response signature verification failed: HMAC mismatch")

    # =======================================================================
    # KpeKph file / string loading helpers
    # =======================================================================

    @staticmethod
    def b64_decode_strict(value: str) -> bytes:
        """Strict base64 decode with URL-safe normalisation and padding fix."""
        normalized_value = value.strip().strip('"').strip("'")
        normalized_value = normalized_value.replace('-', '+').replace('_', '/')
        pad_needed = len(normalized_value) % 4
        if pad_needed == 2:
            normalized_value += '=='
        elif pad_needed == 3:
            normalized_value += '='
        return base64.b64decode(normalized_value.encode("ascii"), validate=True)

    @classmethod
    def find_sidecar_file(cls, filename: str, env_name: str) -> Optional[Path]:
        """Search for *filename* in env-var, CWD, and script directory trees."""
        env_value = os.getenv(env_name)
        candidates: List[Path] = []

        if env_value:
            candidates.append(Path(env_value))

        roots = [Path.cwd(), Path(__file__).resolve().parent]

        for root in roots:
            candidates.append(root / filename)
            candidates.extend(root.glob(f"**/{filename}"))

        seen = set()
        for candidate in candidates:
            key = str(candidate.resolve()) if candidate.exists() else str(candidate)
            if key in seen:
                continue
            seen.add(key)
            if candidate.is_file():
                return candidate

        return None

    @staticmethod
    def load_esnid_file(path: Path) -> str:
        """Read an ESNID string from a text file."""
        value = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not value:
            raise ValueError(f"Empty ESNID file: {path}")
        return value

    @classmethod
    def load_kpe_kph_file(cls, path: Path) -> Tuple[bytes, bytes, bytes]:
        """Load KpeKph from a comma-separated base64 file.

        Returns ``(encryption_key, hmac_key, wrapping_key)``.
        """
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]

        text = raw.decode("utf-8", errors="strict").strip()
        text = re.sub(r"\s*,\s*", ",", text)
        left, right = text.split(",", 1)
        enc_key = cls.b64_decode_strict(left)
        hmac_key = cls.b64_decode_strict(right)

        if len(enc_key) != 16:
            raise ValueError(f"Kpe must decode to 16 bytes, got {len(enc_key)}")
        if len(hmac_key) != 32:
            raise ValueError(f"Kph must decode to 32 bytes, got {len(hmac_key)}")

        wrap_key = cls.derive_wrapping_key(enc_key, hmac_key)
        return enc_key, hmac_key, wrap_key

    @classmethod
    def parse_kpe_kph_string(cls, raw_string: str) -> Tuple[bytes, bytes, bytes]:
        """Parse a raw KpeKph string (e.g. from a CLI argument).

        Supports both ':' and ',' as separator between the Kpe and Kph
        base64-encoded values.
        """
        text = raw_string.strip()
        if ':' in text:
            left, right = text.split(':', 1)
        elif ',' in text:
            left, right = text.split(',', 1)
        else:
            raise ValueError(
                "KpeKph string must contain ':' or ',' separator "
                "between Kpe and Kph values"
            )

        enc_key = cls.b64_decode_strict(left.strip())
        hmac_key = cls.b64_decode_strict(right.strip())

        if len(enc_key) != 16:
            raise ValueError(f"Kpe must decode to 16 bytes, got {len(enc_key)}")
        if len(hmac_key) != 32:
            raise ValueError(f"Kph must decode to 32 bytes, got {len(hmac_key)}")

        wrap_key = cls.derive_wrapping_key(enc_key, hmac_key)
        return enc_key, hmac_key, wrap_key

    # =======================================================================
    # Platform-specific request headers
    # =======================================================================

    @staticmethod
    def build_request_headers(
        request_name: str,
        user_agent: Optional[str] = None,
        referer: Optional[str] = None,
        viewable_id: Optional[int] = None,
        profile_guid: Optional[str] = None,
        esn: Optional[str] = None,
        expiry_timeout: Optional[int] = 12750,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Build the HTTP headers required for MGK MSL requests."""
        headers: Dict[str, str] = {
            "User-Agent": user_agent or MSL_MGK.DEFAULT_USER_AGENT,
            "Accept": "*/*",
            "Content-Type": "application/json",
            "X-Netflix.Client.Request.Name": request_name,
            "X-Netflix.request.attempt": "1",
            "X-Netflix.Request.NonJson.Headers": "true",
            "X-Netflix.Request.Client.Context": MSL_MGK.DEFAULT_REQUEST_CONTEXT,
            "x-netflix.client.nrdjs.version": MSL_MGK.DEFAULT_NRDJS_VERSION,
            "x-netflix.client.netjs.version": MSL_MGK.DEFAULT_NETJS_VERSION,
            "x-netflix.client.last-interacted-days": "0",
        }

        if expiry_timeout is not None:
            headers["x-netflix.request.expiry.timeout"] = str(expiry_timeout)

        if referer:
            headers["Referer"] = referer

        if viewable_id is not None:
            headers["x-netflix.playback.main-content-viewable-id"] = str(viewable_id)

        if profile_guid:
            headers["x-netflix.client.current-profile-guid"] = profile_guid

        if esn:
            headers["x-netflix.client.ftl.esn"] = esn

        if extra_headers:
            headers.update(extra_headers)

        return headers

    # =======================================================================
    # Manifest defaults
    # =======================================================================

    @staticmethod
    def manifest_request_defaults() -> Tuple[str, Dict[str, str]]:
        """Return the default manifest endpoint and query params for MGK."""
        return MSL_MGK.DEFAULT_MANIFEST_ENDPOINT, dict(MSL_MGK.DEFAULT_MANIFEST_PARAMS)

    # =======================================================================
    # Handshake -- MGK AUTHENTICATED_DH key exchange
    # =======================================================================

    @classmethod
    def handshake(
        cls,
        session: requests.Session,
        sender: str,
        kpekph_path: Optional[Union[str, Path]] = None,
        kpekph_raw: Optional[str] = None,
        msl_keys_path: Optional[Union[str, Path]] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        new_msl: bool = False,
    ) -> "MSL_MGK":
        """Perform an MGK (AUTHENTICATED_DH) key exchange.

        Unlike Android/iOS/TV which return raw ``MSLKeys``, this method
        returns a fully constructed :class:`MSL_MGK` instance ready for
        ``send_message()`` calls.  This is because the MGK handshake uses
        entity-level encryption (KpeKph) that is not available after the
        handshake completes.
        """
        _log.info("MGK handshake: sender=%s", sender)
        endpoint = cls.DEFAULT_HANDSHAKE_ENDPOINT
        message_id = random.randint(0, pow(2, 52))

        if cookies:
            session.cookies.update(cookies)

        # ---- Check cache ---------------------------------------------------
        cache_path = Path(msl_keys_path) if msl_keys_path else None
        cached_keys = None if new_msl else cls.load_cache_data(cache_path)

        if cached_keys is not None:
            _log.info("Reusing cached MGK MSL keys")
            return cls(
                session=session,
                keys=cached_keys,
                message_id=message_id,
                sender=sender,
                cookies=cookies,
                proxy=proxy,
            )

        if not sender:
            raise RuntimeError("Missing sender or ESNID for MGK handshake")

        _log.info("Performing fresh MGK key exchange")
        # ---- Resolve KpeKph ------------------------------------------------
        if kpekph_raw:
            _log.debug("KpeKph source: raw string")
            entity_encryption_key, entity_hmac_key, entity_wrapping_key = cls.parse_kpe_kph_string(kpekph_raw)
        elif kpekph_path:
            _log.debug("KpeKph source: file %s", kpekph_path)
            resolved_kpekph_path = Path(kpekph_path)
            entity_encryption_key, entity_hmac_key, entity_wrapping_key = cls.load_kpe_kph_file(
                resolved_kpekph_path
            )
        else:
            resolved_kpekph_path = cls.find_sidecar_file("KpeKph", "MSL_KPEKPH_PATH")
            if not resolved_kpekph_path:
                raise RuntimeError(
                    "KpeKph was not found. Place KpeKph next to the client, "
                    "inside a child folder, in the current working directory, or set MSL_KPEKPH_PATH."
                )
            entity_encryption_key, entity_hmac_key, entity_wrapping_key = cls.load_kpe_kph_file(
                resolved_kpekph_path
            )

        # ---- Build key request data ----------------------------------------
        msl_keys = MSLKeys()
        cached_wrapdata = cached_keys.wrapdata if cached_keys else None
        cached_derivation_key = cached_keys.derivation_key if cached_keys else None
        mechanism = "WRAP" if cached_wrapdata and cached_derivation_key else "MGK"
        derivation_key = cached_derivation_key or entity_wrapping_key

        dh_private_key, dh_public_key_wire = cls.dh_generate_keypair()
        _log.debug("DH keypair generated (mechanism=%s)", mechanism)
        key_data: Dict[str, Any] = {
            "mechanism": mechanism,
            "publickey": cls.b64_encode_bytes(cls.correct_null_bytes(dh_public_key_wire)),
            "parametersid": "1",
        }

        if mechanism == "WRAP":
            key_data["wrapdata"] = cls.b64_encode_bytes(cached_wrapdata)

        key_request_data = {
            "scheme": "AUTHENTICATED_DH",
            "keydata": key_data,
        }
        entity_auth_data = EntityAuthentication.ModelGroup(sender).__dict__

        # ---- Encrypt header with entity keys (MGK v1) ----------------------
        header_plaintext = cls.generate_msg_header(
            message_id=message_id,
            sender=sender,
            is_handshake=True,
            keyrequestdata=key_request_data,
            compression="GZIP",
            languages=["en-US"],
        ).encode("utf-8")
        header_ciphertext = cls.msl_encrypt_v1(sender, entity_encryption_key, header_plaintext)

        payload_plaintext = cls.stable_json(
            {
                "messageid": message_id,
                "data": "",
                "sequencenumber": 1,
                "endofmsg": True,
            }
        ).encode("utf-8")
        payload_ciphertext = cls.msl_encrypt_v1(sender, entity_encryption_key, payload_plaintext)

        request_body = cls.stable_json(
            {
                "entityauthdata": entity_auth_data,
                "headerdata": cls.b64_encode_bytes(header_ciphertext),
                "signature": cls.msl_sign_b64(entity_hmac_key, header_ciphertext),
            }
        )
        request_body += cls.stable_json(
            {
                "payload": cls.b64_encode_bytes(payload_ciphertext),
                "signature": cls.msl_sign_b64(entity_hmac_key, payload_ciphertext),
            }
        )

        # ---- Send handshake request ----------------------------------------
        _log.debug("MGK handshake request → %s", endpoint)
        response = session.post(
            url=endpoint,
            data=request_body,
            headers=headers or {},
            timeout=timeout,
        )
        _log.debug("MGK handshake response ← HTTP %d", response.status_code)

        if response.status_code != 200:
            raise RuntimeError(
                f"Key exchange failed: HTTP {response.status_code} {response.text[:500]}"
            )

        parsed_response = cls.parse_concatenated_json(response.text)

        if not parsed_response:
            raise RuntimeError("Key exchange failed: empty MSL response")

        key_exchange = parsed_response[0]

        if "errordata" in key_exchange:
            decoded_error = base64.b64decode(key_exchange["errordata"]).decode("utf-8", "ignore")
            raise RuntimeError(f"Key exchange failed: {decoded_error}")

        if "headerdata" not in key_exchange:
            raise RuntimeError(
                f"Key exchange failed: missing headerdata in response: {str(key_exchange)[:500]}"
            )

        # ---- Derive session keys from response -----------------------------
        header_json = json.loads(base64.b64decode(key_exchange["headerdata"]).decode("utf-8"))
        key_response_data = header_json["keyresponsedata"]
        response_key_data = key_response_data["keydata"]
        server_public_key_wire = cls.correct_null_bytes(
            base64.b64decode(response_key_data["publickey"])
        )
        response_wrapdata = response_key_data.get("wrapdata")

        if response_wrapdata:
            msl_keys.wrapdata = base64.b64decode(response_wrapdata)
        else:
            msl_keys.wrapdata = cached_wrapdata

        shared_secret = cls.dh_compute_shared_secret_bytes(
            dh_private_key,
            server_public_key_wire,
        )
        encryption_key, sign_key, next_derivation_key = cls.kdf_authenticated_dh(
            derivation_key,
            shared_secret,
        )

        msl_keys.encryption = encryption_key
        msl_keys.sign = sign_key
        msl_keys.derivation_key = next_derivation_key
        msl_keys.mastertoken = key_response_data["mastertoken"]
        msl_keys.key_scheme = key_response_data.get("scheme")
        msl_keys.key_mechanism = response_key_data.get("mechanism")
        msl_keys.server_public_key_b64 = response_key_data.get("publickey")
        msl_keys.userauthdata = header_json.get("userauthdata")
        msl_keys.useridtoken = header_json.get("useridtoken")

        if cache_path:
            cls.cache_keys(msl_keys, cache_path)
        _log.info("MGK key exchange complete, session keys derived")

        return cls(
            session=session,
            keys=msl_keys,
            message_id=message_id,
            sender=sender,
            cookies=cookies,
            proxy=proxy,
        )

    # =======================================================================
    # Override create_message -- MGK uses single payload chunk format
    # =======================================================================

    def create_message(
        self,
        application_data: Dict[str, Any],
        userauthdata: Optional[dict] = None,
    ) -> str:
        """Build an MSL message with a single payload chunk.

        The MGK endpoint expects the payload data and ``endofmsg`` flag in
        a single chunk, unlike the Android/iOS/TV endpoints which use two
        separate chunks (data + endofmsg).
        """
        self.message_id += 1

        header_data = self.encrypt(
            self.generate_msg_header(
                message_id=self.message_id,
                sender=self.sender,
                is_handshake=False,
                userauthdata=userauthdata,
            )
        )

        message = json.dumps(
            {
                "headerdata": base64.standard_b64encode(header_data.encode("utf-8")).decode("utf-8"),
                "signature": self.sign(header_data).decode("utf-8"),
                "mastertoken": self.keys.mastertoken,
            },
            separators=(",", ":"),
        )

        compressed_application_data = self.gzip_compress(
            json.dumps(application_data, separators=(",", ":")).encode("utf-8")
        ).decode("utf-8")

        payload_chunk = self.encrypt(
            json.dumps(
                {
                    "messageid": self.message_id,
                    "data": compressed_application_data,
                    "compressionalgo": "GZIP",
                    "sequencenumber": 1,
                    "endofmsg": True,
                },
                separators=(",", ":"),
            )
        )
        message += json.dumps(
            {
                "payload": base64.standard_b64encode(payload_chunk.encode("utf-8")).decode("utf-8"),
                "signature": self.sign(payload_chunk).decode("utf-8"),
            },
            separators=(",", ":"),
        )

        return message

    # =======================================================================
    # Cache I/O overrides (MGK-specific MSLKeys with extra fields)
    # =======================================================================

    @staticmethod
    def load_cache_data(msl_keys_path: Optional[Path] = None) -> Optional[MSLKeys]:
        """Load cached MGK keys, ensuring all MGK-specific fields exist."""
        if not msl_keys_path or not msl_keys_path.is_file():
            return None

        loaded_keys = jsonpickle.decode(msl_keys_path.read_text(encoding="utf-8"))

        if not isinstance(loaded_keys, MSLKeys):
            # If loaded from a base MSLKeys cache, it won't have MGK fields
            if not hasattr(loaded_keys, "wrapdata"):
                loaded_keys.wrapdata = None
            if not hasattr(loaded_keys, "derivation_key"):
                loaded_keys.derivation_key = None
            if not hasattr(loaded_keys, "key_scheme"):
                loaded_keys.key_scheme = None
            if not hasattr(loaded_keys, "key_mechanism"):
                loaded_keys.key_mechanism = None
            if not hasattr(loaded_keys, "server_public_key_b64"):
                loaded_keys.server_public_key_b64 = None
            if not hasattr(loaded_keys, "userauthdata"):
                loaded_keys.userauthdata = None
            if not hasattr(loaded_keys, "useridtoken"):
                loaded_keys.useridtoken = None

        # Check token expiry using expiration field (MGK uses "expiration"
        # instead of "renewalwindow" because the token is obtained through
        # entity auth, not the standard NONE/RSA/WV handshake)
        if loaded_keys.mastertoken:
            expiry_value = json.loads(
                base64.b64decode(loaded_keys.mastertoken["tokendata"]).decode("utf-8")
            ).get("expiration")

            if expiry_value is not None:
                expiry = datetime.fromtimestamp(int(expiry_value), tz=timezone.utc)
                hours_remaining = (expiry - datetime.now(timezone.utc)).total_seconds() / 3600

                if hours_remaining < 10:
                    return None

        return loaded_keys

    # =======================================================================
    # Override send_message to add PBO normalisation and cookies
    # =======================================================================

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
        """Send an MSL message with PBO payload normalisation and MGK cookies."""
        normalized = self.normalize_application_data(endpoint, application_data)
        message = self.create_message(normalized, userauthdata)

        request_kwargs: Dict[str, Any] = {
            "url": endpoint,
            "data": message,
            "params": params,
            "headers": headers,
            "timeout": timeout,
        }
        effective_proxy = proxy or self.proxy
        if effective_proxy:
            request_kwargs["proxies"] = effective_proxy
        if self.cookies:
            request_kwargs["cookies"] = self.cookies

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


# Initialise the DH prime as an integer after the class body
MSL_MGK.DH_P = int.from_bytes(MSL_MGK.DH_PRIME, "big")


__all__ = [
    "EntityAuthentication",
    "EntityAuthenticationSchemes",
    "MSL_MGK",
    "MSLKeys",
    "Scheme",
    "UserAuthentication",
    "UserAuthenticationSchemes",
]
