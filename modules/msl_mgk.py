from __future__ import annotations

import base64
import json
import os
import random
import re
import zlib
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

from .msl_base import MSLBase, MSLKeys as _BaseMSLKeys, MSLObject


# ---------------------------------------------------------------------------
# Platform-specific key container
# ---------------------------------------------------------------------------

class MSLKeys(_BaseMSLKeys):
    """MGK MSL keys – extends the base with wrapping data and derivation key."""

    def __init__(
        self,
        encryption: Optional[bytes] = None,
        sign: Optional[bytes] = None,
        mastertoken: Optional[dict] = None,
        wrapdata: Optional[bytes] = None,
        derivation_key: Optional[bytes] = None,
    ) -> None:
        super().__init__(encryption=encryption, sign=sign, mastertoken=mastertoken)
        self.wrapdata = wrapdata
        self.derivation_key = derivation_key


# ---------------------------------------------------------------------------
# Authentication schemes
# ---------------------------------------------------------------------------

class Scheme(Enum):
    """Base enum for MSL authentication schemes."""

    def __str__(self) -> str:
        return str(self.value)


class EntityAuthenticationSchemes(Scheme):
    """Supported entity authentication schemes for MGK."""

    ModelGroup = "MGK"


class UserAuthenticationSchemes(Scheme):
    """Supported user authentication schemes for MGK."""

    EmailPassword = "EMAIL_PASSWORD"
    NetflixIDCookies = "NETFLIXID"
    UserIDToken = "USER_ID_TOKEN"


class EntityAuthentication(MSLObject):
    """Entity authentication data for MGK handshake."""

    def __init__(
        self, scheme: EntityAuthenticationSchemes, authdata: Dict[str, Any]
    ) -> None:
        self.scheme = str(scheme)
        self.authdata = authdata

    @classmethod
    def ModelGroup(cls, identity: str) -> "EntityAuthentication":
        """Create an MGK entity authentication with the given identity."""
        return cls(EntityAuthenticationSchemes.ModelGroup, {"identity": identity})


class UserAuthentication(MSLObject):
    """User authentication data for MGK requests."""

    def __init__(
        self, scheme: UserAuthenticationSchemes, authdata: Dict[str, Any]
    ) -> None:
        self.scheme = str(scheme)
        self.authdata = authdata

    @classmethod
    def EmailPassword(cls, email: str, password: str) -> "UserAuthentication":
        """Create an email/password user authentication."""
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
        """Create a user-ID-token authentication."""
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
        """Create a Netflix-ID-cookie-based authentication."""
        return cls(
            UserAuthenticationSchemes.NetflixIDCookies,
            {
                "netflixid": netflixid,
                "securenetflixid": securenetflixid,
            },
        )


# ---------------------------------------------------------------------------
# MSL_MGK
# ---------------------------------------------------------------------------

class MSL_MGK(MSLBase):
    """Netflix MSL client using AUTHENTICATED_DH (Model Group Key) exchange.

    This platform is fundamentally different from the Widevine/RSA variants:
    it uses Diffie-Hellman key agreement with entity authentication, has its
    own wrapping key derivation, and structures MSL messages with a single
    payload chunk instead of two.
    """

    # -- Platform constants --------------------------------------------------
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
    DEFAULT_PBO_COMMON: Dict[str, str] = {
        "sdk": "2025.2.2.0",
        "platform": "2025.2.2.0",
        "application": (
            "12.1.6-23045 R 2025.2 android-30-JPLAYER2 "
            "ninja_6==NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/"
            "7825230_4040.2147:user/release-keys"
        ),
        "uiversion": (
            "UI-release-20260303_43809-gibbon-r100-darwinql-69067="
            "5,78214=2,78929=8,80045=1,80048=2"
        ),
        "uiPlatform": "tv_ui",
        "clientVersion": "v3.11.512",
        "apkVersion": "12.1.6",
    }
    DEFAULT_PBO_LANGUAGES: List[str] = ["en-CA", "en-US", "en"]

    # -- DH / wrapping constants ---------------------------------------------
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
    DH_P: int = int.from_bytes(DH_PRIME, "big")
    DH_G: int = 5

    # -- Constructor ---------------------------------------------------------

    def __init__(
        self,
        session: requests.Session,
        sender: str,
        keys: MSLKeys,
        message_id: int,
        user_auth: Optional[dict] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(session=session, keys=keys, message_id=message_id, sender=sender)
        self.user_auth = user_auth
        self.cookies = cookies

    # -----------------------------------------------------------------------
    # DH key agreement & wrapping
    # -----------------------------------------------------------------------

    @classmethod
    def derive_wrapping_key(
        cls, encryption_key_16: bytes, hmac_key_32: bytes
    ) -> bytes:
        """Derive a 16-byte wrapping key from encryption and HMAC keys."""
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
        """Encode a non-negative integer as big-endian unsigned bytes."""
        if value < 0:
            raise ValueError("value must be non-negative")
        if value == 0:
            return b"\x00"
        return value.to_bytes((value.bit_length() + 7) // 8, "big", signed=False)

    @staticmethod
    def correct_null_bytes(value: bytes) -> bytes:
        """Ensure at most one leading null byte (DH public-key encoding)."""
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
        """Generate a Diffie-Hellman key pair. Returns (private_key, public_key_bytes)."""
        private_key = int.from_bytes(os.urandom(len(cls.DH_PRIME)), "big") % (
            cls.DH_P - 3
        ) + 2
        public_key = pow(cls.DH_G, private_key, cls.DH_P)
        public_key_bytes = cls.int_to_unsigned_bytes(public_key)
        return private_key, cls.correct_null_bytes(public_key_bytes)

    @classmethod
    def dh_compute_shared_secret_bytes(
        cls, dh_private_key: int, server_public_key_wire: bytes
    ) -> bytes:
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
        """Key derivation for AUTHENTICATED_DH.

        Returns (encryption_key, hmac_key, next_derivation_key).
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

    # -----------------------------------------------------------------------
    # MSL v1 encrypt / decrypt / sign / verify (MGK-specific)
    # -----------------------------------------------------------------------

    @staticmethod
    def msl_encrypt_v1(
        key_id: str, encryption_key_16: bytes, plaintext_bytes: bytes
    ) -> bytes:
        """Encrypt data using MSL v1 envelope format (AES-CBC)."""
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
        """Decrypt an MSL v1 envelope (AES-CBC)."""
        envelope = json.loads(envelope_bytes.decode("utf-8"))
        iv = base64.b64decode(envelope["iv"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        padded_plaintext = AES.new(encryption_key_16, AES.MODE_CBC, iv).decrypt(
            ciphertext
        )
        return unpad(padded_plaintext, AES.block_size)

    @staticmethod
    def msl_sign_b64(hmac_key_32: bytes, data_bytes: bytes) -> str:
        """Compute an HMAC-SHA256 signature and return it base64-encoded."""
        signer = HMAC.new(hmac_key_32, digestmod=SHA256)
        signer.update(data_bytes)
        return base64.b64encode(signer.digest()).decode("ascii")

    @staticmethod
    def msl_verify_sig(
        hmac_key_32: bytes, data_bytes: bytes, signature_b64: str
    ) -> None:
        """Verify an HMAC-SHA256 signature. Raises :class:`ValueError` on mismatch."""
        signer = HMAC.new(hmac_key_32, digestmod=SHA256)
        signer.update(data_bytes)
        expected_signature = signer.digest()
        received_signature = base64.b64decode(signature_b64)
        if expected_signature != received_signature:
            raise ValueError(
                "Response signature verification failed: HMAC mismatch"
            )

    # -----------------------------------------------------------------------
    # Sidecar file helpers
    # -----------------------------------------------------------------------

    @classmethod
    def find_sidecar_file(cls, filename: str, env_name: str) -> Optional[Path]:
        """Locate a sidecar file by checking an env var, CWD, and module dir."""
        env_value = os.getenv(env_name)
        candidates: List[Path] = []

        if env_value:
            candidates.append(Path(env_value))

        roots = [Path.cwd(), Path(__file__).resolve().parent]
        for root in roots:
            candidates.append(root / filename)
            candidates.extend(root.glob(f"**/{filename}"))

        seen: set[str] = set()
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
        """Load an ESNID string from a text file."""
        value = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not value:
            raise ValueError(f"Empty ESNID file: {path}")
        return value

    @classmethod
    def load_kpe_kph_file(cls, path: Path) -> Tuple[bytes, bytes, bytes]:
        """Load Kpe/Kph keys from a comma-separated base64 file.

        Returns (encryption_key, hmac_key, wrapping_key).
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

    # -----------------------------------------------------------------------
    # Custom base64 decode (strict validation)
    # -----------------------------------------------------------------------

    @staticmethod
    def b64_decode_strict(value: str) -> bytes:
        """Base64-decode a string with strict validation."""
        normalized_value = value.strip().strip('"').strip("'")
        return base64.b64decode(normalized_value.encode("ascii"), validate=True)

    # -----------------------------------------------------------------------
    # Custom generate_msg_header (json.dumps, custom languages, no recipient)
    # -----------------------------------------------------------------------

    @staticmethod
    def generate_msg_header(
        message_id: int,
        sender: str,
        is_handshake: bool,
        userauthdata: Optional[dict] = None,
        keyrequestdata: Optional[dict] = None,
        compression: Optional[str] = "GZIP",
    ) -> str:
        """Generate an MSL message header for MGK.

        Uses ``json.dumps`` (not jsonpickle) with compact separators, a
        single-language list, and no ``recipient`` field.
        """
        header_data: Dict[str, Any] = {
            "messageid": message_id,
            "renewable": True,
            "handshake": is_handshake,
            "capabilities": {
                "compressionalgos": [compression] if compression else [],
                "languages": ["en-US"],
                "encoderformats": ["JSON"],
            },
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "sender": sender,
            "nonreplayable": False,
        }
        if userauthdata:
            header_data["userauthdata"] = userauthdata
        if keyrequestdata:
            header_data["keyrequestdata"] = [keyrequestdata]
        return json.dumps(header_data, separators=(",", ":"))

    # -----------------------------------------------------------------------
    # AUTHENTICATED_DH handshake
    # -----------------------------------------------------------------------

    @classmethod
    def handshake(
        cls,
        session: requests.Session,
        sender: str,
        kpekph_path: Optional[Union[str, Path]] = None,
        msl_keys_path: Optional[Union[str, Path]] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        new_msl: bool = False,
    ) -> "MSL_MGK":
        """Perform an AUTHENTICATED_DH key exchange and return a configured instance."""
        endpoint = "https://www.netflix.com/msl/playapi/cadmium/licensedmanifest/1"
        message_id = random.randint(0, pow(2, 52))

        if cookies:
            session.cookies.update(cookies)

        cache_path = Path(msl_keys_path) if msl_keys_path else None
        cached_keys = None if new_msl else cls.load_cache_data(cache_path)

        if cached_keys is not None:
            return cls(
                session=session,
                sender=sender,
                keys=cached_keys,
                message_id=message_id,
                cookies=cookies,
            )

        if not sender:
            raise RuntimeError("Missing sender or ESNID for MGK handshake")

        if kpekph_path:
            resolved_kpekph_path = Path(kpekph_path)
        else:
            resolved_kpekph_path = cls.find_sidecar_file("KpeKph", "MSL_KPEKPH_PATH")
            if not resolved_kpekph_path:
                raise RuntimeError(
                    "KpeKph was not found. Place KpeKph next to the client, "
                    "inside a child folder, in the current working directory, "
                    "or set MSL_KPEKPH_PATH."
                )

        entity_encryption_key, entity_hmac_key, entity_wrapping_key = (
            cls.load_kpe_kph_file(resolved_kpekph_path)
        )

        msl_keys = MSLKeys()
        cached_wrapdata = cached_keys.wrapdata if cached_keys else None
        cached_derivation_key = cached_keys.derivation_key if cached_keys else None
        mechanism = "WRAP" if cached_wrapdata and cached_derivation_key else "MGK"
        derivation_key = cached_derivation_key or entity_wrapping_key

        dh_private_key, dh_public_key_wire = cls.dh_generate_keypair()
        key_data: Dict[str, Any] = {
            "mechanism": mechanism,
            "publickey": cls.b64_encode_bytes(
                cls.correct_null_bytes(dh_public_key_wire)
            ),
            "parametersid": "1",
        }

        if mechanism == "WRAP":
            key_data["wrapdata"] = cls.b64_encode_bytes(cached_wrapdata)

        key_request_data = {
            "scheme": "AUTHENTICATED_DH",
            "keydata": key_data,
        }
        entity_auth_data = EntityAuthentication.ModelGroup(sender).__dict__

        header_plaintext = cls.generate_msg_header(
            message_id=message_id,
            sender=sender,
            is_handshake=True,
            keyrequestdata=key_request_data,
            compression="GZIP",
        ).encode("utf-8")
        header_ciphertext = cls.msl_encrypt_v1(
            sender, entity_encryption_key, header_plaintext
        )

        payload_plaintext = cls.stable_json(
            {
                "messageid": message_id,
                "data": "",
                "sequencenumber": 1,
                "endofmsg": True,
            }
        ).encode("utf-8")
        payload_ciphertext = cls.msl_encrypt_v1(
            sender, entity_encryption_key, payload_plaintext
        )

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

        response = session.post(
            url=endpoint,
            data=request_body,
            headers=headers or {},
            timeout=timeout,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Key exchange failed: HTTP {response.status_code} {response.text[:500]}"
            )

        parsed_response = cls.parse_concatenated_json(response.text)
        if not parsed_response:
            raise RuntimeError("Key exchange failed: empty MSL response")

        key_exchange = parsed_response[0]

        if "errordata" in key_exchange:
            decoded_error = base64.b64decode(key_exchange["errordata"]).decode(
                "utf-8", "ignore"
            )
            raise RuntimeError(f"Key exchange failed: {decoded_error}")

        if "headerdata" not in key_exchange:
            raise RuntimeError(
                f"Key exchange failed: missing headerdata in response: "
                f"{str(key_exchange)[:500]}"
            )

        header_json = json.loads(
            base64.b64decode(key_exchange["headerdata"]).decode("utf-8")
        )
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
            dh_private_key, server_public_key_wire
        )
        encryption_key, sign_key, next_derivation_key = cls.kdf_authenticated_dh(
            derivation_key, shared_secret
        )

        msl_keys.encryption = encryption_key
        msl_keys.sign = sign_key
        msl_keys.derivation_key = next_derivation_key
        msl_keys.mastertoken = key_response_data["mastertoken"]

        if cache_path:
            cls.cache_keys(msl_keys, cache_path)

        return cls(
            session=session,
            sender=sender,
            keys=msl_keys,
            message_id=message_id,
            cookies=cookies,
        )

    # -----------------------------------------------------------------------
    # Platform-specific request headers
    # -----------------------------------------------------------------------

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

    # -- Manifest defaults ---------------------------------------------------

    @staticmethod
    def manifest_request_defaults() -> Tuple[str, Dict[str, str]]:
        """Return the default manifest endpoint and query params for MGK."""
        return MSL_MGK.DEFAULT_MANIFEST_ENDPOINT, dict(MSL_MGK.DEFAULT_MANIFEST_PARAMS)

    # -----------------------------------------------------------------------
    # MGK-specific send_message
    # -----------------------------------------------------------------------

    def send_message(
        self,
        endpoint: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
        application_data: Optional[Dict[str, Any]] = None,
        userauthdata: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> Tuple[Dict[str, Any], Any]:
        """Send an MSL message via the MGK flow.

        Raises :class:`RuntimeError` on MSL errors.
        """
        message = self.create_message(application_data or {}, userauthdata)
        response = self.session.post(
            url=endpoint or self.DEFAULT_MANIFEST_ENDPOINT,
            data=message,
            params=params or {},
            headers=headers or {},
            cookies=self.cookies,
            timeout=timeout,
        )

        if response.status_code != 200:
            body_preview = (
                response.text[:500]
                if response.text
                else response.content[:200].hex()
            )
            raise RuntimeError(
                f"MSL request failed: HTTP {response.status_code} {body_preview}"
            )

        header, payload_data = self.parse_message(response)

        if "errordata" in header:
            decoded_error = json.loads(
                base64.b64decode(header["errordata"]).decode("utf-8")
            )
            raise RuntimeError(f"MSL response contains an error: {decoded_error}")

        return header, payload_data

    # -----------------------------------------------------------------------
    # MGK-specific create_message (single payload chunk)
    # -----------------------------------------------------------------------

    def create_message(
        self,
        application_data: Dict[str, Any],
        userauthdata: Optional[dict] = None,
    ) -> str:
        """Build an MSL request message with a **single** payload chunk.

        Unlike the base class which splits data across two chunks
        (data + end-of-msg), MGK puts everything in one chunk with
        ``endofmsg=True``.
        """
        self.message_id += 1

        header_data = self.encrypt(
            self.generate_msg_header(
                message_id=self.message_id,
                sender=self.sender,
                is_handshake=False,
                userauthdata=userauthdata,
                compression="GZIP",
            )
        )
        message = json.dumps(
            {
                "headerdata": base64.b64encode(header_data.encode("utf-8")).decode(
                    "utf-8"
                ),
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
                "payload": base64.b64encode(payload_chunk.encode("utf-8")).decode(
                    "utf-8"
                ),
                "signature": self.sign(payload_chunk).decode("utf-8"),
            },
            separators=(",", ":"),
        )

        return message

    # -----------------------------------------------------------------------
    # MGK-specific parse_message (accepts response objects)
    # -----------------------------------------------------------------------

    def parse_message(self, response: Any) -> Tuple[Dict[str, Any], Any]:
        """Parse an MSL response.

        Accepts either a :class:`requests.Response` object or a raw string.
        Raises :class:`RuntimeError` if the response is empty or not valid
        concatenated JSON.
        """
        if hasattr(response, "text"):
            message = response.text or ""
            raw_content = response.content
            status_code = getattr(response, "status_code", None)
            content_type = (
                response.headers.get("Content-Type", "")
                if getattr(response, "headers", None)
                else ""
            )
        else:
            message = str(response or "")
            raw_content = message.encode("utf-8", errors="ignore")
            status_code = None
            content_type = ""

        parsed_message = self.parse_concatenated_json(message)

        if not parsed_message:
            preview = raw_content[:200]
            try:
                preview_text = preview.decode("utf-8", errors="replace")
            except Exception:
                preview_text = repr(preview)
            raise RuntimeError(
                "MSL response was empty or not concatenated JSON. "
                f"status={status_code} content_type={content_type!r} "
                f"body_preview={preview_text!r}"
            )

        header = parsed_message[0]
        encrypted_payload_chunks = parsed_message[1:] if len(parsed_message) > 1 else []
        payload_chunks = (
            self.decrypt_payload_chunks(encrypted_payload_chunks)
            if encrypted_payload_chunks
            else {}
        )

        return header, payload_chunks

    # -----------------------------------------------------------------------
    # MGK-specific decrypt_payload_chunks (raises on error)
    # -----------------------------------------------------------------------

    def decrypt_payload_chunks(
        self, payload_chunks: List[Dict[str, str]]
    ) -> Any:
        """Decrypt MSL payload chunks.  Raises :class:`RuntimeError` on error."""
        if not self.keys.encryption:
            raise ValueError("Encryption key is not available")

        raw_data = ""

        for payload_chunk in payload_chunks:
            payload_chunk_json = json.loads(
                base64.b64decode(payload_chunk["payload"]).decode("utf-8")
            )
            payload_decrypted = self.aes_cbc_decrypt(
                self.keys.encryption,
                base64.b64decode(payload_chunk_json["iv"]),
                base64.b64decode(payload_chunk_json["ciphertext"]),
            )
            payload_decrypted_json = json.loads(payload_decrypted.decode("utf-8"))
            payload_data = base64.b64decode(payload_decrypted_json["data"])

            if payload_decrypted_json.get("compressionalgo") == "GZIP":
                payload_data = zlib.decompress(payload_data, 16 + zlib.MAX_WBITS)

            raw_data += payload_data.decode("utf-8")

        data = json.loads(raw_data)

        if "error" in data:
            raise RuntimeError(data["error"])

        if "result" not in data:
            return data

        return data["result"]

    # -----------------------------------------------------------------------
    # MGK-specific encrypt / sign (use aes_cbc_encrypt from base)
    # -----------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using the negotiated AES-CBC key."""
        if not self.keys.encryption:
            raise ValueError("Encryption key is not available")
        if not self.keys.mastertoken:
            raise ValueError("Master token is not available")

        iv = os.urandom(16)
        token_data = json.loads(
            base64.b64decode(self.keys.mastertoken["tokendata"]).decode("utf-8")
        )
        ciphertext = self.aes_cbc_encrypt(
            self.keys.encryption, iv, plaintext.encode("utf-8")
        )

        return json.dumps(
            {
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                "keyid": f"{self.sender}_{token_data['sequencenumber']}",
                "sha256": "AA==",
                "iv": base64.b64encode(iv).decode("utf-8"),
            },
            separators=(",", ":"),
        )

    def sign(self, text: str) -> bytes:
        """Sign text using the negotiated HMAC key."""
        if not self.keys.sign:
            raise ValueError("Sign key is not available")

        signer = HMAC.new(self.keys.sign, digestmod=SHA256)
        signer.update(text.encode("utf-8"))
        return base64.b64encode(signer.digest())

    # -----------------------------------------------------------------------
    # Cache I/O override (checks expiration, not renewalwindow)
    # -----------------------------------------------------------------------

    @classmethod
    def load_cache_data(cls, msl_keys_path: Optional[Path] = None) -> Optional[MSLKeys]:
        """Load cached keys, checking the ``expiration`` field in the token."""
        if not msl_keys_path or not msl_keys_path.is_file():
            return None

        loaded_keys = jsonpickle.decode(msl_keys_path.read_text(encoding="utf-8"))

        if not isinstance(loaded_keys, MSLKeys):
            return None

        if loaded_keys.mastertoken:
            expiry_value = json.loads(
                base64.b64decode(loaded_keys.mastertoken["tokendata"]).decode("utf-8")
            ).get("expiration")

            if expiry_value is not None:
                expiry = datetime.fromtimestamp(int(expiry_value), tz=timezone.utc)
                hours_remaining = (
                    (expiry - datetime.now(timezone.utc)).total_seconds() / 3600
                )
                if hours_remaining < 10:
                    return None

        if not hasattr(loaded_keys, "wrapdata"):
            loaded_keys.wrapdata = None
        if not hasattr(loaded_keys, "derivation_key"):
            loaded_keys.derivation_key = None

        return loaded_keys

    # cache_keys inherited from MSLBase (identical implementation)


__all__ = [
    "EntityAuthentication",
    "EntityAuthenticationSchemes",
    "MSL_MGK",
    "MSLKeys",
    "Scheme",
    "UserAuthentication",
    "UserAuthenticationSchemes",
]
