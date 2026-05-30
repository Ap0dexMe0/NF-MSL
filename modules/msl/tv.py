from __future__ import annotations

import base64
import json
import logging
import random
from pathlib import Path

_log = logging.getLogger(__name__)
from typing import Any, Dict, List, Optional, Tuple

import jsonpickle
import requests
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey.RSA import RsaKey
from pywidevine import Cdm as WidevineCdm, Device as WidevineDevice, PSSH

from .base import MSLBase, MSLKeys as _BaseMSLKeys, get_widevine_key


# ---------------------------------------------------------------------------
# Platform-specific key container
# ---------------------------------------------------------------------------

class MSLKeys(_BaseMSLKeys):
    """TV MSL keys – extends the base with an RSA key and CDM session."""

    def __init__(
        self,
        encryption: Optional[bytes] = None,
        sign: Optional[bytes] = None,
        rsa: Optional[RsaKey] = None,
        mastertoken: Optional[dict] = None,
        cdm_session: Any = None,
    ) -> None:
        super().__init__(encryption=encryption, sign=sign, mastertoken=mastertoken)
        self.rsa = rsa
        self.cdm_session = cdm_session


# ---------------------------------------------------------------------------
# MSL_TV
# ---------------------------------------------------------------------------

class MSL_TV(MSLBase):
    """Netflix MSL client for TV devices, supporting both Widevine and RSA."""

    # -- Platform constants --------------------------------------------------
    DEFAULT_HANDSHAKE_ENDPOINT: str = (
        "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_tokens/%5E1.0.0/router"
    )
    DEFAULT_MANIFEST_ENDPOINT: str = (
        "https://api-global.netflix.com/playapi/nrdjs/manifest/1"
    )
    DEFAULT_MANIFEST_PARAMS: Dict[str, str] = {
        "ab_ui_ver": "darwin",
        "nrdapp_version": "2025.2.3.0",
    }
    DEFAULT_USER_AGENT: str = (
        "Netflix/2025.2.3.0 "
        "(DEVTYPE=NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019; "
        "Milo=1.0.6315; build_number=6315; build_sha=a1b915de)"
    )
    DEFAULT_REQUEST_CONTEXT: str = '{"appstate":"foreground","reason":"unknown"}'
    DEFAULT_NRDJS_VERSION: str = "v3.12.55"
    DEFAULT_NETJS_VERSION: str = "3.0.5"
    DEFAULT_PBO_VERSION: int = 2
    DEFAULT_PBO_COMMON: Dict[str, str] = {
        "sdk": "2025.2.3.0",
        "platform": "2025.2.3.0",
        "application": (
            "12.1.9-23083 R 2025.2 android-30-JPLAYER2 "
            "ninja_6==NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/"
            "7825230_4040.2147:user/release-keys"
        ),
        "uiversion": (
            "UI-release-20260407_44745-gibbon-r100-darwinql-69067="
            "5,80198=2,80211=3"
        ),
        "uiPlatform": "tv_ui",
        "clientVersion": "v3.12.55",
        "apkVersion": "12.1.9",
    }
    DEFAULT_PBO_LANGUAGES: List[str] = ["en-US", "en-PH", "en"]
    DEFAULT_DEVICE_MODEL: str = "NVIDIA_SHIELD%20Android%20TV"

    # -- Constructor ---------------------------------------------------------

    def __init__(
        self,
        session: requests.Session,
        keys: MSLKeys,
        message_id: int,
        sender: str,
        user_auth: Optional[dict] = None,
        drm: str = "widevine",
        proxy: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(session=session, keys=keys, message_id=message_id, sender=sender, proxy=proxy)
        self.user_auth = user_auth
        self.drm = drm

    # -- Dual-mode handshake (Widevine + RSA) --------------------------------

    @classmethod
    def handshake(
        cls,
        msl_keys_path: str,
        session: requests.Session,
        sender: str,
        cdm: Any,
        cdm_device: Any,
        new_msl: bool,
        cookies: Optional[Dict[str, str]],
        drm: str,
        endpoint: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> MSLKeys:
        """Perform a key exchange using Widevine (if CDM available) or RSA."""
        _log.info("TV MSL handshake: sender=%s, drm=%s", sender, drm)
        if cookies:
            session.cookies.update(cookies)

        cache_path = Path(msl_keys_path)
        msl_keys = cls.load_cache_data(cache_path)
        if msl_keys is not None and not new_msl:
            _log.info("Reusing cached MSL keys")
            return msl_keys
        _log.info("Performing fresh key exchange")

        message_id = random.randint(0, pow(2, 52))
        msl_keys = MSLKeys()

        # ---- Choose DRM scheme ---------------------------------------------
        if not cdm and drm == "widevine":
            _log.debug("No CDM provided — falling back to RSA key exchange")
            # No CDM provided – fall back to RSA key exchange
            msl_keys.rsa = RSA.generate(2048)
            assert msl_keys.rsa is not None
            keyrequestdata = {
                "scheme": "ASYMMETRIC_WRAPPED",
                "keydata": {
                    "keypairid": "rsaKeypairId",
                    "mechanism": "JWK_RSA",
                    "publickey": base64.b64encode(
                        msl_keys.rsa.publickey().export_key(format="DER")
                    ).decode("utf-8"),
                },
            }
        elif drm == "widevine":
            _log.debug("Using Widevine DRM for key exchange")
            # CDM available – use Widevine
            if not isinstance(cdm, WidevineCdm):
                device = WidevineDevice.load(cdm_device)
                cdm = WidevineCdm.from_device(device)
            cdm_session = cdm.open()
            msl_keys.cdm_session = cdm_session
            challenge = cdm.get_license_challenge(
                cdm_session, PSSH.new(system_id=PSSH.SystemId.Widevine)
            )
            wv_request = base64.b64encode(challenge).decode("utf-8")
            keyrequestdata = {
                "scheme": "WIDEVINE",
                "keydata": {
                    "keyrequest": wv_request,
                },
            }
        else:
            raise ValueError(f"Unsupported DRM mode: {drm}")

        # ---- Build & send handshake request --------------------------------
        data = jsonpickle.encode(
            {
                "entityauthdata": {
                    "scheme": "NONE",
                    "authdata": {
                        "identity": sender,
                    },
                },
                "headerdata": base64.standard_b64encode(
                    cls.generate_msg_header(
                        message_id=message_id,
                        sender=sender,
                        is_handshake=True,
                        keyrequestdata=keyrequestdata,
                    ).encode("utf-8")
                ).decode("utf-8"),
                "signature": "",
            },
            unpicklable=False,
        )
        data += json.dumps(
            {
                "payload": base64.standard_b64encode(
                    json.dumps(
                        {
                            "messageid": message_id,
                            "data": "",
                            "sequencenumber": 1,
                            "endofmsg": True,
                        }
                    ).encode("utf-8")
                ).decode("utf-8"),
                "signature": "",
            }
        )

        handshake_endpoint = endpoint or cls.DEFAULT_HANDSHAKE_ENDPOINT
        handshake_headers = headers or cls.build_request_headers(
            request_name="mintCookies",
            esn=sender,
            host="nrdp25.prod.ftl.netflix.com",
            language="en-US,en-PH,en",
        )
        _log.debug("TV handshake request → %s", handshake_endpoint)
        res = session.post(
            url=handshake_endpoint, data=data, headers=handshake_headers, timeout=30
        )
        _log.debug("TV handshake response ← HTTP %d", res.status_code)

        if res.status_code != 200:
            raise RuntimeError(
                f"Key exchange failed: HTTP {res.status_code} {res.text[:500]}"
            )

        parsed = cls.parse_concatenated_json(res.text)
        if not parsed:
            raise RuntimeError("Key exchange failed: empty MSL response")

        key_exchange = parsed[0]

        if "errordata" in key_exchange:
            decoded_error = base64.standard_b64decode(
                key_exchange["errordata"]
            ).decode("utf-8")
            error_json = json.loads(decoded_error)
            raise RuntimeError(f"Key exchange failed: {error_json}")

        if "headerdata" not in key_exchange:
            raise RuntimeError(
                f"Key exchange failed: missing headerdata in response: "
                f"{str(key_exchange)[:500]}"
            )

        header_json = json.loads(
            base64.standard_b64decode(key_exchange["headerdata"]).decode("utf-8")
        )
        key_response_data = header_json["keyresponsedata"]
        key_data = key_response_data["keydata"]

        # ---- Derive encryption / signing keys from response ----------------
        if cdm:
            # Widevine path
            cdm.parse_license(msl_keys.cdm_session, key_data["cdmkeyresponse"])
            wv_keys = cdm.get_keys(msl_keys.cdm_session)
            msl_keys.encryption = get_widevine_key(
                kid=base64.standard_b64decode(key_data["encryptionkeyid"]),
                keys=wv_keys,
                permissions=["AllowEncrypt", "AllowDecrypt"],
            )
            msl_keys.sign = get_widevine_key(
                kid=base64.standard_b64decode(key_data["hmackeyid"]),
                keys=wv_keys,
                permissions=["AllowSign", "AllowSignatureVerify"],
            )
        else:
            # RSA path
            assert msl_keys.rsa is not None
            cipher_rsa = PKCS1_OAEP.new(msl_keys.rsa)
            msl_keys.encryption = cls.base64key_decode(
                json.loads(
                    cipher_rsa.decrypt(
                        base64.standard_b64decode(key_data["encryptionkey"])
                    ).decode("utf-8")
                )["k"]
            )
            msl_keys.sign = cls.base64key_decode(
                json.loads(
                    cipher_rsa.decrypt(
                        base64.standard_b64decode(key_data["hmackey"])
                    ).decode("utf-8")
                )["k"]
            )

        msl_keys.mastertoken = key_response_data["mastertoken"]
        cls.cache_keys(msl_keys, cache_path)
        _log.info("TV key exchange complete")
        return msl_keys

    # -- Platform-specific request headers -----------------------------------

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
        host: Optional[str] = "nrdp25.prod.ftl.netflix.com",
        language: Optional[str] = "en-US,en-PH,en",
        device_model: Optional[str] = None,
    ) -> Dict[str, str]:
        """Build the HTTP headers required for TV MSL requests."""
        headers: Dict[str, str] = {
            "Host": host or "nrdp25.prod.ftl.netflix.com",
            "Language": language or "en-US,en-PH,en",
            "User-Agent": user_agent or MSL_TV.DEFAULT_USER_AGENT,
            "Accept": "*/*",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "deflate,gzip",
            "Content-Type": "application/json",
            "X-Gibbon-Cache-Control": "no-cache",
            "X-AllowCompression": "true",
            "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
            "X-DeviceModel": device_model or MSL_TV.DEFAULT_DEVICE_MODEL,
            "x-netflix.client.nrdjs.version": MSL_TV.DEFAULT_NRDJS_VERSION,
            "X-Netflix.Client.Request.Name": request_name,
            "X-Netflix.request.attempt": "1",
            "X-Netflix.Request.NonJson.Headers": "true",
            "X-Netflix.Request.Client.Context": MSL_TV.DEFAULT_REQUEST_CONTEXT,
            "x-netflix.client.netjs.version": MSL_TV.DEFAULT_NETJS_VERSION,
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
        """Return the default manifest endpoint and query params for TV."""
        return MSL_TV.DEFAULT_MANIFEST_ENDPOINT, dict(MSL_TV.DEFAULT_MANIFEST_PARAMS)

    # -- Custom generate_msg_header (TV-specific languages) ------------------

    @staticmethod
    def generate_msg_header(
        message_id: int,
        sender: str,
        is_handshake: bool,
        userauthdata: Optional[dict] = None,
        keyrequestdata: Optional[dict] = None,
        compression: Optional[str] = "GZIP",
    ) -> str:
        """Generate an MSL message header with TV-specific language list."""
        return MSLBase.generate_msg_header(
            message_id=message_id,
            sender=sender,
            is_handshake=is_handshake,
            userauthdata=userauthdata,
            keyrequestdata=keyrequestdata,
            compression=compression,
            languages=["en-US", "en-PH", "en"],
        )

    # -- Override send_message to add PBO normalisation ----------------------
    # BUG FIX: original used sys.exit(print(...)) on error; now raises RuntimeError.

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
        """Send an MSL message with PBO payload normalisation.

        Raises :class:`RuntimeError` on MSL errors instead of calling
        ``sys.exit()``.
        """
        normalized = self.normalize_application_data(endpoint, application_data)
        return super().send_message(
            endpoint=endpoint,
            params=params,
            application_data=normalized,
            userauthdata=userauthdata,
            headers=headers,
            proxy=proxy,
            timeout=timeout,
        )

    # -- Cache I/O overrides (RSA key serialisation) -------------------------

    @staticmethod
    def load_cache_data(msl_keys_path: Optional[Path] = None) -> Optional[MSLKeys]:
        """Load cached keys, re-importing the RSA key from its PEM form."""
        msl_keys = MSLBase.load_cache_data(msl_keys_path)
        if msl_keys is None:
            return None
        # Re-import RSA key from serialised PEM form
        if getattr(msl_keys, "rsa", None):
            msl_keys.rsa = RSA.import_key(msl_keys.rsa)
        return msl_keys

    @staticmethod
    def cache_keys(msl_keys: MSLKeys, msl_keys_path: Path) -> None:
        """Persist keys, exporting the RSA key to PEM for JSON compatibility."""
        original_rsa = msl_keys.rsa
        if msl_keys.rsa:
            msl_keys.rsa = msl_keys.rsa.export_key()
        MSLBase.cache_keys(msl_keys, msl_keys_path)
        if original_rsa:
            msl_keys.rsa = original_rsa


__all__ = ["MSL_TV", "MSLKeys"]
