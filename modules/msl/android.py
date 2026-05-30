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
from Cryptodome.Cipher import PKCS1_OAEP, AES as _AES
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey.RSA import RsaKey
from pywidevine import Cdm as WidevineCdm, Device as WidevineDevice, PSSH

from modules.msl.base import MSLBase, MSLKeys as _BaseMSLKeys, get_widevine_key


# ---------------------------------------------------------------------------
# Platform-specific key container
# ---------------------------------------------------------------------------

class MSLKeys(_BaseMSLKeys):
    """Android MSL keys – extends the base with an RSA key and CDM session."""

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
# MSL_ANDROID
# ---------------------------------------------------------------------------

class MSL_ANDROID(MSLBase):
    """Netflix MSL client for Android devices using Widevine DRM."""

    # -- Platform constants --------------------------------------------------
    DEFAULT_HANDSHAKE_ENDPOINT: str = (
        "https://android.prod.ftl.netflix.com/nq/androidui/pbo_license/~1.0.0/router"
    )
    DEFAULT_MANIFEST_ENDPOINT: str = (
        "https://android.prod.ftl.netflix.com/msl/playapi/android/manifest"
    )
    DEFAULT_MANIFEST_PARAMS: Dict[str, str] = {
        "ab_ui_ver": "android",
        "nrdapp_version": "18.26.0",
    }
    DEFAULT_USER_AGENT: str = (
        "com.netflix.mediaclient/63988 "
        "(Linux; U; Android 15; en_US; SM-F711N; "
        "Build/AP3A.240905.015.A2; Cronet/143.0.7445.0)"
    )
    DEFAULT_REQUEST_CONTEXT: str = '{"appState":"foreground","appView":"unknown"}'
    DEFAULT_NRDJS_VERSION: str = "v3.12.55"
    DEFAULT_NETJS_VERSION: str = "3.0.5"
    DEFAULT_PBO_VERSION: int = 2
    DEFAULT_PBO_COMMON: Dict[str, str] = {
        "sdk": "18.26.0",
        "platform": "18.26.0",
        "application": "Netflix Android 18.26.0",
        "uiversion": "18.26.0",
        "uiPlatform": "android",
        "clientVersion": "18.26.0",
        "apkVersion": "18.26.0",
    }
    DEFAULT_PBO_LANGUAGES: List[str] = ["en-US", "en"]
    DEFAULT_DEVICE_MODEL: str = "SM-F711N"

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

    # -- Widevine handshake --------------------------------------------------

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
        """Perform a Widevine key exchange and return negotiated keys."""
        _log.info("Android Widevine handshake: sender=%s", sender)
        if cookies:
            session.cookies.update(cookies)

        cache_path = Path(msl_keys_path)
        msl_keys = cls.load_cache_data(cache_path)
        if msl_keys is not None and not new_msl:
            _log.info("Reusing cached MSL keys")
            return msl_keys
        _log.info("Performing fresh Widevine key exchange")

        if drm != "widevine":
            raise ValueError(f"Unsupported DRM mode: {drm}")

        if not cdm:
            raise ValueError("Widevine CDM is required for this Android MSL flow")

        message_id = random.randint(0, pow(2, 52))
        msl_keys = MSLKeys()

        if not isinstance(cdm, WidevineCdm):
            device = WidevineDevice.load(cdm_device)
            cdm = WidevineCdm.from_device(device)

        cdm_session = cdm.open()
        msl_keys.cdm_session = cdm_session
        challenge = cdm.get_license_challenge(
            cdm_session,
            PSSH.new(system_id=PSSH.SystemId.Widevine),
        )
        _log.debug("Widevine challenge created (%d bytes)", len(challenge))
        wv_request = base64.b64encode(challenge).decode("utf-8")
        keyrequestdata = {
            "scheme": "WIDEVINE",
            "keydata": {
                "keyrequest": wv_request,
            },
        }

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
            host="android15.prod.cloud.netflix.com",
            language="en-US,en",
        )
        _log.debug("Widevine handshake request → %s", handshake_endpoint)
        res = session.post(
            url=handshake_endpoint, data=data, headers=handshake_headers, timeout=30
        )
        _log.debug("Widevine handshake response ← HTTP %d", res.status_code)

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

        msl_keys.mastertoken = key_response_data["mastertoken"]
        cls.cache_keys(msl_keys, cache_path)
        _log.info("Widevine key exchange complete")
        return msl_keys

    # -- RSA / ASYMMETRIC_WRAPPED handshake (no Widevine required) -----------

    @classmethod
    def rsa_handshake(
        cls,
        msl_keys_path: str,
        session: requests.Session,
        sender: str,
        new_msl: bool,
        cookies: Optional[Dict[str, str]],
        endpoint: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> "MSLKeys":
        """Perform an ASYMMETRIC_WRAPPED (RSA + JWE) key exchange.

        This path does **not** require a Widevine device file.  Netflix wraps
        the session AES-GCM keys with our ephemeral RSA-OAEP public key and
        returns them inside a JWE compact serialisation.

        The ESN must use the ``NFCDCH-02-`` prefix (web-style) so that the
        Android FTL endpoint accepts the ``NONE`` entity auth scheme.
        """
        _log.info("Android RSA handshake: sender=%s", sender)
        if cookies:
            session.cookies.update(cookies)

        cache_path = Path(msl_keys_path)
        cached = cls.load_cache_data(cache_path)
        if cached is not None and not new_msl:
            _log.info("Reusing cached RSA MSL keys")
            return cached
        _log.info("Performing fresh RSA key exchange")

        # ---- Generate ephemeral RSA-2048 keypair ----------------------------
        rsa_key = RSA.generate(2048)
        _log.debug("Generated RSA-2048 ephemeral keypair")
        pub_der_b64 = base64.b64encode(
            rsa_key.publickey().export_key("DER")
        ).decode("ascii")

        message_id = random.randint(0, 2 ** 52)
        msl_keys = MSLKeys(rsa=rsa_key)

        keyrequestdata = {
            "scheme": "ASYMMETRIC_WRAPPED",
            "keydata": {
                "keypairid": "rsaKeypairId",
                "mechanism": "JWE_RSA",
                "publickey": pub_der_b64,
            },
        }

        data = jsonpickle.encode(
            {
                "entityauthdata": {
                    "scheme": "NONE",
                    "authdata": {"identity": sender},
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
            host="android15.prod.cloud.netflix.com",
            language="en-US,en",
        )
        _log.debug("RSA handshake request → %s", handshake_endpoint)
        res = session.post(
            url=handshake_endpoint,
            data=data,
            headers=handshake_headers,
            timeout=30,
        )
        _log.debug("RSA handshake response ← HTTP %d", res.status_code)

        if res.status_code != 200:
            raise RuntimeError(
                f"RSA key exchange failed: HTTP {res.status_code} {res.text[:500]}"
            )

        parsed = cls.parse_concatenated_json(res.text)
        if not parsed:
            raise RuntimeError("RSA key exchange failed: empty MSL response")

        key_exchange = parsed[0]

        if "errordata" in key_exchange:
            decoded_error = base64.standard_b64decode(
                key_exchange["errordata"]
            ).decode("utf-8")
            raise RuntimeError(
                f"RSA key exchange failed: {json.loads(decoded_error)}"
            )

        if "headerdata" not in key_exchange:
            raise RuntimeError(
                f"RSA key exchange failed: missing headerdata in response: "
                f"{str(key_exchange)[:500]}"
            )

        header_json = json.loads(
            base64.standard_b64decode(key_exchange["headerdata"]).decode("utf-8")
        )
        key_response_data = header_json["keyresponsedata"]
        key_data = key_response_data["keydata"]

        # ---- Decrypt JWE-wrapped session keys -------------------------------
        msl_keys.encryption = cls._decrypt_jwe_key(
            key_data["encryptionkey"], rsa_key
        )
        msl_keys.sign = cls._decrypt_jwe_key(key_data["hmackey"], rsa_key)
        msl_keys.mastertoken = key_response_data["mastertoken"]

        # Don't persist the RSA key object (not picklable); clear it before caching
        msl_keys.rsa = None
        cls.cache_keys(msl_keys, cache_path)
        _log.info("RSA key exchange complete")
        return msl_keys

    @staticmethod
    def _decrypt_jwe_key(field_b64: str, rsa_private: RsaKey) -> bytes:
        """Decrypt a Netflix JWE-wrapped session key.

        The field value is standard-base64-encoded JWE compact serialisation.
        Netflix uses RSA-OAEP (SHA-1) for the CEK and A128GCM for content
        but skips the AAD in the GCM tag — so we decrypt without verification
        and trust the RSA layer for integrity.
        """
        jwe_compact = base64.b64decode(field_b64 + "==").decode("utf-8")
        hdr_b64, enc_cek_b64, iv_b64, ct_b64, _ = jwe_compact.split(".")

        # Decrypt the Content Encryption Key (CEK) with RSA-OAEP / SHA-1
        enc_cek = base64.urlsafe_b64decode(enc_cek_b64 + "==")
        cek = PKCS1_OAEP.new(rsa_private, hashAlgo=SHA1).decrypt(enc_cek)

        # Decrypt the payload with AES-128-GCM (no AAD verification)
        iv = base64.urlsafe_b64decode(iv_b64 + "==")
        ct = base64.urlsafe_b64decode(ct_b64 + "==")
        plaintext = _AES.new(cek, _AES.MODE_GCM, nonce=iv).decrypt(ct)

        # Payload is a JWK JSON — extract the raw key bytes
        jwk = json.loads(plaintext.decode("utf-8"))
        remainder = len(jwk["k"]) % 4
        padded = jwk["k"] + "=" * (4 - remainder if remainder else 0)
        return base64.urlsafe_b64decode(padded)

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
        host: Optional[str] = "android15.prod.cloud.netflix.com",
        language: Optional[str] = "en-US",
        device_model: Optional[str] = None,
    ) -> Dict[str, str]:
        """Build the HTTP headers required for Android MSL requests."""
        headers: Dict[str, str] = {
            "Host": host or "android15.prod.cloud.netflix.com",
            "Accept": "*/*",
            "User-Agent": user_agent or MSL_ANDROID.DEFAULT_USER_AGENT,
            "Accept-Language": language or "en-US",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Content-Encoding": "msl_v1",
            "X-DeviceModel": device_model or MSL_ANDROID.DEFAULT_DEVICE_MODEL,
            "x-netflix.client.request.name": request_name,
            "x-netflix.request.attempt": "1",
            "x-netflix.request.id": "".join(
                random.choice("0123456789abcdef") for _ in range(32)
            ),
            "x-netflix.request.client.context": MSL_ANDROID.DEFAULT_REQUEST_CONTEXT,
            "x-netflix.request.client.languages": "en-US",
            "x-netflix.request.client.timezoneid": "America/New_York",
            "x-netflix.clienttype": "samurai",
            "x-netflix.deviceformfactor": "PHONE",
            "x-netflix.devicememorylevel": "HIGH",
            "x-netflix.androidapi": "35",
            "x-netflix.context.os-version": "35",
            "x-netflix.context.form-factor": "phone",
            "x-netflix.context.ui-flavor": "android",
            "x-netflix.appver": "9.60.0",
            "x-netflix.context.app-version": "9.60.0",
            "x-netflix.esnprefix": "NFANDROID1-PRV-P-",
            "x-netflix.zuul.brotli.allowed": "true",
            "x-netflix.request.client.supportskidstop10": "true",
            "x-netflix.request.client.supportsgames": "true",
            "x-netflix.request.routing": '{"path":"\\/nq\\/android\\/playback\\/~1.0.0\\/router"}',
            "x-netflix.context.locales": "en-US",
            "x-netflix.context.android.installer-source": "com.android.vending",
        }
        if referer:
            headers["Referer"] = referer
        if viewable_id is not None:
            headers["x-netflix.playback.main-content-viewable-id"] = str(viewable_id)
        if profile_guid:
            headers["x-netflix.client.current-profile-guid"] = profile_guid
        if esn:
            headers["x-netflix.client.ftl.esn"] = esn
            headers["x-netflix.esn"] = esn
        if expiry_timeout is not None:
            headers["x-netflix.request.expiry.timeout"] = str(expiry_timeout)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    # -- Manifest defaults ---------------------------------------------------

    @staticmethod
    def manifest_request_defaults() -> Tuple[str, Dict[str, str]]:
        """Return the default manifest endpoint and query params for Android."""
        return MSL_ANDROID.DEFAULT_MANIFEST_ENDPOINT, dict(MSL_ANDROID.DEFAULT_MANIFEST_PARAMS)

    # -- Override send_message to add PBO normalisation ----------------------

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
        """Send an MSL message with PBO payload normalisation."""
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


__all__ = ["MSL_ANDROID", "MSLKeys"]
