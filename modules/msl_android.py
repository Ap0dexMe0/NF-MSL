import base64
import gzip
import json
import random
import sys
import zlib
import jsonpickle
import requests
from io import BytesIO
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.PublicKey.RSA import RsaKey
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import Padding
from pywidevine import Cdm as WidevineCdm, Device as WidevineDevice, PSSH

class MSLObject:
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {jsonpickle.encode(self, unpicklable=False)}>"


class MSLKeys(MSLObject):
    def __init__(
        self,
        encryption: Optional[bytes] = None,
        sign: Optional[bytes] = None,
        rsa: Optional[RsaKey] = None,
        mastertoken: Optional[dict] = None,
        cdm_session: Any = None,
    ):
        self.encryption = encryption
        self.sign = sign
        self.rsa = rsa
        self.mastertoken = mastertoken
        self.cdm_session = cdm_session

class MSL_ANDROID:
    DEFAULT_HANDSHAKE_ENDPOINT = "https://android.prod.ftl.netflix.com/nq/androidui/pbo_license/~1.0.0/router"
    DEFAULT_MANIFEST_ENDPOINT = "https://android.prod.ftl.netflix.com/msl/playapi/android/manifest"
    DEFAULT_MANIFEST_PARAMS = {
        "ab_ui_ver": "android",
        "nrdapp_version": "18.26.0",
    }
    DEFAULT_USER_AGENT = "com.netflix.mediaclient/63988 (Linux; U; Android 15; en_US; SM-F711N; Build/AP3A.240905.015.A2; Cronet/143.0.7445.0)"
    DEFAULT_REQUEST_CONTEXT = '{"appState":"foreground","appView":"unknown"}'
    DEFAULT_NRDJS_VERSION = "v3.12.55"
    DEFAULT_NETJS_VERSION = "3.0.5"
    DEFAULT_PBO_VERSION = 2
    DEFAULT_PBO_COMMON = {
        "sdk": "18.26.0",
        "platform": "18.26.0",
        "application": "Netflix Android 18.26.0",
        "uiversion": "18.26.0",
        "uiPlatform": "android",
        "clientVersion": "18.26.0",
        "apkVersion": "18.26.0",
    }
    DEFAULT_PBO_LANGUAGES = ["en-US", "en"]
    DEFAULT_DEVICE_MODEL = "SM-F711N"

    def __init__(
        self,
        session: requests.Session,
        keys: MSLKeys,
        message_id: int,
        sender: str,
        user_auth: Optional[dict] = None,
        drm: str = "widevine",
    ):
        self.session = session
        self.keys = keys
        self.sender = sender
        self.user_auth = user_auth
        self.message_id = message_id
        self.drm = drm

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
        if cookies:
            session.cookies.update(cookies)

        cache_path = Path(msl_keys_path)
        msl_keys = MSL_ANDROID.load_cache_data(cache_path)
        if msl_keys is not None and not new_msl:
            return msl_keys

        if drm != "widevine":
            raise ValueError(f"Unsupported DRM mode: {drm}")

        if not cdm:
            raise ValueError("Widevine CDM is required for this iOS MSL flow")

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
                    MSL_ANDROID.generate_msg_header(
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
        res = session.post(url=handshake_endpoint, data=data, headers=handshake_headers, timeout=30)

        if res.status_code != 200:
            raise RuntimeError(f"Key exchange failed: HTTP {res.status_code} {res.text[:500]}")

        parsed = cls.parse_concatenated_json(res.text)
        if not parsed:
            raise RuntimeError("Key exchange failed: empty MSL response")

        key_exchange = parsed[0]

        if "errordata" in key_exchange:
            decoded_error = base64.standard_b64decode(key_exchange["errordata"]).decode("utf-8")
            error_json = json.loads(decoded_error)
            raise RuntimeError(f"Key exchange failed: {error_json}")

        if "headerdata" not in key_exchange:
            raise RuntimeError(f"Key exchange failed: missing headerdata in response: {str(key_exchange)[:500]}")

        header_json = json.loads(
            base64.standard_b64decode(key_exchange["headerdata"]).decode("utf-8")
        )
        key_response_data = header_json["keyresponsedata"]
        key_data = key_response_data["keydata"]

        cdm.parse_license(msl_keys.cdm_session, key_data["cdmkeyresponse"])
        keys = cdm.get_keys(msl_keys.cdm_session)
        msl_keys.encryption = MSL_ANDROID.get_widevine_key(
            kid=base64.standard_b64decode(key_data["encryptionkeyid"]),
            keys=keys,
            permissions=["AllowEncrypt", "AllowDecrypt"],
        )
        msl_keys.sign = MSL_ANDROID.get_widevine_key(
            kid=base64.standard_b64decode(key_data["hmackeyid"]),
            keys=keys,
            permissions=["AllowSign", "AllowSignatureVerify"],
        )

        msl_keys.mastertoken = key_response_data["mastertoken"]
        MSL_ANDROID.cache_keys(msl_keys, cache_path)
        return msl_keys

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
            "x-netflix.request.id": "".join(random.choice("0123456789abcdef") for _ in range(32)),
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

    @staticmethod
    def manifest_request_defaults() -> Tuple[str, Dict[str, str]]:
        return MSL_ANDROID.DEFAULT_MANIFEST_ENDPOINT, dict(MSL_ANDROID.DEFAULT_MANIFEST_PARAMS)

    @staticmethod
    def generate_msg_header(
        message_id: int,
        sender: str,
        is_handshake: bool,
        userauthdata: Optional[dict] = None,
        keyrequestdata: Optional[dict] = None,
        compression: Optional[str] = "GZIP",
    ) -> str:
        header_data: Dict[str, Any] = {
            "messageid": message_id,
            "renewable": True,
            "handshake": is_handshake,
            "capabilities": {
                "compressionalgos": [compression] if compression else [],
                "languages": ["en-US", "en"],
                "encoderformats": ["JSON"],
            },
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "sender": sender,
            "nonreplayable": False,
            "recipient": "Netflix",
        }
        if userauthdata:
            header_data["userauthdata"] = userauthdata
        if keyrequestdata:
            header_data["keyrequestdata"] = [keyrequestdata]
        return jsonpickle.encode(header_data, unpicklable=False)

    @staticmethod
    def get_widevine_key(kid: bytes, keys: List[Any], permissions: List[str]) -> Optional[bytes]:
        import re
        normalized_perms = {re.sub(r'(?<!^)(?=[A-Z])', '_', p).lower() for p in permissions}
        for key in keys:
            if key.type != "OPERATOR_SESSION":
                continue
            key_perms = {p.lower() for p in (getattr(key, "permissions", None) or [])}
            if normalized_perms <= key_perms:
                return key.key
        return None

    def send_message(
        self,
        endpoint: str,
        params: Dict[str, str],
        application_data: Dict[str, Any],
        userauthdata: Optional[dict] = None,
        headers: Optional[dict] = None,
        proxy: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, Any], Any]:
        normalized_application_data = self.normalize_application_data(endpoint, application_data)
        message = self.create_message(normalized_application_data, userauthdata)
        request_kwargs: Dict[str, Any] = {
            "url": endpoint,
            "data": message,
            "params": params,
            "headers": headers,
            "timeout": 30,
        }
        if proxy:
            request_kwargs["proxies"] = proxy

        res = self.session.post(**request_kwargs)

        if res.status_code != 200:
            raise RuntimeError(
                f"MSL request failed with HTTP {res.status_code}: {res.text[:500]}"
            )

        response_text = res.text or ""
        stripped_response = response_text.lstrip()
        if not stripped_response:
            raise RuntimeError("MSL request failed: empty response body")

        if not stripped_response.startswith("{"):
            content_type = res.headers.get("content-type", "")
            raise RuntimeError(
                "MSL request failed: the server did not return concatenated MSL JSON. "
                f"Content-Type: {content_type!r}. Body preview: {response_text[:500]!r}"
            )

        header, payload_data = self.parse_message(response_text)
        if not header:
            raise RuntimeError(
                f"MSL request failed: parsed response does not contain a header. Body preview: {response_text[:500]!r}"
            )

        if "errordata" in header:
            decoded_error = json.loads(
                base64.standard_b64decode(header["errordata"].encode("utf-8")).decode("utf-8")
            )
            raise RuntimeError(f"MSL response contains an error: {decoded_error}")

        return header, payload_data

    @classmethod
    def normalize_application_data(cls, endpoint: str, application_data: Any) -> Any:
        if not isinstance(application_data, dict):
            return application_data

        if cls._looks_like_wrapped_pbo_payload(application_data):
            return application_data

        route = cls._extract_pbo_route(application_data, endpoint)
        if route is None:
            return application_data

        common = dict(cls.DEFAULT_PBO_COMMON)
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
            if key in wrapped or key in {"version", "common", "languages", "params", "path", "method", "route", "endpoint"}:
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

    def create_message(self, application_data: Dict[str, Any], userauthdata: Optional[dict] = None) -> str:
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

    def decrypt_payload_chunks(self, payload_chunks: List[Dict[str, str]]) -> Any:
        raw_data = ""
        assert self.keys.encryption is not None

        for payload_chunk in payload_chunks:
            payload_chunk_json = json.loads(base64.standard_b64decode(payload_chunk["payload"]).decode("utf-8"))
            payload_decrypted = AES.new(
                key=self.keys.encryption,
                mode=AES.MODE_CBC,
                iv=base64.standard_b64decode(payload_chunk_json["iv"]),
            ).decrypt(base64.standard_b64decode(payload_chunk_json["ciphertext"]))
            payload_decrypted = Padding.unpad(payload_decrypted, 16)
            payload_decrypted_json = json.loads(payload_decrypted.decode("utf-8"))

            payload_data = base64.standard_b64decode(payload_decrypted_json["data"])
            if payload_decrypted_json.get("compressionalgo") == "GZIP":
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

    @staticmethod
    def parse_concatenated_json(message: str) -> List[Dict[str, Any]]:
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

    def parse_message(self, message: str) -> Tuple[Dict[str, Any], Any]:
        parsed_message = self.parse_concatenated_json(message)
        header = parsed_message[0]
        encrypted_payload_chunks = parsed_message[1:] if len(parsed_message) > 1 else []
        payload_chunks = self.decrypt_payload_chunks(encrypted_payload_chunks) if encrypted_payload_chunks else {}
        return header, payload_chunks

    @staticmethod
    def gzip_compress(data: bytes) -> bytes:
        out = BytesIO()
        with gzip.GzipFile(fileobj=out, mode="w") as gzip_file:
            gzip_file.write(data)
        return base64.standard_b64encode(out.getvalue())

    @staticmethod
    def base64key_decode(payload: str) -> bytes:
        length = len(payload) % 4
        if length == 2:
            payload += "=="
        elif length == 3:
            payload += "="
        elif length != 0:
            raise ValueError("Invalid base64 string")
        return base64.urlsafe_b64decode(payload.encode("utf-8"))

    def encrypt(self, plaintext: str) -> str:
        if not self.keys.encryption:
            raise ValueError("Encryption key is not available")
        if not self.keys.mastertoken:
            raise ValueError("Master token is not available")

        iv = get_random_bytes(16)
        tokendata = json.loads(base64.standard_b64decode(self.keys.mastertoken["tokendata"]).decode("utf-8"))
        return json.dumps(
            {
                "ciphertext": base64.standard_b64encode(
                    AES.new(self.keys.encryption, AES.MODE_CBC, iv).encrypt(
                        Padding.pad(plaintext.encode("utf-8"), 16)
                    )
                ).decode("utf-8"),
                "keyid": f"{self.sender}_{tokendata['sequencenumber']}",
                "sha256": "AA==",
                "iv": base64.standard_b64encode(iv).decode("utf-8"),
            }
        )

    def sign(self, text: str) -> bytes:
        if not self.keys.sign:
            raise ValueError("Sign key is not available")
        return base64.standard_b64encode(HMAC.new(self.keys.sign, text.encode("utf-8"), SHA256).digest())

    @staticmethod
    def load_cache_data(msl_keys_path: Optional[Path] = None) -> Optional[MSLKeys]:
        if not msl_keys_path or not msl_keys_path.is_file():
            return None

        msl_keys = jsonpickle.decode(msl_keys_path.read_text(encoding="utf-8"))
        if msl_keys.mastertoken:
            tokendata = json.loads(base64.standard_b64decode(msl_keys.mastertoken["tokendata"]).decode("utf-8"))
            renewal_window = datetime.fromtimestamp(int(tokendata["renewalwindow"]), tz=timezone.utc)
            remaining_hours = (renewal_window - datetime.now(timezone.utc)).total_seconds() / 3600
            if remaining_hours < 10:
                return None
        return msl_keys

    @staticmethod
    def cache_keys(msl_keys: MSLKeys, msl_keys_path: Path) -> None:
        with open(msl_keys_path, "w", encoding="utf-8") as cache_file:
            cache_file.write(jsonpickle.encode(msl_keys, indent=4))