from __future__ import annotations
import base64
import gzip
import json
import random
import zlib
import jsonpickle
import requests
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from collections import OrderedDict
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey.RSA import RsaKey
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import Padding


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
    ):
        self.encryption = encryption
        self.sign = sign
        self.rsa = rsa
        self.mastertoken = mastertoken


class MSL_WEB:
    DEFAULT_HANDSHAKE_ENDPOINT = "https://www.netflix.com/nq/msl_v1/nrdjs/pbo_tokens/%5E1.0.0/router"
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/146.0.0.0 Safari/537.36"
    )
    DEFAULT_REQUEST_CONTEXT = '{"appstate":"foreground"}'
    DEFAULT_NRDJS_VERSION = "v3.11.512"
    DEFAULT_NETJS_VERSION = "3.0.5"

    def __init__(
        self,
        session: requests.Session,
        keys: MSLKeys,
        message_id: int,
        sender: str,
        user_auth: Optional[dict] = None,
    ):
        self.session = session
        self.keys = keys
        self.sender = sender
        self.user_auth = user_auth
        self.message_id = message_id

    @classmethod
    def handshake(
        cls,
        msl_keys_path: str | Path,
        session: requests.Session,
        sender: str,
        new_msl: bool = False,
        cookies: Optional[Dict[str, str]] = None,
        endpoint: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> MSLKeys:
        if cookies:
            session.cookies.update(cookies)

        cache_path = Path(msl_keys_path)
        cached = cls.load_cache_data(cache_path)
        if cached is not None and not new_msl:
            return cached

        message_id = random.randint(0, 2**52)
        keys = MSLKeys()
        keys.rsa = RSA.generate(2048)

        keyrequestdata = {
            "scheme": "ASYMMETRIC_WRAPPED",
            "keydata": {
                "keypairid": "rsaKeypairId",
                "mechanism": "JWK_RSA",
                "publickey": base64.b64encode(
                    keys.rsa.publickey().export_key(format="DER")
                ).decode("utf-8"),
            },
        }

        envelope = jsonpickle.encode(
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
        envelope += json.dumps(
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
            },
            separators=(",", ":"),
        )

        response = session.post(
            url=endpoint or cls.DEFAULT_HANDSHAKE_ENDPOINT,
            data=envelope,
            headers=headers or cls.build_request_headers(request_name="aleProvision"),
            timeout=30,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Key exchange failed: HTTP {response.status_code} {response.text[:500]}")

        parsed = cls.parse_concatenated_json(response.text)
        if not parsed:
            raise RuntimeError("Key exchange failed: empty MSL response")

        header = parsed[0]
        if "errordata" in header:
            decoded_error = base64.standard_b64decode(header["errordata"]).decode("utf-8")
            raise RuntimeError(f"Key exchange failed: {decoded_error}")
        if "headerdata" not in header:
            raise RuntimeError(f"Key exchange failed: missing headerdata: {str(header)[:500]}")

        header_json = json.loads(base64.standard_b64decode(header["headerdata"]).decode("utf-8"))
        key_data = header_json["keyresponsedata"]["keydata"]

        cipher_rsa = PKCS1_OAEP.new(keys.rsa)
        keys.encryption = cls.base64key_decode(
            json.loads(cipher_rsa.decrypt(base64.standard_b64decode(key_data["encryptionkey"])).decode("utf-8"))["k"]
        )
        keys.sign = cls.base64key_decode(
            json.loads(cipher_rsa.decrypt(base64.standard_b64decode(key_data["hmackey"])).decode("utf-8"))["k"]
        )
        keys.mastertoken = header_json["keyresponsedata"]["mastertoken"]

        cls.cache_keys(keys, cache_path)
        return keys

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
        headers: Dict[str, str] = {
            "User-Agent": user_agent or MSL_WEB.DEFAULT_USER_AGENT,
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Content-Encoding": "msl_v1",
            "Origin": "https://www.netflix.com",
            "X-Netflix.Client.Request.Name": request_name,
            "X-Netflix.request.attempt": "1",
            "X-Netflix.Request.NonJson.Headers": "true",
            "X-Netflix.Request.Client.Context": MSL_WEB.DEFAULT_REQUEST_CONTEXT,
            "x-netflix.client.nrdjs.version": MSL_WEB.DEFAULT_NRDJS_VERSION,
            "x-netflix.client.netjs.version": MSL_WEB.DEFAULT_NETJS_VERSION,
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
                "languages": [],
                "encoderformats": [],
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

    def send_message(
        self,
        endpoint: str,
        params: Dict[str, str],
        application_data: Any,
        userauthdata: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, Any], Any]:
        message = self.create_message(application_data, userauthdata)
        response = self.session.post(url=endpoint, params=params, data=message, headers=headers, timeout=30)
        response.raise_for_status()
        header, payload = self.parse_message(response.text)
        if "errordata" in header:
            decoded_error = json.loads(base64.standard_b64decode(header["errordata"]).decode("utf-8"))
            raise RuntimeError(f"MSL response contains an error: {decoded_error}")
        return header, payload

    def create_message(self, application_data: Any, userauthdata: Optional[dict] = None) -> str:
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

        compressed_data = self.gzip_compress(json.dumps(application_data, separators=(",", ":")).encode("utf-8")).decode("utf-8")
        payloads = [
            {
                "sequencenumber": 1,
                "messageid": self.message_id,
                "compressionalgo": "GZIP",
                "data": compressed_data,
            },
            {
                "sequencenumber": 2,
                "messageid": self.message_id,
                "endofmsg": True,
                "data": "",
            },
        ]

        for payload in payloads:
            encrypted_chunk = self.encrypt(json.dumps(payload, separators=(",", ":")))
            message += json.dumps(
                {
                    "payload": base64.standard_b64encode(encrypted_chunk.encode("utf-8")).decode("utf-8"),
                    "signature": self.sign(encrypted_chunk).decode("utf-8"),
                },
                separators=(",", ":"),
            )
        return message

    def parse_message(self, message: str) -> Tuple[Dict[str, Any], Any]:
        parsed = self.parse_concatenated_json(message)
        header = parsed[0]
        payload_chunks = parsed[1:] if len(parsed) > 1 else []
        payload = self.decrypt_payload_chunks(payload_chunks) if payload_chunks else {}
        return header, payload

    def decrypt_payload_chunks(self, payload_chunks: List[Dict[str, str]]) -> Any:
        if not self.keys.encryption:
            raise ValueError("Encryption key is not available")

        raw_data = ""
        for payload_chunk in payload_chunks:
            chunk_json = json.loads(base64.standard_b64decode(payload_chunk["payload"]).decode("utf-8"))
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

        data = json.loads(raw_data)
        if "error" in data:
            return None
        return data.get("result", data)

    def encrypt(self, plaintext: str) -> str:
        if not self.keys.encryption:
            raise ValueError("Encryption key is not available")
        if not self.keys.mastertoken:
            raise ValueError("Master token is not available")

        iv = get_random_bytes(16)
        tokendata = json.loads(base64.standard_b64decode(self.keys.mastertoken["tokendata"]).decode("utf-8"))
        ciphertext = AES.new(self.keys.encryption, AES.MODE_CBC, iv).encrypt(Padding.pad(plaintext.encode("utf-8"), 16))
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
        return base64.standard_b64encode(HMAC.new(self.keys.sign, text.encode("utf-8"), SHA256).digest())

    @staticmethod
    def parse_concatenated_json(message: str) -> List[Dict[str, Any]]:
        decoder = json.JSONDecoder()
        items: List[Dict[str, Any]] = []
        index = 0
        while index < len(message):
            while index < len(message) and message[index].isspace():
                index += 1
            if index >= len(message):
                break
            item, index = decoder.raw_decode(message, index)
            items.append(item)
        return items

    @staticmethod
    def gzip_compress(data: bytes) -> bytes:
        out = BytesIO()
        with gzip.GzipFile(fileobj=out, mode="w") as handle:
            handle.write(data)
        return base64.standard_b64encode(out.getvalue())

    @staticmethod
    def base64key_decode(payload: str) -> bytes:
        remainder = len(payload) % 4
        if remainder == 2:
            payload += "=="
        elif remainder == 3:
            payload += "="
        elif remainder != 0:
            raise ValueError("Invalid base64 string")
        return base64.urlsafe_b64decode(payload.encode("utf-8"))

    @staticmethod
    def load_cache_data(msl_keys_path: Optional[Path] = None) -> Optional[MSLKeys]:
        if not msl_keys_path or not msl_keys_path.is_file():
            return None

        msl_keys = jsonpickle.decode(msl_keys_path.read_text(encoding="utf-8"))
        if msl_keys.rsa:
            msl_keys.rsa = RSA.import_key(msl_keys.rsa)

        if msl_keys.mastertoken:
            tokendata = json.loads(base64.standard_b64decode(msl_keys.mastertoken["tokendata"]).decode("utf-8"))
            renewal_window = datetime.fromtimestamp(int(tokendata["renewalwindow"]), tz=timezone.utc)
            if (renewal_window - datetime.now(timezone.utc)).total_seconds() / 3600 < 10:
                return None
        return msl_keys

    @staticmethod
    def cache_keys(msl_keys: MSLKeys, msl_keys_path: Path) -> None:
        original_rsa = msl_keys.rsa
        if msl_keys.rsa:
            msl_keys.rsa = msl_keys.rsa.export_key()
        msl_keys_path.write_text(jsonpickle.encode(msl_keys, indent=4), encoding="utf-8")
        if original_rsa:
            msl_keys.rsa = original_rsa

    @staticmethod
    def cookiejar_to_list(cookie_jar: CookieJar) -> List[Dict[str, Any]]:
        cookies: List[Dict[str, Any]] = []
        for cookie in cookie_jar:
            cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": bool(cookie.secure),
                    "expires": cookie.expires,
                    "discard": bool(cookie.discard),
                    "rest": dict(cookie._rest),
                }
            )
        return cookies

    @staticmethod
    def cookiejar_to_ordered_dict(cookie_jar: CookieJar) -> Dict[str, str]:
        cookies: Dict[str, str] = OrderedDict()
        for cookie in cookie_jar:
            cookies[cookie.name] = cookie.value
        return cookies

    @staticmethod
    def save_cookie_values(cookie_jar: CookieJar, output_path: str | Path) -> Dict[str, str]:
        path = Path(output_path)
        payload = MSL_WEB.cookiejar_to_ordered_dict(cookie_jar)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    @staticmethod
    def save_cookiejar(cookie_jar: CookieJar, output_path: str | Path) -> None:
        path = Path(output_path)
        path.write_text(json.dumps(MSL_WEB.cookiejar_to_list(cookie_jar), indent=2), encoding="utf-8")

    @staticmethod
    def load_cookiejar(session: requests.Session, source: str | Path | Iterable[Dict[str, Any]] | Dict[str, str]) -> None:
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.is_file():
                return
            payload = json.loads(path.read_text(encoding="utf-8"))
        else:
            payload = source

        if isinstance(payload, dict):
            session.cookies.update(payload)
            return

        for item in payload:
            session.cookies.set(
                name=item["name"],
                value=item["value"],
                domain=item.get("domain"),
                path=item.get("path", "/"),
                secure=item.get("secure", False),
                expires=item.get("expires"),
                rest=item.get("rest", {}),
            )