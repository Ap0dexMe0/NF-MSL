from __future__ import annotations

import base64
import json
import logging
import random
from collections import OrderedDict

_log = logging.getLogger(__name__)
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import jsonpickle
import requests
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey.RSA import RsaKey

from .base import MSLBase, MSLKeys as _BaseMSLKeys


# ---------------------------------------------------------------------------
# Platform-specific key container
# ---------------------------------------------------------------------------

class MSLKeys(_BaseMSLKeys):
    """Web MSL keys – extends the base with an RSA key (no CDM session)."""

    def __init__(
        self,
        encryption: Optional[bytes] = None,
        sign: Optional[bytes] = None,
        rsa: Optional[RsaKey] = None,
        mastertoken: Optional[dict] = None,
    ) -> None:
        super().__init__(encryption=encryption, sign=sign, mastertoken=mastertoken)
        self.rsa = rsa


# ---------------------------------------------------------------------------
# MSL_WEB
# ---------------------------------------------------------------------------

class MSL_WEB(MSLBase):
    """Netflix MSL client for web browsers using RSA key exchange."""

    # -- Platform constants --------------------------------------------------
    DEFAULT_HANDSHAKE_ENDPOINT: str = (
        "https://www.netflix.com/nq/msl_v1/nrdjs/pbo_tokens/%5E1.0.0/router"
    )
    DEFAULT_USER_AGENT: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/146.0.0.0 Safari/537.36"
    )
    DEFAULT_REQUEST_CONTEXT: str = '{"appstate":"foreground"}'
    DEFAULT_NRDJS_VERSION: str = "v3.11.512"
    DEFAULT_NETJS_VERSION: str = "3.0.5"

    # -- Constructor ---------------------------------------------------------

    def __init__(
        self,
        session: requests.Session,
        keys: MSLKeys,
        message_id: int,
        sender: str,
        user_auth: Optional[dict] = None,
        proxy: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(session=session, keys=keys, message_id=message_id, sender=sender, proxy=proxy)
        self.user_auth = user_auth

    # -- RSA handshake -------------------------------------------------------

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
        """Perform an RSA (ASYMMETRIC_WRAPPED) key exchange."""
        _log.info("Web RSA handshake: sender=%s", sender)
        if cookies:
            session.cookies.update(cookies)

        cache_path = Path(msl_keys_path)
        cached = cls.load_cache_data(cache_path)
        if cached is not None and not new_msl:
            _log.info("Reusing cached MSL keys")
            return cached
        _log.info("Performing fresh RSA key exchange")

        message_id = random.randint(0, 2**52)
        keys = MSLKeys()
        keys.rsa = RSA.generate(2048)
        _log.debug("Generated RSA-2048 ephemeral keypair")

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

        _log.debug("Web handshake request → %s", endpoint or cls.DEFAULT_HANDSHAKE_ENDPOINT)
        response = session.post(
            url=endpoint or cls.DEFAULT_HANDSHAKE_ENDPOINT,
            data=envelope,
            headers=headers or cls.build_request_headers(request_name="aleProvision"),
            timeout=30,
        )
        _log.debug("Web handshake response ← HTTP %d", response.status_code)
        if response.status_code != 200:
            raise RuntimeError(
                f"Key exchange failed: HTTP {response.status_code} {response.text[:500]}"
            )

        parsed = cls.parse_concatenated_json(response.text)
        if not parsed:
            raise RuntimeError("Key exchange failed: empty MSL response")

        header = parsed[0]
        if "errordata" in header:
            decoded_error = base64.standard_b64decode(header["errordata"]).decode(
                "utf-8"
            )
            raise RuntimeError(f"Key exchange failed: {decoded_error}")
        if "headerdata" not in header:
            raise RuntimeError(
                f"Key exchange failed: missing headerdata: {str(header)[:500]}"
            )

        header_json = json.loads(
            base64.standard_b64decode(header["headerdata"]).decode("utf-8")
        )
        key_data = header_json["keyresponsedata"]["keydata"]

        cipher_rsa = PKCS1_OAEP.new(keys.rsa)
        keys.encryption = cls.base64key_decode(
            json.loads(
                cipher_rsa.decrypt(
                    base64.standard_b64decode(key_data["encryptionkey"])
                ).decode("utf-8")
            )["k"]
        )
        keys.sign = cls.base64key_decode(
            json.loads(
                cipher_rsa.decrypt(
                    base64.standard_b64decode(key_data["hmackey"])
                ).decode("utf-8")
            )["k"]
        )
        keys.mastertoken = header_json["keyresponsedata"]["mastertoken"]

        cls.cache_keys(keys, cache_path)
        _log.info("Web RSA key exchange complete")
        return keys

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
    ) -> Dict[str, str]:
        """Build the HTTP headers required for Web MSL requests."""
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

    # -- Custom generate_msg_header (empty languages / encoderformats) -------

    @staticmethod
    def generate_msg_header(
        message_id: int,
        sender: str,
        is_handshake: bool,
        userauthdata: Optional[dict] = None,
        keyrequestdata: Optional[dict] = None,
        compression: Optional[str] = "GZIP",
    ) -> str:
        """Generate an MSL message header with Web-specific capabilities.

        The Web platform sends empty ``languages`` and ``encoderformats``
        arrays in the capabilities block.
        """
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

    # -- Web-specific send_message (no PBO normalisation) --------------------

    def send_message(
        self,
        endpoint: str,
        params: Dict[str, str],
        application_data: Any,
        userauthdata: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, Any], Any]:
        """Send an MSL message without PBO payload normalisation.

        Raises :class:`RuntimeError` on MSL errors.
        """
        message = self.create_message(application_data, userauthdata)
        response = self.session.post(
            url=endpoint, params=params, data=message, headers=headers, timeout=30
        )
        response.raise_for_status()
        header, payload = self.parse_message(response.text)
        if "errordata" in header:
            decoded_error = json.loads(
                base64.standard_b64decode(header["errordata"]).decode("utf-8")
            )
            raise RuntimeError(f"MSL response contains an error: {decoded_error}")
        return header, payload

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

    # -- Cookie-jar helpers (Web-specific) -----------------------------------

    @staticmethod
    def cookiejar_to_list(cookie_jar: CookieJar) -> List[Dict[str, Any]]:
        """Serialise a :class:`CookieJar` to a list of dicts."""
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
        """Convert a :class:`CookieJar` to an :class:`OrderedDict` of name→value."""
        cookies: Dict[str, str] = OrderedDict()
        for cookie in cookie_jar:
            cookies[cookie.name] = cookie.value
        return cookies

    @staticmethod
    def save_cookie_values(
        cookie_jar: CookieJar, output_path: str | Path
    ) -> Dict[str, str]:
        """Save cookie name→value pairs to a JSON file and return them."""
        path = Path(output_path)
        payload = MSL_WEB.cookiejar_to_ordered_dict(cookie_jar)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    @staticmethod
    def save_cookiejar(cookie_jar: CookieJar, output_path: str | Path) -> None:
        """Save the full cookie jar to a JSON file."""
        path = Path(output_path)
        path.write_text(
            json.dumps(MSL_WEB.cookiejar_to_list(cookie_jar), indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def load_cookiejar(
        session: requests.Session,
        source: str | Path | Iterable[Dict[str, Any]] | Dict[str, str],
    ) -> None:
        """Load cookies into *session* from a file path, iterable, or dict."""
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


__all__ = ["MSL_WEB", "MSLKeys"]
