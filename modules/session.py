from __future__ import annotations
import logging
import ssl
import certifi

_log = logging.getLogger(__name__)
import requests
import urllib3
from requests.adapters import HTTPAdapter
from typing import Any, Optional

# On Windows, pip._vendor.truststore monkey-patches ssl.SSLContext.wrap_socket to add
# a Windows trust store check AFTER Python's own TLS verification. Netflix's root CAs
# are in certifi but not always in the Windows cert store, so the Windows check fails.
# Patch _verify_peercerts (the truststore post-handshake hook) to a no-op so that
# only Python's built-in verification against the certifi CA bundle is used.
try:
    import pip._vendor.truststore._api as _ts_api
    _ts_api._verify_peercerts = lambda ssl_sock, server_hostname=None: None
except Exception:
    pass


class CertifiAdapter(HTTPAdapter):
    def __init__(self, ssl_context: Optional[ssl.SSLContext] = None, *args: Any, **kwargs: Any) -> None:
        self._ssl_context = ssl_context
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        if self._ssl_context is None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(cafile=certifi.where())
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            self._ssl_context = ctx
        else:
            ctx = self._ssl_context
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, conn: Any, url: str, verify: bool, cert: Optional[Any]) -> None:
        pass


def setup_session(
    verify_tls: bool = True,
    proxy: Optional[str] = None,
) -> requests.Session:
    _log.debug("Creating session (TLS verify=%s, proxy=%s)", verify_tls, proxy)
    session = requests.Session()
    if verify_tls:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.load_verify_locations(cafile=certifi.where())
        ssl_ctx.check_hostname = True
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        session.verify = certifi.where()
        session.mount("https://", CertifiAdapter(ssl_context=ssl_ctx))
    else:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
        _log.debug("Proxy configured: %s", proxy)
    session.headers.update({
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    })
    return session
