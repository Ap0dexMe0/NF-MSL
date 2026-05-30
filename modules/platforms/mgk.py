from __future__ import annotations
import json
import sys
from pathlib import Path
from typing import Optional
from modules.msl.mgk import MSL_MGK, UserAuthentication
from modules.helpers import (
    ensure_output_dir,
    save_session_cookies,
)
from modules.config import setup_config
from modules.logging import setup_logger
from modules.session import setup_session

config = setup_config()
EMAIL = config["NETFLIX"]["EMAIL"]
PASSWORD = config["NETFLIX"]["PASSWORD"]


def run_mgk(kpekph_path: Optional[str], esnid: str,
            new_msl: bool = False, no_verify: bool = False,
            proxy: Optional[str] = None):
    log = setup_logger('MGK MSL')

    OUTPUT_DIR = ensure_output_dir("mgk")
    MSL_CACHE_PATH = OUTPUT_DIR / "msl_keys_cache_mgk.json"
    AUTH_COOKIES_PATH = OUTPUT_DIR / "netflix_auth_cookies_mgk.json"

    DEVICE_TYPE = "NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019"

    # Resolve ESNID: auto-detect file path vs raw string
    esnid_path = Path(esnid)
    if esnid_path.is_file():
        ESN = MSL_MGK.load_esnid_file(esnid_path)
        log.info("Loaded ESNID from file: %s", esnid_path)
    else:
        ESN = esnid
        log.info("Using ESNID as raw string")

    # Resolve KpeKph: auto-detect file path vs raw string
    kpekph_file_path = None
    kpekph_raw = None
    if kpekph_path:
        kpekph_as_path = Path(kpekph_path)
        if kpekph_as_path.is_file():
            kpekph_file_path = str(kpekph_as_path)
            log.info("Loading KpeKph from file: %s", kpekph_as_path)
        else:
            kpekph_raw = kpekph_path
            log.info("Using KpeKph as raw string")

    session = setup_session(verify_tls=not no_verify, proxy=proxy)
    _proxy = {"http": proxy, "https": proxy} if proxy else None

    log.info("Starting MSL MGK handshake with ESN: %s", ESN)

    handshake_headers = MSL_MGK.build_request_headers(
        request_name="mintCookies",
        esn=ESN,
        expiry_timeout=12750,
    )

    msl_client = MSL_MGK.handshake(
        session=session,
        sender=ESN,
        kpekph_path=kpekph_file_path,
        kpekph_raw=kpekph_raw,
        msl_keys_path=str(MSL_CACHE_PATH),
        cookies=None,
        headers=handshake_headers,
        proxy=_proxy,
        new_msl=new_msl,
    )

    log.info("MGK handshake completed successfully")
    user_auth = UserAuthentication.EmailPassword(EMAIL, PASSWORD).__dict__

    manifest_endpoint, manifest_params = MSL_MGK.manifest_request_defaults()
    manifest_headers = MSL_MGK.build_request_headers(
        request_name="licensedManifest",
        esn=ESN,
        expiry_timeout=12750,
    )

    log.info("Sending authenticated MSL request with EMAIL_PASSWORD user auth")
    try:
        header, payload = msl_client.send_message(
            endpoint=manifest_endpoint,
            params=manifest_params,
            application_data={},
            userauthdata=user_auth,
            headers=manifest_headers,
        )
    except Exception:
        log.exception("MGK authenticated request failed")
        sys.exit(1)

    try:
        auth_cookies = save_session_cookies(session, AUTH_COOKIES_PATH, log)
    except Exception:
        sys.exit(1)

    result = {
        "auth_cookies": auth_cookies,
        "header": header,
        "payload": payload,
    }

    log.info("MGK login succeeded")
    print(json.dumps(result, indent=2, default=str))
