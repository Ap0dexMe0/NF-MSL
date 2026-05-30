from __future__ import annotations
import json
import random
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import quote
from pywidevine import Cdm as WidevineCdm, Device as WidevineDevice
from modules.msl.android import MSL_ANDROID
from modules.helpers import (
    ensure_output_dir, restore_auth_cookies, get_nfvdid, get_flow_session_cookies,
    save_session_cookies,
    generate_netflix_uuid, generate_request_id, generate_esn_random_suffix,
    decrypt_msl_header, extract_clcs_session_id, extract_rendition_id,
)
from modules.config import setup_config
from modules.logging import setup_logger
from modules.session import setup_session

config = setup_config()
EMAIL = config["NETFLIX"]["EMAIL"]
PASSWORD = config["NETFLIX"]["PASSWORD"]


def run_android(wvd_path: Path,
                new_msl: bool = False, no_verify: bool = False,
                proxy: Optional[str] = None):
    log = setup_logger('ANDROID MSL')
    OUTPUT_DIR = ensure_output_dir("android")

    NETFLIX_HOME_URL = "https://www.netflix.com/"
    NETFLIX_CANONICAL_URL = "https://netflix.com/"
    LOGIN_URL = "https://www.netflix.com/login"
    APPBOOT_URL = "https://android15.appboot.netflix.com/appboot/NFANDROID1-PRV-P-"
    MSL_HANDSHAKE_ENDPOINT = "https://android.prod.ftl.netflix.com/nq/androidui/pbo_license/~1.0.0/router"
    VERIFY_LOGIN_URL = "https://android.prod.ftl.netflix.com/nq/androidui/samurai/v1/config"

    USER_AGENT = "com.netflix.mediaclient/63988 (Linux; U; Android 15; en_US; SM-F711N; Build/AP3A.240905.015.A2; Cronet/143.0.7445.0)"
    CLIENT_VERSION = "18.26.0"
    APP_VERSION = "9.60.0"
    HAWKINS_VERSION = "5.15.0"
    UI_FLAVOR = "android"
    OS_VERSION = "35"
    FORM_FACTOR = "phone"
    FEATURE_CAPABILITIES = "supportsStudioBranding"
    LOCALE = "en-US"
    DEVICE_MODEL = "SM-F711N"

    VERIFY_TLS = not no_verify
    RESTORE_AUTH_COOKIES = False

    if not wvd_path.exists():
        raise FileNotFoundError(f"Missing WVD file: {wvd_path}")
    widevine_device = WidevineDevice.load(wvd_path)
    cdm = WidevineCdm.from_device(widevine_device)
    _sid = widevine_device.system_id
    MSL_CACHE_PATH = OUTPUT_DIR / f"msl_keys_cache_android_{_sid}.json"
    AUTH_COOKIES_PATH = OUTPUT_DIR / f"netflix_auth_cookies_{_sid}.json"
    USERIDTOKEN_PATH = OUTPUT_DIR / f"netflix_auth_useridtoken_{_sid}.json"
    TOKENS_OUTPUT_PATH = OUTPUT_DIR / f"netflix_auth_tokens_{_sid}.json"

    ESN = f"NFANDROID1-PRV-P-SAMSUSM-F711N-{_sid}-{generate_esn_random_suffix(64)}"
    log.info("ESN: %s", ESN)

    REQUEST_CLIENT_CONTEXT_UNKNOWN = '{"appView":"unknown","appState":"foreground"}'
    APPBOOT_REQUEST_CLIENT_CONTEXT = '{"appView":"unknown","appState":"foreground"}'

    session = setup_session(verify_tls=VERIFY_TLS, proxy=proxy)
    _proxy = {"http": proxy, "https": proxy} if proxy else None

    if RESTORE_AUTH_COOKIES:
        restore_auth_cookies(session, AUTH_COOKIES_PATH, log)

    log.info("Initializing session")
    response = session.get(NETFLIX_CANONICAL_URL, timeout=30, allow_redirects=True)
    response.raise_for_status()

    response = session.get(NETFLIX_HOME_URL, timeout=30)
    response.raise_for_status()

    log.info("Requesting initial nfvdid cookie")
    appboot_headers = {
        "Host": "android15.appboot.netflix.com",
        "Connection": "keep-alive",
        "X-Netflix.Request.Client.Context": APPBOOT_REQUEST_CLIENT_CONTEXT,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "gzip, deflate, br",
    }

    response = session.post(
        APPBOOT_URL,
        params={"keyVersion": "1"},
        headers=appboot_headers,
        timeout=30,
    )

    nfvdid = get_nfvdid(session, response)

    log.info("Initial nfvdid cookie obtained")

    log.info("Starting MSL Widevine exchange")

    msl_headers = MSL_ANDROID.build_request_headers(
        request_name="getProxyEsn",
        user_agent=USER_AGENT,
        referer=None,
        esn=ESN,
        expiry_timeout=12750,
        host="android15.prod.cloud.netflix.com",
        language="en-US,en",
        device_model=quote(DEVICE_MODEL, safe=""),
        extra_headers={
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Encoding": "msl_v1",
            "x-netflix.zuul.brotli.allowed": "true",
            "x-netflix.appver": APP_VERSION,
            "x-netflix.clienttype": "samurai",
            "x-netflix.request.client.context": REQUEST_CLIENT_CONTEXT_UNKNOWN,
            "x-netflix.esnprefix": "NFANDROID1-PRV-P-",
            "x-netflix.request.uuid": (
                generate_netflix_uuid()
            ),
            "x-netflix.androidapi": "35",
            "x-netflix.deviceformfactor": "PHONE",
            "x-netflix.devicememorylevel": "HIGH",
            "x-netflix.request.attempt": "1",
            "x-netflix.request.id": generate_request_id(),
            "Content-Type": "application/json",
            "x-netflix.client.request.name": "getProxyEsn",
            "x-netflix.request.routing": '{"path":"\\/nq\\/android\\/playback\\/~1.0.0\\/router"}',
            "user-agent": USER_AGENT,
        },
    )

    handshake_cookies = {
        "nfvdid": nfvdid,
    }

    msl_keys = MSL_ANDROID.handshake(
        msl_keys_path=str(MSL_CACHE_PATH),
        session=session,
        sender=ESN,
        cdm=cdm,
        cdm_device=str(wvd_path),
        new_msl=False,
        cookies=handshake_cookies,
        drm="widevine",
        endpoint=MSL_HANDSHAKE_ENDPOINT,
        headers=msl_headers,
    )

    msl_client = MSL_ANDROID(
        session=session,
        keys=msl_keys,
        message_id=random.randint(0, 2**52),
        sender=ESN,
        drm="widevine",
        proxy=_proxy,
    )

    nfvdid, flow_session_id = get_flow_session_cookies(session)

    log.info("MSL Widevine exchange completed")

    log.info("Loading login page")
    response = session.get(LOGIN_URL, timeout=30)
    response.raise_for_status()
    login_html = response.text

    cookie_dict = session.cookies.get_dict()
    flow_session_id = cookie_dict.get("flwssn", flow_session_id)
    if not flow_session_id:
        raise RuntimeError("The flwssn flow session cookie is missing")

    log.info("Submitting VerifyLoginMslRequest")

    confirm_login_query = {
        "api": "33",
        "appType": "samurai",
        "appVer": "62902",
        "appVersion": "9.18.0",
        "chipset": "sm8150",
        "chipsetHardware": "qcom",
        "clientAppState": "FOREGROUND",
        "clientAppVersionState": "NORMAL",
        "countryIsoCode": "US",
        "ctgr": "phone",
        "dbg": "false",
        "deviceLocale": "en-US",
        "devmod": f"samsung_{DEVICE_MODEL}",
        "ffbc": "phone",
        "flwssn": flow_session_id,
        "installType": "regular",
        "isAutomation": "false",
        "isConsumptionOnly": "true",
        "isNetflixPreloaded": "false",
        "isPlayBillingEnabled": "true",
        "isStubInSystemPartition": "false",
        "lackLocale": "false",
        "landingOrigin": "https://www.netflix.com",
        "mId": "SAMSUSM-F711N",
        "memLevel": "HIGH",
        "method": "get",
        "mnf": "samsung",
        "model": DEVICE_MODEL,
        "netflixClientPlatform": "androidNative",
        "netflixId": cookie_dict.get("NetflixId", ""),
        "networkType": "wifi",
        "osBoard": "kona",
        "osDevice": "bloom",
        "osDisplay": "RP1A.200720.012",
        "password": PASSWORD,
        "path": '["signInVerify"]',
        "pathFormat": "hierarchical",
        "platform": "android",
        "preloadSignupRoValue": "",
        "progressive": "false",
        "qlty": "hd",
        "recaptchaResponseTime": 445,
        "recaptchaResponseToken": "",
        "responseFormat": "json",
        "roBspVer": "RP1A.200720.012",
        "secureNetflixId": cookie_dict.get("SecureNetflixId", ""),
        "sid": "7176",
        "store": "google",
        "userLoginId": EMAIL,
    }

    confirm_login_headers = {
        "X-Netflix.Request.NqTracking": "VerifyLoginMslRequest",
        "X-Netflix.Client.Request.Name": "VerifyLoginMslRequest",
        "X-Netflix.Request.Client.Context": '{"appState":"foreground"}',
        "X-Netflix-Esn": ESN,
        "X-Netflix.EsnPrefix": "NFANDROID1-PRV-P-",
        "X-Netflix.msl-header-friendly-client": "true",
        "content-encoding": "msl_v1",
    }

    _THROTTLE_RETRIES = 3
    _THROTTLE_WAIT = 60
    _clcs_attempted = False

    for _attempt in range(1, _THROTTLE_RETRIES + 2):  # +1 slot for the CLCS retry
        try:
            confirm_login_header, confirm_login_payload_chunks = msl_client.send_message(endpoint=VERIFY_LOGIN_URL,
                                                                                         params=confirm_login_query,
                                                                                         application_data={},
                                                                                         headers=confirm_login_headers)
        except Exception:
            log.error("VerifyLoginMslRequest failed")
            log.debug("Request URL: %s", VERIFY_LOGIN_URL)
            log.debug("Request params: %s", json.dumps(confirm_login_query, indent=2))
            log.debug("Request headers: %s", json.dumps(confirm_login_headers, indent=2))
            log.debug("Session cookies: %s", json.dumps(session.cookies.get_dict(), indent=2))
            log.exception("Exception occurred")
            sys.exit(1)

        _error_code = None
        if (
            isinstance(confirm_login_payload_chunks, dict)
            and "errorCode" in confirm_login_payload_chunks.get("jsonGraph", {}).get("signInVerify", {}).get("value", {}).get("fields", {})
        ):
            _error_code = (
                confirm_login_payload_chunks.get("jsonGraph", {})
                .get("signInVerify", {})
                .get("value", {})
                .get("fields", {})
                .get("errorCode", {})
                .get("value")
            )

        if _error_code == "throttling_failure" and _attempt < _THROTTLE_RETRIES:
            log.warning("Throttled by Netflix (attempt %d/%d), retrying in %ds...", _attempt, _THROTTLE_RETRIES, _THROTTLE_WAIT)
            time.sleep(_THROTTLE_WAIT)
            continue

        elif _error_code == "incorrect_password" and not _clcs_attempted:
            # Samurai rejected credentials without auth cookies — fall back to CLCS
            # web login to obtain NetflixId/SecureNetflixId, then retry once.
            log.warning("incorrect_password — falling back to CLCS web login")
            clcs_session_id = extract_clcs_session_id(login_html)
            rendition_id = extract_rendition_id(login_html)
            if not clcs_session_id or not rendition_id:
                log.error("Cannot extract CLCS session IDs from login page for fallback")
                sys.exit(1)
            clcs_resp = session.post(
                "https://web.prod.cloud.netflix.com/graphql",
                json={
                    "operationName": "CLCSScreenUpdate",
                    "variables": {
                        "format": "HTML",
                        "imageFormat": "PNG",
                        "locale": "en-US",
                        "serverState": json.dumps({
                            "realm": "growth",
                            "name": "PASSWORD_LOGIN",
                            "clcsSessionId": clcs_session_id,
                            "sessionContext": {
                                "session-breadcrumbs": {"funnel_name": "loginWeb"},
                                "login.navigationSettings": {"hideOtpToggle": True},
                            },
                        }, separators=(",", ":")),
                        "serverScreenUpdate": json.dumps({
                            "realm": "custom",
                            "name": "growthLoginByPassword",
                            "metadata": {"recaptchaSiteKey": "6Lf8hrcUAAAAAIpQAFW2VFjtiYnThOjZOA5xvLyR"},
                            "loggingAction": "Submitted",
                            "loggingCommand": "SubmitCommand",
                            "referrerRenditionId": rendition_id,
                        }, separators=(",", ":")),
                        "inputFields": [
                            {"name": "password",              "value": {"stringValue": PASSWORD}},
                            {"name": "userLoginId",            "value": {"stringValue": EMAIL}},
                            {"name": "countryCode",            "value": {"stringValue": "1"}},
                            {"name": "countryIsoCode",         "value": {"stringValue": "US"}},
                            {"name": "recaptchaResponseTime",  "value": {"intValue": 445}},
                            {"name": "recaptchaResponseToken", "value": {"stringValue": ""}},
                        ],
                    },
                    "extensions": {"persistedQuery": {"id": "1c276cdf-caef-49cf-b38e-384972c2b47e", "version": 102}},
                },
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": "https://www.netflix.com",
                    "Referer": LOGIN_URL,
                },
                timeout=30,
            )
            if "errors" in clcs_resp.json():
                log.error("CLCS fallback login failed: %s", clcs_resp.json().get("errors"))
                sys.exit(1)
            session.get("https://www.netflix.com/browse", timeout=30)
            _fresh = session.cookies.get_dict()
            confirm_login_query["netflixId"] = _fresh.get("NetflixId", "")
            confirm_login_query["secureNetflixId"] = _fresh.get("SecureNetflixId", "")
            confirm_login_query["flwssn"] = _fresh.get("flwssn", flow_session_id)
            _clcs_attempted = True
            log.info("CLCS fallback complete, retrying VerifyLoginMslRequest")
            continue

        elif _error_code:
            log.error("Login errorCode: %s", _error_code)
            sys.exit(1)
        break

    if "headerdata" not in confirm_login_header:
        log.critical("Missing 'headerdata' in MSL response")
        sys.exit(1)

    try:
        header_data = decrypt_msl_header(confirm_login_header["headerdata"], msl_client.keys.encryption, msl_client.keys.sign)
    except Exception:
        log.exception("Failed to decrypt MSL header")
        sys.exit(1)

    tokens = header_data.get("useridtoken")
    if not tokens:
        log.error("Authentication failed: invalid ESN, email, or password")
        sys.exit(1)

    try:
        TOKENS_OUTPUT_PATH.write_text(json.dumps(header_data, indent=4), encoding="utf-8")
        USERIDTOKEN_PATH.write_text(json.dumps(tokens, indent=2), encoding="utf-8")
        log.info("User ID token data saved to: %s", TOKENS_OUTPUT_PATH)
        log.info("User ID token saved to: %s", USERIDTOKEN_PATH)
    except Exception:
        log.exception("Failed to save token files")
        sys.exit(1)

    try:
        auth_cookies = save_session_cookies(session, AUTH_COOKIES_PATH, log)
    except Exception:
        sys.exit(1)

    result = {
        "useridtoken": tokens,
        "auth_cookies": auth_cookies,
        "header_data": header_data,
    }

    log.info("VerifyLoginMslRequest succeeded")
    # print(json.dumps(result, indent=2))
