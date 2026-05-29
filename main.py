from __future__ import annotations
import argparse, os, base64, gzip, json, logging, random, re, sys, time, uuid, zlib, requests, urllib3
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pywidevine import Cdm as WidevineCdm, Device as WidevineDevice
from modules.msl_android import MSL_ANDROID
from modules.msl_ios import MSL_IOS
from modules.msl_tv import MSL_TV
from modules.msl_web import MSL_WEB
from modules.msl_mgk import MSL_MGK
from modules.helpers import (
    ensure_output_dir, restore_auth_cookies, get_nfvdid, get_flow_session_cookies,
    save_session_cookies, build_cookie_header, apply_set_cookie_headers,
    dedupe_important_cookies, collect_important_cookies, generate_hex_id,
    generate_netflix_uuid, generate_request_id, generate_esn_random_suffix,
    decrypt_msl_header, extract_clcs_session_id, extract_rendition_id,
    parse_flow_data, parse_msl_payload, extract_useridtoken_from_payload,
    build_msl_trace_event, extract_key_id_from_mastertoken, request_args_to_dict,
)
from modules.config import setup_config

logging.basicConfig(level=logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("MSL HANDSHAKE")

config = setup_config()
EMAIL = config["NETFLIX"]["EMAIL"]
PASSWORD = config["NETFLIX"]["PASSWORD"]

def setup_session(verify_tls: bool = True) -> requests.Session:
    session = requests.Session()
    session.verify = verify_tls
    session.headers.update({
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    })
    return session

# ======================================================================
# ANDROID
# ======================================================================

def run_android_rsa(new_msl: bool = False, no_verify: bool = False):
    logger = logging.getLogger('ANDROID MSL RSA')
    output_dir = ensure_output_dir("android")
    msl_cache_path = output_dir / "msl_keys_cache_android_rsa.json"
    auth_cookies_path = output_dir / "netflix_auth_cookies_rsa.json"
    useridtoken_path = output_dir / "netflix_auth_useridtoken_rsa.json"
    tokens_output_path = output_dir / "netflix_auth_tokens_rsa.json"

    # NFCDCH-02-* ESN is accepted by the Android FTL endpoint without a WVD
    esn = f"NFCDCH-02-{''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))}"
    user_agent = f"com.netflix.mediaclient/63988 (Linux; U; Android 15; en_US; SM-F711N; Build/AP3A.240905.015.A2; Cronet/143.0.7445.0)"
    device_model = "SM-F711N"

    session = setup_session(verify_tls=True)

    response = session.post(
        "https://android15.appboot.netflix.com/appboot/NFANDROID1-PRV-P-",
        params={"keyVersion": "1"},
        headers={
            "Host": "android15.appboot.netflix.com",
            "X-Netflix.Request.Client.Context": '{"appView":"unknown","appState":"foreground"}',
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": user_agent,
            "Accept-Encoding": "gzip, deflate, br",
        },
        timeout=30,
    )
    nfvdid = get_nfvdid(session, response)
    logger.info("Initial nfvdid cookie obtained")

    msl_headers = MSL_ANDROID.build_request_headers(
        request_name="getProxyEsn",
        user_agent=user_agent,
        referer=None,
        esn=esn,
        expiry_timeout=12750,
        host="android15.prod.cloud.netflix.com",
        language="en-US,en",
        device_model=quote(device_model, safe=""),
        extra_headers={
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Encoding": "msl_v1",
            "x-netflix.zuul.brotli.allowed": "true",
            "x-netflix.appver": "9.60.0",
            "x-netflix.clienttype": "samurai",
            "x-netflix.request.client.context": '{"appView":"unknown","appState":"foreground"}',
            "x-netflix.esnprefix": "NFANDROID1-PRV-P-",
            "x-netflix.request.uuid": f"{generate_hex_id(8)}-{generate_hex_id(4)}-{generate_hex_id(4)}-{generate_hex_id(4)}-{generate_hex_id(12)}",
            "x-netflix.androidapi": "35",
            "x-netflix.deviceformfactor": "PHONE",
            "x-netflix.devicememorylevel": "HIGH",
            "x-netflix.request.attempt": "1",
            "x-netflix.request.id": generate_hex_id(32),
            "Content-Type": "application/json",
            "x-netflix.client.request.name": "getProxyEsn",
            "x-netflix.request.routing": '{"path":"\\/nq\\/android\\/playback\\/~1.0.0\\/router"}',
            "user-agent": user_agent,
        },
    )

    logger.info("Performing RSA/ASYMMETRIC_WRAPPED MSL handshake (no WVD needed)")
    msl_keys = MSL_ANDROID.rsa_handshake(
        msl_keys_path=str(msl_cache_path),
        session=session,
        sender=esn,
        new_msl=new_msl,
        cookies={"nfvdid": nfvdid},
        endpoint="https://android.prod.ftl.netflix.com/nq/androidui/pbo_license/~1.0.0/router",
        headers=msl_headers,
    )

    msl_client = MSL_ANDROID(
        session=session,
        keys=msl_keys,
        message_id=random.randint(0, 2**52),
        sender=esn,
        drm="widevine",
    )

    logger.info("MSL RSA key exchange completed")

    # The NFCDCH-02-* ESN triggers the web CLCS auth flow (not samurai useridtoken).
    # After the MSL handshake the HTTP session carries Netflix cookies, so we use
    # the same CLCSScreenUpdate GraphQL path that run_web() uses.
    logger.info("Fetching login page and extracting CLCS session context")
    login_response = session.get("https://www.netflix.com/login", timeout=30)
    login_html = login_response.text

    clcs_session_id = None
    rendition_id = None
    patterns = [
        r'clcsSessionId[\\"\'": ]+([0-9a-f\-]{36})',
        r'(?<!clcs)renditionId[\\"\'": ]+([0-9a-f\-]{36})',
    ]
    for pattern in patterns:
        match = re.search(pattern, login_html)
        if match:
            if not clcs_session_id:
                clcs_session_id = match.group(1)
            elif not rendition_id:
                rendition_id = match.group(1)

    if not clcs_session_id or not rendition_id:
        logger.error("Could not extract CLCS session IDs from login page")
        sys.exit(1)

    logger.info("Submitting credentials via CLCSScreenUpdate (web flow)")

    full_variables = {
        "format": "HTML", "imageFormat": "PNG", "locale": "en-US",
        "serverState": json.dumps({
            "realm": "growth", "name": "PASSWORD_LOGIN",
            "clcsSessionId": clcs_session_id,
            "sessionContext": {
                "session-breadcrumbs": {"funnel_name": "loginWeb"},
                "login.navigationSettings": {"hideOtpToggle": True},
            },
        }, separators=(",", ":")),
        "serverScreenUpdate": json.dumps({
            "realm": "custom", "name": "growthLoginByPassword",
            "metadata": {"recaptchaSiteKey": "6Lf8hrcUAAAAAIpQAFW2VFjtiYnThOjZOA5xvLyR"},
            "loggingAction": "Submitted", "loggingCommand": "SubmitCommand",
            "referrerRenditionId": rendition_id,
        }, separators=(",", ":")),
        "inputFields": [
            {"name": "password", "value": {"stringValue": PASSWORD}},
            {"name": "userLoginId", "value": {"stringValue": EMAIL}},
            {"name": "countryCode", "value": {"stringValue": "1"}},
            {"name": "countryIsoCode", "value": {"stringValue": "US"}},
            {"name": "recaptchaResponseTime", "value": {"intValue": 445}},
            {"name": "recaptchaResponseToken", "value": {"stringValue": ""}},
        ],
    }

    response = session.post(
        "https://web.prod.cloud.netflix.com/graphql",
        json={
            "operationName": "CLCSScreenUpdate",
            "variables": full_variables,
            "extensions": {"persistedQuery": {"id": "1c276cdf-caef-49cf-b38e-384972c2b47e", "version": 102}},
        },
        headers={
            "User-Agent": user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://www.netflix.com",
            "Referer": "https://www.netflix.com/login",
        },
        timeout=30,
    )
    login_resp_json = response.json()
    if "errors" in login_resp_json:
        logger.error("CLCSScreenUpdate failed: %s", login_resp_json["errors"])
        sys.exit(1)

    # Check login result
    data = login_resp_json.get("data", {})
    result_block = data.get("result", {}) if isinstance(data, dict) else {}
    status = result_block.get("status") if isinstance(result_block, dict) else None

    # Finalise the session
    session.get("https://www.netflix.com/browse", timeout=30)

    auth_cookies = {cookie.name: cookie.value for cookie in session.cookies}
    auth_cookies_path.write_text(json.dumps(auth_cookies, indent=2), encoding="utf-8")
    logger.info("Authentication cookies saved")

    has_netflix_id = "NetflixId" in auth_cookies
    if status == "SUCCESS" or has_netflix_id:
        logger.info("LOGIN SUCCESSFUL")
        tokens_output_path.write_text(json.dumps(login_resp_json, indent=4), encoding="utf-8")
        result = {"status": "SUCCESS", "auth_cookies": auth_cookies}
        # print(json.dumps(result, indent=2))
    else:
        logger.error("LOGIN FAILED — status=%s cookies=%s", status, list(auth_cookies.keys()))
        sys.exit(1)
        
def run_android(wvd_path: Path,
                new_msl: bool = False, no_verify: bool = False):
    log = logging.getLogger('ANDROID MSL')
    OUTPUT_DIR = ensure_output_dir("android")
    MSL_CACHE_PATH = OUTPUT_DIR / "msl_keys_cache_android.json"
    AUTH_COOKIES_PATH = OUTPUT_DIR / "netflix_auth_cookies.json"
    USERIDTOKEN_PATH = OUTPUT_DIR / "netflix_auth_useridtoken.json"
    TOKENS_OUTPUT_PATH = OUTPUT_DIR / "netflix_auth_tokens.json"

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

    VERIFY_TLS = True
    RESTORE_AUTH_COOKIES = False

    ESN = f"NFANDROID1-PRV-P-SAMSUSM-F711N-22594-{generate_esn_random_suffix(64)}"

    REQUEST_CLIENT_CONTEXT_UNKNOWN = '{"appView":"unknown","appState":"foreground"}'
    APPBOOT_REQUEST_CLIENT_CONTEXT = '{"appView":"unknown","appState":"foreground"}'

    session = requests.Session()
    session.verify = VERIFY_TLS
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        }
    )

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

    if not wvd_path.exists():
        raise FileNotFoundError(f"Missing WVD file: {wvd_path}")

    widevine_device = WidevineDevice.load(wvd_path)
    cdm = WidevineCdm.from_device(widevine_device)

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
    )

    nfvdid, flow_session_id = get_flow_session_cookies(session)

    log.info("MSL Widevine exchange completed")

    log.info("Loading login page to collect session cookies")
    response = session.get(LOGIN_URL, timeout=30)
    response.raise_for_status()

    cookie_dict = session.cookies.get_dict()
    flow_session_id = cookie_dict.get("flwssn", flow_session_id)

    if not flow_session_id:
        raise RuntimeError("The flwssn flow session cookie is missing before VerifyLoginMslRequest")

    if "NetflixId" not in cookie_dict or "SecureNetflixId" not in cookie_dict:
        log.warning("NetflixId or SecureNetflixId cookie is missing before VerifyLoginMslRequest")

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

    if (
        isinstance(confirm_login_payload_chunks, dict)
        and "errorCode" in confirm_login_payload_chunks.get("jsonGraph", {}).get("signInVerify", {}).get("value", {}).get("fields", {})
    ):
        error_code = (
            confirm_login_payload_chunks.get("jsonGraph", {})
            .get("signInVerify", {})
            .get("value", {})
            .get("fields", {})
            .get("errorCode", {})
            .get("value")
        )
        log.error("Login errorCode: %s", error_code)
        sys.exit(1)

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


# ======================================================================
# iOS
# ======================================================================

def run_ios(wvd_path: Path,
            new_msl: bool = False, no_verify: bool = False):
    log = logging.getLogger('IOS MSL')

    OUTPUT_DIR = ensure_output_dir("ios")
    MSL_CACHE_PATH = OUTPUT_DIR / "msl_keys_cache_ios.json"
    AUTH_COOKIES_PATH = OUTPUT_DIR / "netflix_auth_cookies.json"

    NETFLIX_HOME_URL = "https://www.netflix.com/"
    NETFLIX_CANONICAL_URL = "https://netflix.com/"
    GRAPHQL_URL = "https://ios.prod.cloud.netflix.com/graphql"
    LOGIN_URL = "https://www.netflix.com/login"
    BROWSE_URL = "https://www.netflix.com/browse"
    APPBOOT_URL = "https://ios18.appboot.netflix.com/appboot/NFANDROID1-PRV-P-"
    MSL_HANDSHAKE_ENDPOINT = "https://ios.prod.ftl.netflix.com/nq/iosplatform/pbo_license/~1.0.0/router"

    USER_AGENT = "Netflix/5850 CFNetwork/3826.600.41 Darwin/24.6.0"
    CLIENT_VERSION = "18.26.0"
    APP_VERSION = "18.26.0"
    HAWKINS_VERSION = "5.16.0"
    UI_FLAVOR = "argo"
    OS_VERSION = "18.6.2"
    FORM_FACTOR = "phone"
    FEATURE_CAPABILITIES = "supportsStudioBranding"
    LOCALE = "en-US"
    DEVICE_MODEL = "iPhone15,3"

    ESN = f"NFANDROID1-PRV-P-IPHONE15=3-22594-{generate_esn_random_suffix(64)}"

    REQUEST_CLIENT_CONTEXT_LANDING = '{"appView":"nmLanding","appState":"foreground"}'
    REQUEST_CLIENT_CONTEXT_IDENTIFIER = '{"appView":"login","appState":"foreground"}'
    REQUEST_CLIENT_CONTEXT_PASSWORD = '{"appView":"passwordLogin","appState":"foreground"}'
    REQUEST_CLIENT_CONTEXT_PROFILES = '{"appView":"profilesGate","appState":"foreground"}'

    APPBOOT_CLIENT_CONTEXT = '{"appState":"foreground","reason":"user-action"}'
    APPBOOT_REQUEST_CLIENT_CONTEXT = '{"appView":"unknown","appState":"foreground"}'

    RECAPTCHA_SITE_KEY = "6Lf8hrcUAAAAAIpQAFW2VFjtiYnThOjZOA5xvLyR"

    QUERY_IDS = {
        "MembershipStatus": {"id": "3f50f3b3-fff8-48c0-bbd3-5fa2cb04b3c1", "version": 102},
        "CLCSScreenUpdate": {"id": "1c276cdf-caef-49cf-b38e-384972c2b47e", "version": 102},
        "CLCSSendFeedback": {"id": "079b2271-196b-4edd-b65c-e9439b22e305", "version": 102},
        "CLCSInterstitialProfileGate": {"id": "b6e10c7d-0e6f-4921-83b5-177995a80d97", "version": 102},
    }

    recaptcha_token = ""

    verify_tls = True
    restore_auth_cookies = False

    session = requests.Session()
    session.verify = verify_tls
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    })

    if restore_auth_cookies:
        restore_auth_cookies(session, AUTH_COOKIES_PATH, log)

    log.info("Initializing session")
    response = session.get(NETFLIX_CANONICAL_URL, timeout=30, allow_redirects=True)
    response.raise_for_status()

    response = session.get(NETFLIX_HOME_URL, timeout=30)
    response.raise_for_status()

    log.info("Requesting initial nfvdid cookie")
    appboot_request_id = generate_request_id()

    appboot_headers = {
        "Host": "ios18.appboot.netflix.com",
        "X-Netflix.Client.appVersion": APP_VERSION,
        "Accept": "*/*",
        "X-Netflix.Request.Id": appboot_request_id,
        "X-Netflix.APIAction": "appboot",
        "X-Netflix.Client.Context": APPBOOT_CLIENT_CONTEXT,
        "X-Netflix.Client.Request.Name": "appboot",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Netflix.Request.Attempt": "1",
        "X-Netflix.Request.Client.Context": APPBOOT_REQUEST_CLIENT_CONTEXT,
        "User-Agent": USER_AGENT,
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

    if not wvd_path.exists():
        raise FileNotFoundError(f"Missing WVD file: {wvd_path}")

    device = WidevineDevice.load(wvd_path)
    cdm = WidevineCdm.from_device(device)

    msl_headers = MSL_IOS.build_request_headers(
        request_name="mintCookies",
        user_agent=USER_AGENT,
        referer=None,
        esn=ESN,
        expiry_timeout=12750,
        host="ios.prod.ftl.netflix.com",
        language="en-US,en",
        device_model=quote(DEVICE_MODEL, safe=""),
        extra_headers={
            "Accept-Encoding": "deflate,gzip",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Encoding": "msl_v1",
            "X-Gibbon-Cache-Control": "no-cache",
            "X-AllowCompression": "true",
            "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
            "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
            "x-netflix.esn": ESN,
            "X-Netflix.Client.Request.Name": "mintCookies",
            "X-Netflix.Request.Client.Context": '{"appView":"login","appState":"foreground"}',
        },
    )

    handshake_cookies = {
        "nfvdid": nfvdid,
    }

    msl_keys = MSL_IOS.handshake(
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

    msl_client = MSL_IOS(
        session=session,
        keys=msl_keys,
        message_id=random.randint(0, pow(2, 52)),
        sender=ESN,
        drm="widevine",
    )

    nfvdid, flow_session_id = get_flow_session_cookies(session)

    log.info("MSL Widevine exchange completed")

    log.info("Submitting membership request")
    operation_name = "MembershipStatus"
    variables = {}

    headers = {
        "Host": "ios.prod.cloud.netflix.com",
        "Connection": "keep-alive",
        "X-Netflix.Request.Client.Context": REQUEST_CLIENT_CONTEXT_LANDING,
        "Content-Encoding": "msl_v1",
        "x-netflix.context.feature-capabilities": FEATURE_CAPABILITIES,
        "x-netflix.context.operation-name": operation_name,
        "X-Netflix.request.expiry.timeout": "15000",
        "X-Netflix.Request.Id": generate_request_id(),
        "x-netflix.context.hawkins-version": HAWKINS_VERSION,
        "x-netflix.context.form-factor": FORM_FACTOR,
        "X-Netflix.Request.Attempt": "1",
        "x-netflix.request.clcs.bucket": "high",
        "User-Agent": USER_AGENT,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "*/*",
        "Content-Type": "application/json",
        "x-netflix.context.locales": LOCALE,
        "x-netflix.context.os-version": OS_VERSION,
        "Accept-Encoding": "gzip, deflate, br",
        "x-netflix.context.app-version": APP_VERSION,
        "x-netflix.context.ui-flavor": UI_FLAVOR,
    }
    body = {
        "operationName": operation_name,
        "variables": variables,
        "extensions": {"persistedQuery": QUERY_IDS[operation_name]},
    }
    membership_header, membership_status_response = msl_client.send_message(
        endpoint=GRAPHQL_URL,
        params={},
        application_data=body,
        headers=headers,
    )
    if isinstance(membership_status_response, dict) and "errors" in membership_status_response:
        raise RuntimeError(json.dumps(membership_status_response["errors"], indent=2))

    log.info("Loading login page")
    response = session.get(LOGIN_URL, timeout=30)
    response.raise_for_status()
    login_html = response.text

    clcs_session_id = extract_clcs_session_id(login_html)
    rendition_id = extract_rendition_id(login_html)

    log.info("Submitting password screen update")

    session_context: Dict[str, Any] = {
        "session-breadcrumbs": {"funnel_name": "loginWeb"},
    }
    session_context.update({
        "login.navigationSettings": {"hideOtpToggle": True},
    })

    full_server_state = {
        "realm": "growth",
        "name": "PASSWORD_LOGIN",
        "clcsSessionId": clcs_session_id,
        "sessionContext": session_context,
    }

    full_screen_update = {
        "realm": "custom",
        "name": "growthLoginByPassword",
        "metadata": {"recaptchaSiteKey": RECAPTCHA_SITE_KEY},
        "loggingAction": "Submitted",
        "loggingCommand": "SubmitCommand",
        "referrerRenditionId": rendition_id,
    }

    full_variables = {
        "format": "HTML",
        "imageFormat": "PNG",
        "locale": "en-US",
        "serverState": json.dumps(full_server_state, separators=(",", ":")),
        "serverScreenUpdate": json.dumps(full_screen_update, separators=(",", ":")),
        "inputFields": [
            {"name": "password", "value": {"stringValue": PASSWORD}},
            {"name": "userLoginId", "value": {"stringValue": EMAIL}},
            {"name": "countryCode", "value": {"stringValue": "1"}},
            {"name": "countryIsoCode", "value": {"stringValue": "US"}},
            {"name": "recaptchaResponseTime", "value": {"intValue": 445}},
            {"name": "recaptchaResponseToken", "value": {"stringValue": recaptcha_token}},
        ],
    }
    try:
        operation_name = "CLCSScreenUpdate"
        headers = {
            "Host": "ios.prod.cloud.netflix.com",
            "Connection": "keep-alive",
            "X-Netflix.Request.Client.Context": REQUEST_CLIENT_CONTEXT_PASSWORD,
            "Content-Encoding": "msl_v1",
            "x-netflix.context.feature-capabilities": FEATURE_CAPABILITIES,
            "x-netflix.context.operation-name": operation_name,
            "X-Netflix.request.expiry.timeout": "15000",
            "X-Netflix.Request.Id": generate_request_id(),
            "x-netflix.context.hawkins-version": HAWKINS_VERSION,
            "x-netflix.context.form-factor": FORM_FACTOR,
            "X-Netflix.Request.Attempt": "1",
            "x-netflix.request.clcs.bucket": "high",
            "User-Agent": USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "*/*",
            "Content-Type": "application/json",
            "x-netflix.context.locales": LOCALE,
            "x-netflix.context.os-version": OS_VERSION,
            "Accept-Encoding": "gzip, deflate, br",
            "x-netflix.context.app-version": APP_VERSION,
            "x-netflix.context.ui-flavor": UI_FLAVOR,
        }

        body = {
            "operationName": operation_name,
            "variables": full_variables,
            "extensions": {
                "persistedQuery": QUERY_IDS[operation_name]
            },
        }

        login_header, login_response = msl_client.send_message(endpoint=GRAPHQL_URL,
                                                               params={},
                                                               application_data=body,
                                                               headers=headers)

        data = login_response.get("data", {}) if isinstance(login_response, dict) else {}
        result = data.get("result", {}) if isinstance(data, dict) else {}

        status = result.get("status")

        encrypted_header_b64 = login_header.get("headerdata")
        header_data = {}

        if encrypted_header_b64:
            header_data = decrypt_msl_header(encrypted_header_b64, msl_client.keys.encryption, msl_client.keys.sign)

    except Exception:
        log.exception("Failed to process the login response")
        sys.exit(1)

    if status == "SUCCESS":
        log.info("LOGIN SUCCESSFUL")

        try:
            save_session_cookies(session, AUTH_COOKIES_PATH, log)
        except Exception:
            sys.exit(1)

    else:
        log.error("LOGIN FAILED")
        sys.exit(1)


# ======================================================================
# TV (email/password)
# ======================================================================

def run_tv(wvd_path: Path,
           new_msl: bool = False, no_verify: bool = False):
    log = logging.getLogger('ANDROID TV MSL')

    OUTPUT_DIR = ensure_output_dir("tv")
    MSL_CACHE_PATH = OUTPUT_DIR / "msl_keys_cache.json"
    USER_ID_TOKEN_PATH = OUTPUT_DIR / "useridtoken.json"
    MSL_TRACE_PATH = OUTPUT_DIR / "msl_debug_trace.json"
    NETFLIX_COOKIES_PATH = OUTPUT_DIR / "netflix_cookies.json"
    LOGIN_RESPONSE_PATH = OUTPUT_DIR / "password_login_response.json"

    MSL_HANDSHAKE_ENDPOINT = "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_tokens/%5E1.0.0/router"
    MSL_TV_ENDPOINT = "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_tokens/%5E1.0.0/router"
    PBO_CONFIG_ENDPOINT = "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_config/%5E1.0.0/router?ab_ui_ver=darwin&nrdapp_version=2025.2.3.0"

    DEVICE_TYPE = "NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019"
    DEVICE_MODEL = "NVIDIA_SHIELD Android TV"
    DEVICE_NAME = "SHIELD"
    ANDROID_BUILD_FINGERPRINT = "12.1.9-23083 R 2025.2 android-30-JPLAYER2 ninja_6==NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4040.2147:user/release-keys"
    APP_VERSION = "UI-release-20260408_44798-gibbon-r100-aui-nrdjs=v3.12.55"
    AUI_SW_VERSION = "UI-release-20260408_44798-gibbon-sapphire-darwinql"
    SDK_VERSION = "2025.2.3.0"
    CLIENT_VERSION = "v3.12.55"
    NETJS_VERSION = "3.0.5"
    APK_VERSION = "12.1.9"
    UI_SEM_VER = "44798.0.0"
    ESN = f"{DEVICE_TYPE}-11233-{generate_esn_random_suffix(64)}"

    IMPORTANT_COOKIE_NAMES = (
        "netflix-mfa-nonce",
        "NetflixId",
        "SecureNetflixId",
        "nfvdid",
        "gsid",
    )

    QUERY_IDS = {
        "clcsLegacyMoneyballInitiateSession": {"id": "5152154d-6b61-4333-a738-92dc4ab712bd", "version": 102},
        "clcsLegacyMoneyballSubmit": {"id": "e8ef3234-6525-4975-8796-1299602e3297", "version": 102},
        "clcsScreenUpdate": {"id": "8daa70b0-fc21-4b5e-8c7e-ce0f31c8ca66", "version": 102},
        "useNavItemsQuery": {"id": "77a2fe81-a789-4b80-8c4c-0e962194cd09", "version": 102},
    }

    REQUEST_ARGS = [
        {"name": "deviceModel", "value": {"stringValue": DEVICE_MODEL}},
        {"name": "deviceName", "value": {"stringValue": DEVICE_NAME}},
        {"name": "deviceTypeOverride", "value": {"stringValue": DEVICE_TYPE}},
        {"name": "esn", "value": {"stringValue": ESN}},
        {"name": "fetchPartnerStrings", "value": {"booleanValue": False}},
        {"name": "isSuspendedMode", "value": {"booleanValue": False}},
        {"name": "nglVersion", "value": {"stringValue": "NGL_3"}},
        {"name": "resolution", "value": {"stringValue": "720p"}},
        {"name": "secureVLV", "value": {"stringValue": "true"}},
        {"name": "swVersion", "value": {"stringValue": AUI_SW_VERSION}},
        {"name": "ui_trace_tag", "value": {"stringValue": "aui-ql"}},
        {"name": "allocAutomation", "value": {"booleanValue": False}},
        {"name": "availableLocales", "value": {"stringValue": "zh,ta,ml,ko,te,gu,zh,kn,ur,ja"}},
        {"name": "suppScripts", "value": {"stringValue": "Hant,Tibt,Thai,Taml,Sinh,Orya,Mlym,Laoo,Armn,Geor,Kore,Telu,Beng,*,Hebr,Cyrl,Gujr,Hans,Deva,Guru,Cans,Ethi,Cher,Mymr,Knda,Grek,Latn,Arab,Jpan"}},
        {"name": "deviceLocale", "value": {"stringValue": "en-CA"}},
        {"name": "inAppSwVersion", "value": {"stringValue": APP_VERSION}},
        {"name": "appVersion", "value": {"stringValue": APP_VERSION}},
        {"name": "hasGooglePlayServiceOnTenfoot", "value": {"booleanValue": True}},
        {"name": "ab_ui_ver", "value": {"stringValue": "darwin"}},
        {"name": "application_name", "value": {"stringValue": "htmltvui"}},
        {"name": "application_v", "value": {"stringValue": APP_VERSION}},
        {"name": "dh", "value": {"stringValue": "720"}},
        {"name": "dw", "value": {"stringValue": "1280"}},
        {"name": "falcor_server", "value": {"stringValue": "0.1.0"}},
        {"name": "materialize", "value": {"booleanValue": True}},
        {"name": "mdxlib_version", "value": {"stringValue": SDK_VERSION}},
        {"name": "nrdapp_version", "value": {"stringValue": SDK_VERSION}},
        {"name": "nrdlib_version", "value": {"stringValue": SDK_VERSION}},
        {"name": "nrdp", "value": {"booleanValue": True}},
        {"name": "revision", "value": {"stringValue": "latest"}},
        {"name": "sdk_version", "value": {"stringValue": SDK_VERSION}},
        {"name": "sw_version", "value": {"stringValue": ANDROID_BUILD_FINGERPRINT}},
        {"name": "tag", "value": {"stringValue": "latest"}},
        {"name": "ui_sem_ver", "value": {"stringValue": UI_SEM_VER}},
        {"name": "webapiConfigAppName", "value": {"stringValue": "htmltvui"}},
        {"name": "withSize", "value": {"booleanValue": True}},
    ]

    REQUEST_ARGS_DICT = request_args_to_dict(REQUEST_ARGS)

    PBO_COMMON = {
        "sdk": SDK_VERSION,
        "platform": SDK_VERSION,
        "application": ANDROID_BUILD_FINGERPRINT,
        "uiversion": APP_VERSION,
        "uiPlatform": "tv_ui",
        "clientVersion": CLIENT_VERSION,
        "apkVersion": APK_VERSION,
    }

    MSL_TRACE: List[Dict[str, Any]] = []

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = False

    launch_uid = str(uuid.uuid4())
    aui_referer = (
        "https://secure.netflix.com/us/tvui/aui/20260408_44798/release_v8/auiStartup.js"
        f"?q=source_type%3D2%26launchUID%3D{launch_uid}&dw=1280&dh=720&dar=16_9"
        "&reg=false&noMemberTarget=true"
    )
    runtime_referer = (
        "https://secure.netflix.com/us/tvui/ql/20260407/44745/release_v8/darwinBootstrap.js"
        "?startup_key=429c6159fd3e080b97d6df5bf5ce8e38b0ecc222773811cd12d8251aeea4a738"
        f"&device_type={DEVICE_TYPE}"
        f"&e={quote(ESN, safe='')}"
        "&env=prod&fromNM=true&nm_prefetch=true&nrdapp_version=2025.2.3.0&plain=true&script_engine=v8"
        f"&sessionId={uuid.uuid4()}&authType=login&authclid={uuid.uuid4()}"
        f"&q=source_type%3D2%26launchUID%3D{launch_uid}%26source_type_payload%3D"
    )

    graphql_url = "https://nrdp.prod.cloud.netflix.com/graphql"

    log.info("Fetching nfvdid from Android TV config endpoint")
    response = session.get(
        "https://androidtv.prod.cloud.netflix.com/android/ninja/config",
        params={
            "responseFormat": "json",
            "progressive": "false",
            "method": "get",
            "routing": "redirect",
            "appType": "ninja",
            "mnf": "NVIDIA",
            "mId": "SHIELD=ANDROID=TV",
            "appVer": "23083",
            "appVerName": "12.1.9 build 23083",
            "api": "30",
            "modelgroup": "NVIDIASHIELDANDROIDTV2019",
            "oemmodel": "",
            "esn": ESN,
            "osBoard": "darcy",
            "osDevice": "mdarcy",
            "osDisplay": "RQ1A.210105.003.7825230_4040.2147",
            "osFingerprint": "NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4040.2147:user/release-keys",
            "osCpu": "armeabi-v7a",
            "osProduct": "mdarcy",
            "validation": "ninja_6",
            "ramSizeMB": "2946",
            "path": ["['deviceConfig']", "['fpConfig']"],
        },
        headers={
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SHIELD Android TV Build/RQ1A.210105.003)",
            "Accept": "*/*",
            "X-Netflix.Client.Request.Name": "androidninjaconfig",
            "X-Netflix.Request.Client.Context": '{"appState":"foreground"}',
        },
        timeout=30,
    )
    response.raise_for_status()
    nfvdid = session.cookies.get("nfvdid")
    log.info("nfvdid: %s", (nfvdid[:80] + "...") if nfvdid else "not received")

    log.info("Bootstrap AUI and pre-login pathEvaluator")
    try:
        session.headers.clear()
        session.get(
            aui_referer,
            headers={
                "User-Agent": f"Netflix/{SDK_VERSION} (DEVTYPE={DEVICE_TYPE}; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
                "Accept": "application/javascript,text/javascript,application/x-javascript",
            },
            timeout=30,
        )
        session.get(
            "https://nrdp.prod.cloud.netflix.com/healthcheck",
            headers={
                "User-Agent": f"Netflix/{SDK_VERSION} (DEVTYPE={DEVICE_TYPE}; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
                "Accept": "*/*",
                "x-netflix.context.sdk-version": SDK_VERSION,
                "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
                "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
                "X-Netflix.Request.NonJson.Headers": "true",
                "x-netflix.client.netjs.version": NETJS_VERSION,
                "X-Netflix.request.attempt": "1",
                "Referer": aui_referer,
            },
            timeout=30,
        )

        params = [
            ("ab_ui_ver", "darwin"),
            ("application_name", "htmltvui"),
            ("application_v", APP_VERSION),
            ("dh", "720"),
            ("dw", "1280"),
            ("falcor_server", "0.1.0"),
            ("materialize", "true"),
            ("mdxlib_version", SDK_VERSION),
            ("nrdapp_version", SDK_VERSION),
            ("nrdlib_version", SDK_VERSION),
            ("nrdp", "true"),
            ("revision", "latest"),
            ("sdk_version", SDK_VERSION),
            ("sw_version", ANDROID_BUILD_FINGERPRINT),
            ("tag", "latest"),
            ("ui_sem_ver", UI_SEM_VER),
            ("webapiConfigAppName", "htmltvui"),
            ("withSize", "true"),
            ("availableLocales", "zh,ta,ml,ko,te,gu,zh,kn,ur,ja"),
            ("deviceLocale", "en-CA"),
            ("deviceModel", DEVICE_MODEL),
            ("deviceName", DEVICE_NAME),
            ("deviceTypeOverride", DEVICE_TYPE),
            ("esn", ESN),
            ("hasGooglePlayServiceOnTenfoot", "true"),
            ("isSuspendedMode", "false"),
            ("netflixClientPlatform", "tenfootMDS"),
            ("nglVersion", "NGL_3"),
            ("resolution", "720p"),
            ("secureVLV", "true"),
            ("suppScripts", "Hant,Tibt,Thai,Taml,Sinh,Orya,Mlym,Laoo,Armn,Geor,Kore,Telu,Beng,*,Hebr,Cyrl,Gujr,Hans,Deva,Guru,Cans,Ethi,Cher,Mymr,Knda,Grek,Latn,Arab,Jpan"),
            ("swVersion", AUI_SW_VERSION),
            ("ui_trace_tag", "aui-ql"),
            ("inAppSwVersion", APP_VERSION),
            ("path", '["aui",["appconfig","partnerData","requestContext","userContext"]]'),
            ("path", '["aui","truths",["project.bao.ui.enabled","tvui.aui.bugsnag.enabled","tvui.aui.clcs.enabled"]]'),
            ("json", "true"),
            ("method", "get"),
            ("seed", str(random.random())),
        ]

        session.headers.clear()
        session.headers.update(
            {
                "User-Agent": f"Netflix/{SDK_VERSION} (DEVTYPE={DEVICE_TYPE}; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
                "Accept": "*/*",
                "Accept-Encoding": "deflate,gzip",
                "x-netflix.context.sdk-version": SDK_VERSION,
                "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
                "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
                "X-Gibbon-Cache-Control": "no-cache",
                "X-Netflix.request.expiry.timeout": "20000",
                "X-Netflix.Client.Request.Name": "ui/falcorUnclassified",
                "X-Netflix.Request.Routing": '{"control_tag":"auinqtv","path":"/nq/aui/endpoint/%5E1.0.0-tv/pathEvaluator"}',
                "x-netflix.client.last-interacted-days": "0",
                "X-Netflix.Request.NonJson.Headers": "true",
                "x-netflix.client.netjs.version": NETJS_VERSION,
                "X-Netflix.request.attempt": "1",
                "Referer": aui_referer,
            }
        )
        response = session.get("https://api-global.netflix.com/aui/pathEvaluator/tv/latest?" + urlencode(params, doseq=True), timeout=30)
        response.raise_for_status()
        log.info("AUI bootstrap OK")
    except Exception as exc:
        log.warning("AUI bootstrap failed: %s", exc)

    log.info("MSL handshake and mintCookies")
    msl = None
    try:
        cached_keys = MSL_TV.load_cache_data(MSL_CACHE_PATH)
    except Exception:
        cached_keys = None

    try:
        if cached_keys and getattr(cached_keys, "mastertoken", None) and getattr(cached_keys, "encryption", None) and getattr(cached_keys, "sign", None):
            msl = MSL_TV(
                session=session,
                keys=cached_keys,
                message_id=random.randint(0, 2**52),
                sender=ESN,
                user_auth=None,
                drm="widevine",
            )
            log.info("Using cached MSL keys")
        else:
            if not wvd_path.exists():
                raise FileNotFoundError(f"Missing WVD file: {wvd_path}")
            device = WidevineDevice.load(wvd_path)
            cdm = WidevineCdm.from_device(device)
            cdm_device = str(wvd_path)

            cookies_for_handshake: Dict[str, str] = {}
            if nfvdid:
                cookies_for_handshake["nfvdid"] = nfvdid

            msl_headers = MSL_TV.build_request_headers(
                request_name="mintCookies",
                user_agent=f"Netflix/{SDK_VERSION} (DEVTYPE={DEVICE_TYPE}; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
                referer=None,
                esn=ESN,
                expiry_timeout=12750,
                extra_headers={
                    "Accept-Encoding": "deflate,gzip",
                    "Content-Encoding": "msl_v1",
                    "X-Gibbon-Cache-Control": "no-cache",
                    "X-AllowCompression": "true",
                    "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
                    "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
                    "x-netflix.client.nrdjs.version": CLIENT_VERSION,
                    "x-netflix.esn": ESN,
                },
            )

            keys = MSL_TV.handshake(
                msl_keys_path=str(MSL_CACHE_PATH),
                session=session,
                sender=ESN,
                cdm=cdm,
                cdm_device=cdm_device,
                new_msl=False,
                cookies=cookies_for_handshake,
                drm="widevine",
                endpoint=MSL_HANDSHAKE_ENDPOINT,
                headers=msl_headers,
            )

            if not keys or not keys.mastertoken:
                raise RuntimeError("MSL handshake did not return a valid master token")

            msl = MSL_TV(
                session=session,
                keys=keys,
                message_id=random.randint(0, 2**52),
                sender=ESN,
                user_auth=None,
                drm="widevine",
            )
            log.info("MSL handshake OK")

        if not (msl.keys and msl.keys.mastertoken and msl.keys.encryption and msl.keys.sign):
            cached_keys = MSL_TV.load_cache_data(MSL_CACHE_PATH)
            if cached_keys is None:
                raise RuntimeError("MSL cache is empty or expired")
            msl = MSL_TV(
                session=msl.session,
                keys=cached_keys,
                message_id=random.randint(0, 2**52),
                sender=ESN,
                user_auth=None,
                drm="widevine",
            )

        msl.session.headers.clear()
        mint_headers = MSL_TV.build_request_headers(
            request_name="mintCookies",
            user_agent=f"Netflix/{SDK_VERSION} (DEVTYPE={DEVICE_TYPE}; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
            referer=runtime_referer,
            esn=ESN,
            expiry_timeout=12750,
            extra_headers={
                "Accept-Encoding": "deflate,gzip",
                "Content-Encoding": "msl_v1",
                "X-Gibbon-Cache-Control": "no-cache",
                "X-AllowCompression": "true",
                "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
                "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
                "x-netflix.esn": ESN,
            },
        )

        header, payload = msl.send_message(
            endpoint=MSL_TV_ENDPOINT,
            params={},
            application_data={
                "version": 2,
                "common": dict(PBO_COMMON),
                "url": "/mintCookies",
                "languages": ["en-CA"],
                "params": {},
            },
            headers=mint_headers,
        )

        payload_type, parsed_payload, text_payload = parse_msl_payload(payload)

        key_id = extract_key_id_from_mastertoken(msl.keys.mastertoken) if msl.keys.mastertoken else ""

        event = build_msl_trace_event(msl.message_id, key_id, payload_type, parsed_payload, text_payload)
        MSL_TRACE.append(event)

        useridtoken = extract_useridtoken_from_payload(parsed_payload, payload)

        if useridtoken:
            USER_ID_TOKEN_PATH.write_text(json.dumps(useridtoken, indent=2), encoding="utf-8")
            log.info("useridtoken saved to %s", USER_ID_TOKEN_PATH.name)

        log.info("Cookies after mintCookies: %s", [cookie.name for cookie in session.cookies])
    except Exception as exc:
        log.warning("MSL setup or mintCookies failed: %s", exc)
        log.warning("Continuing with the HAR login order anyway")

    log.info("CLCS initiate session")
    trace_uuid = str(uuid.uuid4())
    session.headers.clear()
    session.headers.update(
        {
            "Language": "en-CA,en-US,en",
            "User-Agent": f"Netflix/{SDK_VERSION} (DEVTYPE={DEVICE_TYPE}; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
            "Accept": "*/*",
            "Accept-Language": "en-CA,en-US,en",
            "Accept-Encoding": "deflate,gzip",
            "Content-Type": "application/json",
            "Connection": "Keep-Alive",
            "x-netflix.context.sdk-version": SDK_VERSION,
            "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
            "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
            "X-Gibbon-Cache-Control": "no-cache",
            "x-netflix.request.expiry.timeout": "20000",
            "x-Netflix.context.app-version": UI_SEM_VER,
            "x-Netflix.context.cloud-games-enabled": "false",
            "X-Netflix.context.device-height": "720",
            "x-Netflix.context.device-image-capability": "scalingFactor=1.0;supportedFormats=jpg,png,astc",
            "x-Netflix.context.dt": "",
            "x-Netflix.context.hawkins-version": "5.13.0",
            "X-Netflix.context.locales": '["en-CA","en-US","en"]',
            "X-Netflix.context.ui-flavor": "photon",
            "X-Netflix.request.device-model": quote(DEVICE_MODEL, safe=""),
            "X-Netflix.request.is-suspended": "false",
            "x-netflix.request.clcs.bucket": "high",
            "X-Netflix.request.toplevel.uuid": trace_uuid,
            "X-Netflix.tracing.cl.userActionId": trace_uuid,
            "x-netflix.client.last-interacted-days": "0",
            "X-Netflix.Request.NonJson.Headers": "true",
            "x-netflix.client.netjs.version": NETJS_VERSION,
            "X-Netflix.request.attempt": "1",
            "X-Netflix.context.operation-name": "clcsLegacyMoneyballInitiateSession",
            "Referer": aui_referer,
        }
    )

    cookie_values: List[str] = []
    headers = dict(session.headers)
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(
        graphql_url + f"?device_type={DEVICE_TYPE}&esn={quote(ESN, safe='')}&o=clcsLegacyMoneyballInitiateSession",
        json={
            "extensions": {"persistedQuery": QUERY_IDS["clcsLegacyMoneyballInitiateSession"]},
            "operationName": "clcsLegacyMoneyballInitiateSession",
            "variables": {
                "action": "",
                "flow": "tenfootSignUp",
                "hasGooglePlayService": False,
                "imageFormat": "ASTC",
                "inputFields": [],
                "legacyRequestArguments": REQUEST_ARGS,
                "mode": "none",
                "resolutionMode": "TV_720P",
                "supportedVideoFormat": "mp4",
            },
        },
        headers=headers,
        timeout=30,
    )

    apply_set_cookie_headers(session, response, cookie_values)

    response.raise_for_status()
    init_data = response.json()

    flow: Dict[str, str] = {}
    data = init_data.get("data", {})
    operation_key = next(iter(data.keys()), "")
    inner = data.get(operation_key, {})
    screen = inner.get("screen", inner) if isinstance(inner, dict) else {}
    stack = [screen]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            tracking_info = value.get("trackingInfo")
            if isinstance(tracking_info, str) and tracking_info:
                try:
                    tracking = json.loads(tracking_info)
                except Exception:
                    tracking = {}
                if tracking.get("clcsSessionId") and not flow.get("clcsSessionId"):
                    flow["clcsSessionId"] = tracking.get("clcsSessionId", "")
                if tracking.get("clcsRenditionId") and not flow.get("renditionId"):
                    flow["renditionId"] = tracking.get("clcsRenditionId", "")
            payload_json = value.get("payloadJson")
            if isinstance(payload_json, str) and payload_json:
                try:
                    payload = json.loads(payload_json)
                except Exception:
                    payload = {}
                if payload.get("flwssn") and not flow.get("flowSessionId"):
                    flow["flowSessionId"] = payload.get("flwssn", "")
                if payload.get("mode") and not flow.get("mode"):
                    flow["mode"] = payload.get("mode", "")
            if value.get("membershipStatus"):
                flow["membershipStatus"] = value.get("membershipStatus", "")
            for child in value.values():
                stack.append(child)
        elif isinstance(value, list):
            for item in value:
                stack.append(item)

    flow_session_id = flow.get("flowSessionId", "")
    clcs_session_id = flow.get("clcsSessionId", "")
    rendition_id = flow.get("renditionId", "")
    log.info("flowSessionId: %s", flow_session_id)
    log.info("clcsSessionId: %s", clcs_session_id)
    log.info("initial renditionId: %s", rendition_id)

    if not flow_session_id or not clcs_session_id:
        raise RuntimeError("Failed to extract flow/session IDs from initiate session response")

    log.info("Move from welcome landing into web sign-in and password path")

    # Step 5a: signInAction on welcomeContentLanding
    trace_uuid = str(uuid.uuid4())
    session.headers["X-Netflix.request.id"] = generate_hex_id(32, uppercase=True)
    session.headers["X-Netflix.request.toplevel.uuid"] = trace_uuid
    session.headers["X-Netflix.tracing.cl.userActionId"] = trace_uuid
    session.headers["X-Netflix.context.operation-name"] = "clcsLegacyMoneyballSubmit"

    server_state = json.dumps(
        {
            "realm": "moneyball",
            "flow": "tenfootSignUp",
            "mode": "welcomeContentLanding",
            "flowSessionId": flow_session_id,
            "requestArguments": REQUEST_ARGS_DICT,
            "clcsSessionId": clcs_session_id,
        },
        separators=(",", ":"),
    )

    cookie_values = []
    headers = dict(session.headers)
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(
        graphql_url + f"?device_type={DEVICE_TYPE}&esn={quote(ESN, safe='')}&o=clcsLegacyMoneyballSubmit",
        json={
            "extensions": {"persistedQuery": QUERY_IDS["clcsLegacyMoneyballSubmit"]},
            "operationName": "clcsLegacyMoneyballSubmit",
            "variables": {
                "action": "signInAction",
                "flow": "tenfootSignUp",
                "flwssn": flow_session_id,
                "imageFormat": "ASTC",
                "inputFields": [],
                "mode": "welcomeContentLanding",
                "requestArguments": REQUEST_ARGS,
                "resolutionMode": "TV_720P",
                "serverState": server_state,
            },
        },
        headers=headers,
        timeout=30,
    )

    apply_set_cookie_headers(session, response, cookie_values)

    response.raise_for_status()
    submit_data = response.json()
    mfa_nonce = session.cookies.get("netflix-mfa-nonce")
    log.info("netflix-mfa-nonce: %s", (mfa_nonce[:80] + "...") if mfa_nonce else "missing")

    flow_update = parse_flow_data(submit_data)

    flow_session_id = flow_update.get("flowSessionId", flow_session_id)
    clcs_session_id = flow_update.get("clcsSessionId", clcs_session_id)
    rendition_id = flow_update.get("renditionId", rendition_id)

    # Step 5b: lrudSignInAction on webSignIn
    trace_uuid = str(uuid.uuid4())
    session.headers["X-Netflix.request.id"] = generate_hex_id(32, uppercase=True)
    session.headers["X-Netflix.request.toplevel.uuid"] = trace_uuid
    session.headers["X-Netflix.tracing.cl.userActionId"] = trace_uuid
    session.headers["X-Netflix.context.operation-name"] = "clcsScreenUpdate"

    server_state = json.dumps(
        {
            "realm": "moneyball",
            "flow": "tenfootSignUp",
            "mode": "webSignIn",
            "flowSessionId": flow_session_id,
            "requestArguments": REQUEST_ARGS_DICT,
            "clcsSessionId": clcs_session_id,
        },
        separators=(",", ":"),
    )

    cookie_values = []
    headers = dict(session.headers)
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(
        graphql_url + f"?device_type={DEVICE_TYPE}&esn={quote(ESN, safe='')}&o=clcsScreenUpdate",
        json={
            "extensions": {"persistedQuery": QUERY_IDS["clcsScreenUpdate"]},
            "operationName": "clcsScreenUpdate",
            "variables": {
                "imageFormat": "PNG",
                "inputFields": [],
                "resolutionMode": "TV_720P",
                "serverScreenUpdate": json.dumps(
                    {
                        "realm": "moneyball",
                        "action": "lrudSignInAction",
                        "loggingAction": "Submitted",
                        "loggingCommand": "SubmitCommand",
                        "referrerRenditionId": rendition_id,
                    },
                    separators=(",", ":"),
                ),
                "serverState": server_state,
            },
        },
        headers=headers,
        timeout=30,
    )
    response.raise_for_status()
    step_web_signin = response.json()

    flow_update = parse_flow_data(step_web_signin)

    flow_session_id = flow_update.get("flowSessionId", flow_session_id)
    clcs_session_id = flow_update.get("clcsSessionId", clcs_session_id)
    rendition_id = flow_update.get("renditionId", rendition_id)

    # Step 5c: submitUserIdAction on enterMemberCredentials
    trace_uuid = str(uuid.uuid4())
    session.headers["X-Netflix.request.id"] = generate_hex_id(32, uppercase=True)
    session.headers["X-Netflix.request.toplevel.uuid"] = trace_uuid
    session.headers["X-Netflix.tracing.cl.userActionId"] = trace_uuid
    session.headers["X-Netflix.context.operation-name"] = "clcsScreenUpdate"

    server_state = json.dumps(
        {
            "realm": "moneyball",
            "flow": "tenfootSignUp",
            "mode": "enterMemberCredentials",
            "flowSessionId": flow_session_id,
            "requestArguments": REQUEST_ARGS_DICT,
            "clcsSessionId": clcs_session_id,
        },
        separators=(",", ":"),
    )

    cookie_values = []
    headers = dict(session.headers)
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(
        graphql_url + f"?device_type={DEVICE_TYPE}&esn={quote(ESN, safe='')}&o=clcsScreenUpdate",
        json={
            "extensions": {"persistedQuery": QUERY_IDS["clcsScreenUpdate"]},
            "operationName": "clcsScreenUpdate",
            "variables": {
                "imageFormat": "PNG",
                "inputFields": [
                    {"name": "userLoginId", "value": {"stringValue": EMAIL}},
                ],
                "resolutionMode": "TV_720P",
                "serverScreenUpdate": json.dumps(
                    {
                        "realm": "moneyball",
                        "action": "submitUserIdAction",
                        "loggingAction": "Submitted",
                        "loggingCommand": "SubmitCommand",
                        "referrerRenditionId": rendition_id,
                    },
                    separators=(",", ":"),
                ),
                "serverState": server_state,
            },
        },
        headers=headers,
        timeout=30,
    )
    response.raise_for_status()
    step_user = response.json()

    flow_update = parse_flow_data(step_user)

    flow_session_id = flow_update.get("flowSessionId", flow_session_id)
    clcs_session_id = flow_update.get("clcsSessionId", clcs_session_id)
    rendition_id = flow_update.get("renditionId", rendition_id)

    # Step 5d: usePasswordAction on loginLinkOption
    trace_uuid = str(uuid.uuid4())
    session.headers["X-Netflix.request.id"] = generate_hex_id(32, uppercase=True)
    session.headers["X-Netflix.request.toplevel.uuid"] = trace_uuid
    session.headers["X-Netflix.tracing.cl.userActionId"] = trace_uuid
    session.headers["X-Netflix.context.operation-name"] = "clcsScreenUpdate"

    server_state = json.dumps(
        {
            "realm": "moneyball",
            "flow": "tenfootSignUp",
            "mode": "loginLinkOption",
            "flowSessionId": flow_session_id,
            "requestArguments": REQUEST_ARGS_DICT,
            "clcsSessionId": clcs_session_id,
        },
        separators=(",", ":"),
    )

    cookie_values = []
    headers = dict(session.headers)
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(
        graphql_url + f"?device_type={DEVICE_TYPE}&esn={quote(ESN, safe='')}&o=clcsScreenUpdate",
        json={
            "extensions": {"persistedQuery": QUERY_IDS["clcsScreenUpdate"]},
            "operationName": "clcsScreenUpdate",
            "variables": {
                "imageFormat": "PNG",
                "inputFields": [],
                "resolutionMode": "TV_720P",
                "serverScreenUpdate": json.dumps(
                    {
                        "realm": "moneyball",
                        "action": "usePasswordAction",
                        "replaceCurrentScreen": True,
                        "loggingAction": "Submitted",
                        "loggingCommand": "SubmitCommand",
                        "referrerRenditionId": rendition_id,
                    },
                    separators=(",", ":"),
                ),
                "serverState": server_state,
            },
        },
        headers=headers,
        timeout=30,
    )
    response.raise_for_status()
    step_password_path = response.json()

    flow_update = parse_flow_data(step_password_path)

    flow_session_id = flow_update.get("flowSessionId", flow_session_id)
    clcs_session_id = flow_update.get("clcsSessionId", clcs_session_id)
    rendition_id = flow_update.get("renditionId", rendition_id)

    log.info("Credential path ready, current renditionId: %s", rendition_id)

    log.info("Submit email and password")
    trace_uuid = str(uuid.uuid4())
    session.headers["X-Netflix.request.id"] = generate_hex_id(32, uppercase=True)
    session.headers["X-Netflix.request.toplevel.uuid"] = trace_uuid
    session.headers["X-Netflix.tracing.cl.userActionId"] = trace_uuid
    session.headers["X-Netflix.context.operation-name"] = "clcsScreenUpdate"

    server_state = json.dumps(
        {
            "realm": "moneyball",
            "flow": "tenfootSignUp",
            "mode": "enterMemberCredentials",
            "flowSessionId": flow_session_id,
            "requestArguments": REQUEST_ARGS_DICT,
            "clcsSessionId": clcs_session_id,
        },
        separators=(",", ":"),
    )

    cookie_values = []
    headers = dict(session.headers)
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(
        graphql_url + f"?device_type={DEVICE_TYPE}&esn={quote(ESN, safe='')}&o=clcsScreenUpdate",
        json={
            "extensions": {"persistedQuery": QUERY_IDS["clcsScreenUpdate"]},
            "operationName": "clcsScreenUpdate",
            "variables": {
                "imageFormat": "PNG",
                "inputFields": [
                    {"name": "userLoginId", "value": {"stringValue": EMAIL}},
                    {"name": "password", "value": {"stringValue": PASSWORD}},
                ],
                "resolutionMode": "TV_720P",
                "serverScreenUpdate": json.dumps(
                    {
                        "realm": "moneyball",
                        "action": "nextAction",
                        "loggingAction": "Submitted",
                        "loggingCommand": "SubmitCommand",
                        "referrerRenditionId": rendition_id,
                    },
                    separators=(",", ":"),
                ),
                "serverState": server_state,
            },
        },
        headers=headers,
        timeout=30,
    )

    apply_set_cookie_headers(session, response, cookie_values)

    response.raise_for_status()
    login_data = response.json()
    LOGIN_RESPONSE_PATH.write_text(json.dumps(login_data, indent=2, ensure_ascii=False), encoding="utf-8")

    flow_result = parse_flow_data(login_data)

    membership = flow_result.get("membershipStatus", "")
    flow_session_id = flow_result.get("flowSessionId", flow_session_id)
    clcs_session_id = flow_result.get("clcsSessionId", clcs_session_id)
    rendition_id = flow_result.get("renditionId", rendition_id)
    log.info("Membership after credential submit: %s", membership)

    log.info("Post-login bootstrap to obtain gsid")
    trace_uuid = str(uuid.uuid4())
    session.headers.clear()
    session.headers.update(
        {
            "Language": "en-CA,en-US,en",
            "User-Agent": f"Netflix/{SDK_VERSION} (DEVTYPE={DEVICE_TYPE}; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
            "Accept": "*/*",
            "Accept-Language": "en-CA,en-US,en",
            "Accept-Encoding": "deflate,gzip",
            "Content-Type": "application/json",
            "Connection": "Keep-Alive",
            "x-netflix.context.sdk-version": SDK_VERSION,
            "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
            "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"browseTitles","appstate":"foreground","reason":"unknown"}',
            "X-Gibbon-Cache-Control": "no-cache",
            "x-netflix.request.expiry.timeout": "20000",
            "x-Netflix.context.app-version": UI_SEM_VER,
            "x-Netflix.context.cloud-games-enabled": "false",
            "X-Netflix.context.device-height": "720",
            "x-Netflix.context.device-image-capability": "scalingFactor=1.0;supportedFormats=jpg,png,astc,webp",
            "x-Netflix.context.dt": "",
            "x-Netflix.context.hawkins-version": "5.13.0",
            "X-Netflix.context.locales": '["en-CA","en-US","en"]',
            "X-Netflix.context.ui-flavor": "photon",
            "X-Netflix.request.device-model": quote(DEVICE_MODEL, safe=""),
            "X-Netflix.request.is-suspended": "false",
            "x-netflix.request.clcs.bucket": "high",
            "X-Netflix.request.toplevel.uuid": trace_uuid,
            "X-Netflix.tracing.cl.userActionId": trace_uuid,
            "x-netflix.client.last-interacted-days": "0",
            "X-Netflix.Request.NonJson.Headers": "true",
            "x-netflix.client.netjs.version": NETJS_VERSION,
            "X-Netflix.request.attempt": "1",
            "X-Netflix.context.operation-name": "useNavItemsQuery",
            "Referer": runtime_referer,
        }
    )

    cookie_values = []
    headers = dict(session.headers)
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(
        graphql_url + "?o=useNavItemsQuery",
        json={
            "extensions": {"persistedQuery": QUERY_IDS["useNavItemsQuery"]},
            "operationName": "useNavItemsQuery",
            "query": None,
            "variables": {
                "artworkCapability": {
                    "artworkResolution": "TVUI_720P",
                    "deviceResolution": "TVUI_720P",
                    "disablePersonalization": False,
                    "supportsAstcFormat": True,
                    "useWebPForAllImages": True,
                    "useWebPForLargeImages": True,
                }
            },
        },
        headers=headers,
        timeout=30,
    )

    apply_set_cookie_headers(session, response, cookie_values)

    response.raise_for_status()
    gsid = session.cookies.get("gsid")
    log.info("gsid: %s", gsid if gsid else "missing")

    log.info("Post-login PBO config and token refresh")
    if msl is not None and "NetflixId" in session.cookies.get_dict() and "SecureNetflixId" in session.cookies.get_dict():
        try:
            if not (msl.keys and msl.keys.mastertoken and msl.keys.encryption and msl.keys.sign):
                cached_keys = MSL_TV.load_cache_data(MSL_CACHE_PATH)
                if cached_keys is None:
                    raise RuntimeError("MSL cache is empty or expired")
                msl = MSL_TV(
                    session=msl.session,
                    keys=cached_keys,
                    message_id=random.randint(0, 2**52),
                    sender=ESN,
                    user_auth=None,
                    drm="widevine",
                )

            msl.session.headers.clear()
            config_headers = MSL_TV.build_request_headers(
                request_name="config",
                user_agent=f"Netflix/{SDK_VERSION} (DEVTYPE={DEVICE_TYPE}; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
                referer=aui_referer,
                esn=ESN,
                expiry_timeout=12750,
                extra_headers={
                    "Accept-Encoding": "deflate,gzip",
                    "Content-Encoding": "msl_v1",
                    "X-Gibbon-Cache-Control": "no-cache",
                    "X-AllowCompression": "true",
                    "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
                    "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
                    "x-netflix.esn": ESN,
                },
            )
            msl.send_message(
                endpoint=PBO_CONFIG_ENDPOINT,
                params={},
                application_data={"method": "config", "params": {}},
                headers=config_headers,
            )

            for request_name, route, referer_to_use in [
                ("getPartnerToken", "/getPartnerToken", aui_referer),
                ("ping", "/ping", runtime_referer),
                ("getPartnerToken", "/getPartnerToken", runtime_referer),
            ]:
                if not (msl.keys and msl.keys.mastertoken and msl.keys.encryption and msl.keys.sign):
                    cached_keys = MSL_TV.load_cache_data(MSL_CACHE_PATH)
                    if cached_keys is None:
                        raise RuntimeError("MSL cache is empty or expired")
                    msl = MSL_TV(
                        session=msl.session,
                        keys=cached_keys,
                        message_id=random.randint(0, 2**52),
                        sender=ESN,
                        user_auth=None,
                        drm="widevine",
                    )

                msl.session.headers.clear()
                optional_headers = MSL_TV.build_request_headers(
                    request_name=request_name,
                    user_agent=f"Netflix/{SDK_VERSION} (DEVTYPE={DEVICE_TYPE}; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
                    referer=referer_to_use,
                    esn=ESN,
                    expiry_timeout=12750,
                    extra_headers={
                        "Accept-Encoding": "deflate,gzip",
                        "Content-Encoding": "msl_v1",
                        "X-Gibbon-Cache-Control": "no-cache",
                        "X-AllowCompression": "true",
                        "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
                        "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
                        "x-netflix.esn": ESN,
                    },
                )

                header, payload = msl.send_message(
                    endpoint=MSL_TV_ENDPOINT,
                    params={},
                    application_data={
                        "version": 2,
                        "common": dict(PBO_COMMON),
                        "url": route,
                        "languages": ["en-CA"],
                        "params": {},
                    },
                    headers=optional_headers,
                )

                payload_type, parsed_payload, text_payload = parse_msl_payload(payload)

                event = build_msl_trace_event(msl.message_id, "", payload_type, parsed_payload, text_payload)
                MSL_TRACE.append(event)

                if isinstance(header, dict) and "headerdata" in header:
                    try:
                        header_data = decrypt_msl_header(header["headerdata"], msl.keys.encryption, msl.keys.sign)
                        tokens = header_data.get("useridtoken")
                        if tokens:
                            USER_ID_TOKEN_PATH.write_text(json.dumps(tokens, indent=2), encoding="utf-8")
                            log.info("useridtoken refreshed from %s", route)
                    except Exception:
                        pass
        except Exception as exc:
            log.warning("Post-login MSL refresh failed: %s", exc)

    log.info("Save filtered cookies")
    dedupe_important_cookies(session, IMPORTANT_COOKIE_NAMES)

    cookies: Dict[str, str] = {}
    for cookie in session.cookies:
        if cookie.name in IMPORTANT_COOKIE_NAMES and cookie.value and cookie.name not in cookies:
            cookies[cookie.name] = cookie.value

    NETFLIX_COOKIES_PATH.write_text(json.dumps(cookies, indent=2), encoding="utf-8")
    MSL_TRACE_PATH.write_text(json.dumps(MSL_TRACE, indent=2, ensure_ascii=False), encoding="utf-8")

    log.info("Final status")
    if membership == "CURRENT_MEMBER" and "NetflixId" in cookies and "SecureNetflixId" in cookies:
        log.info("LOGIN SUCCESSFUL")
        log.info("NetflixId: %s", f"{cookies['NetflixId'][:80]}...")
        log.info("SecureNetflixId: %s", f"{cookies['SecureNetflixId'][:80]}...")
        log.info("nfvdid: %s", f"{cookies.get('nfvdid', 'N/A')[:80]}...")
        log.info("netflix-mfa-nonce: %s", f"{cookies.get('netflix-mfa-nonce', 'N/A')[:80]}...")
        log.info("gsid: %s", cookies.get("gsid", "N/A"))
    else:
        log.error("LOGIN FAILED")
        exit(1)

    result = {
        "cookies": cookies,
        "session": session,
        "flow_session_id": flow_session_id,
        "clcs_session_id": clcs_session_id,
        "response": login_data,
        "useridtoken_path": str(USER_ID_TOKEN_PATH) if USER_ID_TOKEN_PATH.exists() else None,
        "msl_trace_path": str(MSL_TRACE_PATH),
        "login_response_path": str(LOGIN_RESPONSE_PATH),
    }

    log.info("Cookies saved to %s", NETFLIX_COOKIES_PATH.name)
    log.info("MSL decrypt trace saved to %s", MSL_TRACE_PATH.name)
    log.info("Password login response saved to %s", LOGIN_RESPONSE_PATH.name)
    if result["useridtoken_path"]:
        log.info("useridtoken saved to %s", Path(result["useridtoken_path"]).name)
    else:
        log.info("useridtoken was not observed during this run")


# ======================================================================
# TV OTP (pairing code)
# ======================================================================

def run_tv_otp(wvd_path: Path, new_msl: bool = False, no_verify: bool = False):
    log = logging.getLogger('ANDROID TV MSL')

    OUTPUT_DIR = ensure_output_dir()
    MSL_CACHE_PATH = OUTPUT_DIR / "msl_keys_cache.json"
    USER_ID_TOKEN_PATH = OUTPUT_DIR / "useridtoken.json"
    NETFLIX_COOKIES_PATH = OUTPUT_DIR / "netflix_cookies.json"

    MSL_HANDSHAKE_ENDPOINT = "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_tokens/%5E1.0.0/router"
    MSL_TV_ENDPOINT = "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_tokens/%5E1.0.0/router"
    PBO_CONFIG_ENDPOINT = "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_config/%5E1.0.0/router?ab_ui_ver=darwin&nrdapp_version=2025.2.3.0"

    DEVICE_TYPE = "NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019"
    DEVICE_MODEL = "NVIDIA_SHIELD Android TV"
    DEVICE_NAME = "SHIELD"
    ANDROID_BUILD_FINGERPRINT = "12.1.9-23083 R 2025.2 android-30-JPLAYER2 ninja_6==NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4040.2147:user/release-keys"
    APP_VERSION = "UI-release-20260408_44798-gibbon-r100-aui-nrdjs=v3.12.55"
    ESN = f"NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019-NVIDISHIELD=ANDROID=TV-11233-{generate_esn_random_suffix(64)}"

    IMPORTANT_COOKIE_NAMES = ("netflix-mfa-nonce", "NetflixId", "SecureNetflixId", "nfvdid", "gsid")

    QUERY_IDS = {
        "clcsLegacyMoneyballInitiateSession": {"id": "5152154d-6b61-4333-a738-92dc4ab712bd", "version": 102},
        "clcsLegacyMoneyballSubmit": {"id": "e8ef3234-6525-4975-8796-1299602e3297", "version": 102},
        "clcsScreenUpdate": {"id": "8daa70b0-fc21-4b5e-8c7e-ce0f31c8ca66", "version": 102},
        "useNavItemsQuery": {"id": "77a2fe81-a789-4b80-8c4c-0e962194cd09", "version": 102},
    }

    REQUEST_ARGS = [
        {"name": "deviceModel", "value": {"stringValue": DEVICE_MODEL}},
        {"name": "deviceName", "value": {"stringValue": DEVICE_NAME}},
        {"name": "deviceTypeOverride", "value": {"stringValue": DEVICE_TYPE}},
        {"name": "esn", "value": {"stringValue": ESN}},
        {"name": "fetchPartnerStrings", "value": {"booleanValue": False}},
        {"name": "isSuspendedMode", "value": {"booleanValue": False}},
        {"name": "nglVersion", "value": {"stringValue": "NGL_3"}},
        {"name": "resolution", "value": {"stringValue": "720p"}},
        {"name": "secureVLV", "value": {"stringValue": "true"}},
        {"name": "swVersion", "value": {"stringValue": "UI-release-20260408_44798-gibbon-sapphire-darwinql"}},
        {"name": "ui_trace_tag", "value": {"stringValue": "aui-ql"}},
        {"name": "sourceType", "value": {"stringValue": "2"}},
        {"name": "allocAutomation", "value": {"booleanValue": False}},
        {"name": "availableLocales", "value": {"stringValue": "zh,ta,ml,ko,te,gu,zh,kn,ur,ja"}},
        {"name": "suppScripts", "value": {"stringValue": "Hant,Tibt,Thai,Taml,Sinh,Orya,Mlym,Laoo,Armn,Geor,Kore,Telu,Beng,*,Hebr,Cyrl,Gujr,Hans,Deva,Guru,Cans,Ethi,Cher,Mymr,Knda,Grek,Latn,Arab,Jpan"}},
        {"name": "deviceLocale", "value": {"stringValue": "en-CA"}},
        {"name": "inAppSwVersion", "value": {"stringValue": APP_VERSION}},
        {"name": "appVersion", "value": {"stringValue": APP_VERSION}},
        {"name": "hasGooglePlayServiceOnTenfoot", "value": {"booleanValue": True}},
        {"name": "ab_ui_ver", "value": {"stringValue": "darwin"}},
        {"name": "application_name", "value": {"stringValue": "htmltvui"}},
        {"name": "application_v", "value": {"stringValue": APP_VERSION}},
        {"name": "dh", "value": {"stringValue": "720"}},
        {"name": "dw", "value": {"stringValue": "1280"}},
        {"name": "falcor_server", "value": {"stringValue": "0.1.0"}},
        {"name": "materialize", "value": {"booleanValue": True}},
        {"name": "mdxlib_version", "value": {"stringValue": "2025.2.3.0"}},
        {"name": "nrdapp_version", "value": {"stringValue": "2025.2.3.0"}},
        {"name": "nrdlib_version", "value": {"stringValue": "2025.2.3.0"}},
        {"name": "nrdp", "value": {"booleanValue": True}},
        {"name": "revision", "value": {"stringValue": "latest"}},
        {"name": "sdk_version", "value": {"stringValue": "2025.2.3.0"}},
        {"name": "sw_version", "value": {"stringValue": ANDROID_BUILD_FINGERPRINT}},
        {"name": "tag", "value": {"stringValue": "latest"}},
        {"name": "ui_sem_ver", "value": {"stringValue": "44798.0.0"}},
        {"name": "webapiConfigAppName", "value": {"stringValue": "htmltvui"}},
        {"name": "withSize", "value": {"booleanValue": True}},
    ]

    HEADERS = {
        "User-Agent": "Netflix/2025.2.3.0 (DEVTYPE=NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019; Milo=1.0.6315; build_number=6315; build_sha=a1b915de)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate,gzip",
        "X-Gibbon-Cache-Control": "no-cache",
        "X-AllowCompression": "true",
        "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
        "x-netflix.request.expiry.timeout": "12750",
        "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
        "x-netflix.client.nrdjs.version": "v3.12.55",
        "Content-Type": "application/json",
        "Content-Encoding": "msl_v1",
        "X-Netflix.Client.Request.Name": "mintCookies",
        "X-Netflix.Request.NonJson.Headers": "true",
        "X-Netflix.Request.Client.Context": '{"appstate":"foreground","reason":"unknown"}',
        "x-netflix.client.netjs.version": "3.0.5",
        "X-Netflix.request.attempt": "1",
        "x-netflix.esn": ESN,
    }

    PBO_COMMON = {
        "sdk": "2025.2.3.0",
        "platform": "2025.2.3.0",
        "application": ANDROID_BUILD_FINGERPRINT,
        "uiversion": APP_VERSION,
        "uiPlatform": "tv_ui",
        "clientVersion": "v3.12.55",
        "apkVersion": "12.1.9",
    }

    AUI_STARTUP_URL = (
        "https://secure.netflix.com/us/tvui/aui/20260408_44798/release_v8/auiStartup.js"
        "?q=source_type%3D2%26launchUID%3D{launch_uid}&dw=1280&dh=720&dar=16_9"
        "&reg=false&noMemberTarget=true"
    )

    ANDROID_CONFIG_URL = "https://androidtv.prod.cloud.netflix.com/android/ninja/config"
    ANDROID_CONFIG_PARAMS = {
        "responseFormat": "json",
        "progressive": "false",
        "method": "get",
        "routing": "redirect",
        "appType": "ninja",
        "mnf": "NVIDIA",
        "mId": "SHIELD=ANDROID=TV",
        "appVer": "23083",
        "appVerName": "12.1.9 build 23083",
        "api": "30",
        "modelgroup": "NVIDIASHIELDANDROIDTV2019",
        "oemmodel": "",
        "esn": ESN,
        "osBoard": "darcy",
        "osDevice": "mdarcy",
        "osDisplay": "RQ1A.210105.003.7825230_4040.2147",
        "osFingerprint": "NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4040.2147:user/release-keys",
        "osCpu": "armeabi-v7a",
        "osProduct": "mdarcy",
        "validation": "ninja_6",
        "ramSizeMB": "2946",
        "path": ["['deviceConfig']", "['fpConfig']"],
    }

    MSL_TRACE: List[Dict[str, Any]] = []

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = False

    launch_uid = str(uuid.uuid4())
    aui_referer = AUI_STARTUP_URL.format(launch_uid=launch_uid)
    runtime_referer = (
        "https://secure.netflix.com/us/tvui/ql/20260407/44745/release_v8/darwinBootstrap.js"
        "?startup_key=429c6159fd3e080b97d6df5bf5ce8e38b0ecc222773811cd12d8251aeea4a738"
        f"&device_type={DEVICE_TYPE}"
        f"&e={quote(ESN, safe='')}"
        "&env=prod&fromNM=true&nm_prefetch=true&nrdapp_version=2025.2.3.0&plain=true&script_engine=v8"
        f"&sessionId={uuid.uuid4()}&authType=login&authclid={uuid.uuid4()}"
        f"&q=source_type%3D2%26launchUID%3D{launch_uid}%26source_type_payload%3D"
    )

    log.info("Fetching nfvdid from Android TV config endpoint")
    response = session.get(
        ANDROID_CONFIG_URL,
        params=ANDROID_CONFIG_PARAMS,
        headers={
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SHIELD Android TV Build/RQ1A.210105.003)",
            "Accept": "*/*",
            "X-Netflix.Client.Request.Name": "androidninjaconfig",
            "X-Netflix.Request.Client.Context": '{"appState":"foreground"}',
        },
        timeout=30,
    )
    log.info("Config response HTTP %d", response.status_code)
    if response.status_code != 200:
        log.warning("Config request failed: %s", response.text[:500])
    nfvdid = session.cookies.get("nfvdid")
    log.info("nfvdid: %s", (nfvdid[:60] + "...") if nfvdid else "not received")

    log.info("Bootstrap TV UI")
    try:
        session.headers.clear()
        ua = HEADERS["User-Agent"]
        session.get(
            aui_referer,
            headers={"User-Agent": ua, "Accept": "application/javascript,text/javascript,application/x-javascript"},
            timeout=30,
        )
        session.get(
            "https://nrdp.prod.cloud.netflix.com/healthcheck",
            headers={
                "User-Agent": ua,
                "Accept": "*/*",
                "x-netflix.context.sdk-version": "2025.2.3.0",
                "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
                "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
                "X-Netflix.Request.NonJson.Headers": "true",
                "x-netflix.client.netjs.version": "3.0.5",
                "X-Netflix.request.attempt": "1",
                "Referer": aui_referer,
            },
            timeout=30,
        )
        log.info("Bootstrap OK")
    except Exception as exc:
        log.warning("Bootstrap failed: %s", exc)

    log.info("pre-mint pathEvaluator")
    try:
        params = [
            ("ab_ui_ver", "darwin"),
            ("application_name", "htmltvui"),
            ("application_v", APP_VERSION),
            ("dh", "720"),
            ("dw", "1280"),
            ("falcor_server", "0.1.0"),
            ("materialize", "true"),
            ("mdxlib_version", "2025.2.3.0"),
            ("nrdapp_version", "2025.2.3.0"),
            ("nrdlib_version", "2025.2.3.0"),
            ("nrdp", "true"),
            ("revision", "latest"),
            ("sdk_version", "2025.2.3.0"),
            ("sw_version", ANDROID_BUILD_FINGERPRINT),
            ("tag", "latest"),
            ("ui_sem_ver", "44798.0.0"),
            ("webapiConfigAppName", "htmltvui"),
            ("withSize", "true"),
            ("availableLocales", "zh,ta,ml,ko,te,gu,zh,kn,ur,ja"),
            ("deviceLocale", "en-CA"),
            ("deviceModel", DEVICE_MODEL),
            ("deviceName", DEVICE_NAME),
            ("deviceTypeOverride", DEVICE_TYPE),
            ("esn", ESN),
            ("hasGooglePlayServiceOnTenfoot", "true"),
            ("isSuspendedMode", "false"),
            ("netflixClientPlatform", "tenfootMDS"),
            ("nglVersion", "NGL_3"),
            ("resolution", "720p"),
            ("secureVLV", "true"),
            ("suppScripts", "Hant,Tibt,Thai,Taml,Sinh,Orya,Mlym,Laoo,Armn,Geor,Kore,Telu,Beng,*,Hebr,Cyrl,Gujr,Hans,Deva,Guru,Cans,Ethi,Cher,Mymr,Knda,Grek,Latn,Arab,Jpan"),
            ("swVersion", "UI-release-20260408_44798-gibbon-sapphire-darwinql"),
            ("ui_trace_tag", "aui-ql"),
            ("inAppSwVersion", APP_VERSION),
        ]
        params.extend([
            ("path", '["aui",["appconfig","partnerData","requestContext","userContext"]]'),
            ("path", '["aui","truths",["project.bao.ui.enabled","tvui.aui.bugsnag.enabled","tvui.aui.clcs.enabled","tvui.aui.improvedPollingModeMismatchCheck.enabled","tvui.aui.partner.bundle.server.driven.tou.enabled","tvui.aui.partner.fullHd.enabled","tvui.aui.preApp.enabled","tvui.aui.showDeviceSupportMenu.enabled","tvui.aui.speech.enabled","tvui.aui.welcomeContentLandingPointer.enabled","tvui.gibbon.aui.enableRouteTransition.enabled","tvui.gibbon.aui.fetchAllTranslationsWithGql","tvui.gibbon.aui.fetchAllTranslationsWithGqlVerboseLogging","tvui.gibbon.aui.flushFontsOnStartup","tvui.gibbon.aui.useNetflixSans"]]'),
            ("json", "true"),
            ("method", "get"),
            ("seed", "0.7002274648406179"),
        ])

        session.headers.clear()
        session.headers.update(
            {
                "User-Agent": HEADERS["User-Agent"],
                "Accept": "*/*",
                "Accept-Encoding": "deflate,gzip",
                "x-netflix.context.sdk-version": "2025.2.3.0",
                "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
                "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
                "X-Gibbon-Cache-Control": "no-cache",
                "X-Netflix.request.expiry.timeout": "20000",
                "X-Netflix.Client.Request.Name": "ui/falcorUnclassified",
                "X-Netflix.Request.Routing": '{"control_tag":"auinqtv","path":"/nq/aui/endpoint/%5E1.0.0-tv/pathEvaluator"}',
                "x-netflix.client.last-interacted-days": "0",
                "X-Netflix.Request.NonJson.Headers": "true",
                "x-netflix.client.netjs.version": "3.0.5",
                "X-Netflix.request.attempt": "1",
                "Referer": aui_referer,
            }
        )

        url = "https://api-global.netflix.com/aui/pathEvaluator/tv/latest?" + urlencode(params, doseq=True)
        response = session.get(url, timeout=30)
        if response.status_code != 200:
            raise RuntimeError(f"pathEvaluator failed: HTTP {response.status_code} {response.text[:500]}")
        log.info("pre-mint pathEvaluator OK")
    except Exception as exc:
        log.warning("pre-mint pathEvaluator failed: %s", exc)

    log.info("MSL Widevine key exchange + mintCookies")
    msl = None
    try:
        if not wvd_path.exists():
            raise FileNotFoundError(f"Missing WVD file: {wvd_path}")
        device = WidevineDevice.load(wvd_path)
        cdm = WidevineCdm.from_device(device)
        cdm_device = str(wvd_path)

        cookies_for_handshake = {}
        nfvdid_cookie = session.cookies.get("nfvdid")
        if nfvdid_cookie:
            cookies_for_handshake["nfvdid"] = nfvdid_cookie

        log.info("Performing MSL Widevine key exchange")
        session.headers.clear()

        msl_headers = MSL_TV.build_request_headers(
            request_name="mintCookies",
            user_agent=HEADERS["User-Agent"],
            referer=None,
            esn=ESN,
            expiry_timeout=12750,
            extra_headers={
                "Accept-Encoding": "deflate,gzip",
                "Content-Encoding": "msl_v1",
                "X-Gibbon-Cache-Control": "no-cache",
                "X-AllowCompression": "true",
                "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
                "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
                "x-netflix.esn": ESN,
            },
        )

        keys = MSL_TV.handshake(
            msl_keys_path=str(MSL_CACHE_PATH),
            session=session,
            sender=ESN,
            cdm=cdm,
            cdm_device=cdm_device,
            new_msl=False,
            cookies=cookies_for_handshake,
            drm="widevine",
            endpoint=MSL_HANDSHAKE_ENDPOINT,
            headers=msl_headers,
        )

        if not keys or not keys.mastertoken:
            raise RuntimeError("TV_MSL handshake did not return a valid master token")

        token_data = json.loads(base64.b64decode(keys.mastertoken["tokendata"]).decode("utf-8"))
        log.info("Mastertoken acquired seq=%d serial=%d", token_data["sequencenumber"], token_data["serialnumber"])

        msl = MSL_TV(
            session=session,
            keys=keys,
            message_id=random.randint(0, 2**52),
            sender=ESN,
            user_auth=None,
            drm="widevine",
        )

        if not (msl.keys and msl.keys.mastertoken and msl.keys.encryption and msl.keys.sign):
            cached_keys = MSL_TV.load_cache_data(MSL_CACHE_PATH)
            if cached_keys is None:
                raise RuntimeError("MSL cache is empty or expired and the active MSL instance is unusable")
            msl = MSL_TV(
                session=msl.session,
                keys=cached_keys,
                message_id=random.randint(0, 2**52),
                sender=ESN,
                user_auth=None,
                drm="widevine",
            )

        msl.session.headers.clear()
        mint_headers = MSL_TV.build_request_headers(
            request_name="mintCookies",
            user_agent=HEADERS["User-Agent"],
            referer=runtime_referer,
            esn=ESN,
            expiry_timeout=12750,
            extra_headers={
                "Accept-Encoding": "deflate,gzip",
                "Content-Encoding": "msl_v1",
                "X-Gibbon-Cache-Control": "no-cache",
                "X-AllowCompression": "true",
                "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
                "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
                "x-netflix.esn": ESN,
            },
        )

        header, payload = msl.send_message(
            endpoint=MSL_TV_ENDPOINT,
            params={},
            application_data={
                "version": 2,
                "common": dict(PBO_COMMON),
                "url": "/mintCookies",
                "languages": ["en-CA"],
                "params": {},
            },
            headers=mint_headers,
        )

        payload_type, parsed_payload, text_payload = parse_msl_payload(payload)

        key_id = extract_key_id_from_mastertoken(msl.keys.mastertoken) if msl.keys.mastertoken else ""

        event = build_msl_trace_event(
            msl.message_id, key_id, payload_type, parsed_payload, text_payload,
            extra_fields={"_iv": None, "_ciphertextLen": None, "_plaintextLen": len(text_payload.encode("utf-8")) if isinstance(text_payload, str) else None},
        )

        useridtoken = extract_useridtoken_from_payload(parsed_payload, payload)

        if useridtoken:
            USER_ID_TOKEN_PATH.write_text(json.dumps(useridtoken, indent=2), encoding="utf-8")
            log.info("useridtoken saved to %s", USER_ID_TOKEN_PATH)

        MSL_TRACE.append(event)

        cookie_names = [cookie.name for cookie in msl.session.cookies]
        log.info("Cookies after mintCookies: %s", cookie_names)
        if "NetflixId" not in cookie_names:
            log.warning("mintCookies did not return NetflixId; payload=%s", str(payload)[:500])

        log.info("mintCookies payload type: %s", event.get("_dataType"))
        log.info("NetflixId: %s", f"{session.cookies.get('NetflixId', 'N/A')[:60]}...")
        log.info("SecureNetflixId: %s", f"{session.cookies.get('SecureNetflixId', 'N/A')[:60]}...")

        try:
            params = [
                ("ab_ui_ver", "darwin"),
                ("application_name", "htmltvui"),
                ("application_v", APP_VERSION),
                ("dh", "720"),
                ("dw", "1280"),
                ("falcor_server", "0.1.0"),
                ("materialize", "true"),
                ("mdxlib_version", "2025.2.3.0"),
                ("nrdapp_version", "2025.2.3.0"),
                ("nrdlib_version", "2025.2.3.0"),
                ("nrdp", "true"),
                ("revision", "latest"),
                ("sdk_version", "2025.2.3.0"),
                ("sw_version", ANDROID_BUILD_FINGERPRINT),
                ("tag", "latest"),
                ("ui_sem_ver", "44798.0.0"),
                ("webapiConfigAppName", "htmltvui"),
                ("withSize", "true"),
                ("availableLocales", "zh,ta,ml,ko,te,gu,zh,kn,ur,ja"),
                ("deviceLocale", "en-CA"),
                ("deviceModel", DEVICE_MODEL),
                ("deviceName", DEVICE_NAME),
                ("deviceTypeOverride", DEVICE_TYPE),
                ("esn", ESN),
                ("hasGooglePlayServiceOnTenfoot", "true"),
                ("isSuspendedMode", "false"),
                ("netflixClientPlatform", "tenfootMDS"),
                ("nglVersion", "NGL_3"),
                ("resolution", "720p"),
                ("secureVLV", "true"),
                ("suppScripts", "Hant,Tibt,Thai,Taml,Sinh,Orya,Mlym,Laoo,Armn,Geor,Kore,Telu,Beng,*,Hebr,Cyrl,Gujr,Hans,Deva,Guru,Cans,Ethi,Cher,Mymr,Knda,Grek,Latn,Arab,Jpan"),
                ("swVersion", "UI-release-20260408_44798-gibbon-sapphire-darwinql"),
                ("ui_trace_tag", "aui-ql"),
                ("inAppSwVersion", APP_VERSION),
            ]
            params.extend([
                ("path", '["aui","unsupportedLanguageImage"]'),
                ("path", '["aui","countryProps","cross-platform-ui",["cancelBundleUponPartnerPause","preTaxDisclaimerOnPrice","show_kr_footer_disclaimer","show_paid_button_label_when_not_free","signup_tou_checkbox"]]'),
                ("path", '["aui","countryProps","tvui",["shouldReorderName","showPrivacyStatementText"]]'),
                ("json", "true"),
                ("method", "get"),
                ("seed", "0.6825750436070701"),
            ])

            session.headers.clear()
            session.headers.update(
                {
                    "User-Agent": HEADERS["User-Agent"],
                    "Accept": "*/*",
                    "Accept-Encoding": "deflate,gzip",
                    "x-netflix.context.sdk-version": "2025.2.3.0",
                    "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
                    "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
                    "X-Gibbon-Cache-Control": "no-cache",
                    "X-Netflix.request.expiry.timeout": "20000",
                    "X-Netflix.Client.Request.Name": "ui/falcorUnclassified",
                    "X-Netflix.Request.Routing": '{"control_tag":"auinqtv","path":"/nq/aui/endpoint/%5E1.0.0-tv/pathEvaluator"}',
                    "x-netflix.client.last-interacted-days": "0",
                    "X-Netflix.Request.NonJson.Headers": "true",
                    "x-netflix.client.netjs.version": "3.0.5",
                    "X-Netflix.request.attempt": "1",
                    "Referer": aui_referer,
                }
            )

            url = "https://api-global.netflix.com/aui/pathEvaluator/tv/latest?" + urlencode(params, doseq=True)
            response = session.get(url, timeout=30)
            if response.status_code != 200:
                raise RuntimeError(f"pathEvaluator failed: HTTP {response.status_code} {response.text[:500]}")
            log.info("post-mint pathEvaluator OK")
        except Exception as exc:
            log.warning("post-mint pathEvaluator failed: %s", exc)

        try:
            msl.session.headers.clear()
            config_headers = MSL_TV.build_request_headers(
                request_name="config",
                user_agent=HEADERS["User-Agent"],
                referer=aui_referer,
                esn=ESN,
                expiry_timeout=12750,
                extra_headers={
                    "Accept-Encoding": "deflate,gzip",
                    "Content-Encoding": "msl_v1",
                    "X-Gibbon-Cache-Control": "no-cache",
                    "X-AllowCompression": "true",
                    "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
                    "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
                    "x-netflix.esn": ESN,
                },
            )
            msl.send_message(
                endpoint=PBO_CONFIG_ENDPOINT,
                params={},
                application_data={"method": "config", "params": {}},
                headers=config_headers,
            )
            log.info("pbo_config OK")
        except Exception as exc:
            log.warning("pbo_config failed: %s", exc)

        for request_name, route, referer_to_use in [
            ("getPartnerToken", "/getPartnerToken", aui_referer),
            ("ping", "/ping", runtime_referer),
            ("getPartnerToken", "/getPartnerToken", runtime_referer),
        ]:
            try:
                if not (msl.keys and msl.keys.mastertoken and msl.keys.encryption and msl.keys.sign):
                    cached_keys = MSL_TV.load_cache_data(MSL_CACHE_PATH)
                    if cached_keys is None:
                        raise RuntimeError("MSL cache is empty or expired and the active MSL instance is unusable")
                    msl = MSL_TV(
                        session=msl.session,
                        keys=cached_keys,
                        message_id=random.randint(0, 2**52),
                        sender=ESN,
                        user_auth=None,
                        drm="widevine",
                    )

                msl.session.headers.clear()
                optional_headers = MSL_TV.build_request_headers(
                    request_name=request_name,
                    user_agent=HEADERS["User-Agent"],
                    referer=referer_to_use,
                    esn=ESN,
                    expiry_timeout=12750,
                    extra_headers={
                        "Accept-Encoding": "deflate,gzip",
                        "Content-Encoding": "msl_v1",
                        "X-Gibbon-Cache-Control": "no-cache",
                        "X-AllowCompression": "true",
                        "X-Client-Request-Id": str(random.randint(10**17, 10**18 - 1)),
                        "X-DeviceModel": quote(DEVICE_MODEL, safe=""),
                        "x-netflix.esn": ESN,
                    },
                )

                header, payload = msl.send_message(
                    endpoint=MSL_TV_ENDPOINT,
                    params={},
                    application_data={
                        "version": 2,
                        "common": dict(PBO_COMMON),
                        "url": route,
                        "languages": ["en-CA"],
                        "params": {},
                    },
                    headers=optional_headers,
                )

                payload_type, parsed_payload, text_payload = parse_msl_payload(payload)

                key_id = extract_key_id_from_mastertoken(msl.keys.mastertoken) if msl.keys.mastertoken else ""

                event = build_msl_trace_event(
                    msl.message_id, key_id, payload_type, parsed_payload, text_payload,
                    extra_fields={"_iv": None, "_ciphertextLen": None, "_plaintextLen": len(text_payload.encode("utf-8")) if isinstance(text_payload, str) else None},
                )

                useridtoken = extract_useridtoken_from_payload(parsed_payload, payload)

                if useridtoken:
                    USER_ID_TOKEN_PATH.write_text(json.dumps(useridtoken, indent=2), encoding="utf-8")
                    log.info("useridtoken saved to %s", USER_ID_TOKEN_PATH)

                MSL_TRACE.append(event)
                log.info("PBO route %s completed, payload type=%s", route, event.get("_dataType"))
            except Exception as exc:
                log.warning("Optional PBO route %s failed: %s", route, exc)

    except Exception as exc:
        log.warning("MSL setup or mintCookies failed: %s", exc)
        log.warning("Continuing without guaranteed MSL cookies")

    log.info("Initiating CLCS login session")
    trace_uuid = str(uuid.uuid4())
    session.headers.clear()
    session.headers.update(
        {
            "Language": "en-CA,en-US,en",
            "User-Agent": HEADERS["User-Agent"],
            "Accept": "*/*",
            "Accept-Language": "en-CA,en-US,en",
            "Accept-Encoding": "deflate,gzip",
            "Content-Type": "application/json",
            "Connection": "Keep-Alive",
            "x-netflix.context.sdk-version": "2025.2.3.0",
            "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
            "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
            "X-Gibbon-Cache-Control": "no-cache",
            "x-netflix.request.expiry.timeout": "20000",
            "x-Netflix.context.app-version": "44798.0.0",
            "x-Netflix.context.cloud-games-enabled": "false",
            "X-Netflix.context.device-height": "720",
            "x-Netflix.context.device-image-capability": "scalingFactor=1.0;supportedFormats=jpg,png,astc",
            "x-Netflix.context.dt": "",
            "x-Netflix.context.hawkins-version": "5.13.0",
            "X-Netflix.context.locales": '["en-CA","en-US","en"]',
            "X-Netflix.context.ui-flavor": "photon",
            "X-Netflix.request.device-model": quote(DEVICE_MODEL, safe=""),
            "X-Netflix.request.is-suspended": "false",
            "x-netflix.request.clcs.bucket": "high",
            "X-Netflix.request.toplevel.uuid": trace_uuid,
            "X-Netflix.tracing.cl.userActionId": trace_uuid,
            "x-netflix.client.last-interacted-days": "0",
            "X-Netflix.Request.NonJson.Headers": "true",
            "x-netflix.client.netjs.version": "3.0.5",
            "X-Netflix.request.attempt": "1",
            "X-Netflix.context.operation-name": "clcsLegacyMoneyballInitiateSession",
            "Referer": aui_referer,
        }
    )

    cookie_values: List[str] = []
    graphql_url = (
        "https://nrdp.prod.cloud.netflix.com/graphql"
        f"?device_type={DEVICE_TYPE}"
        f"&esn={quote(ESN, safe='')}"
        f"&o=clcsLegacyMoneyballInitiateSession"
    )
    body = {
        "extensions": {"persistedQuery": QUERY_IDS["clcsLegacyMoneyballInitiateSession"]},
        "operationName": "clcsLegacyMoneyballInitiateSession",
        "variables": {
            "action": "",
            "flow": "tenfootSignUp",
            "hasGooglePlayService": False,
            "imageFormat": "ASTC",
            "inputFields": [],
            "legacyRequestArguments": REQUEST_ARGS,
            "mode": "none",
            "resolutionMode": "TV_720P",
            "supportedVideoFormat": "mp4",
        },
    }
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    headers = dict(session.headers)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(graphql_url, json=body, headers=headers, timeout=30)

    apply_set_cookie_headers(session, response, cookie_values)

    dedupe_important_cookies(session, IMPORTANT_COOKIE_NAMES)

    response.raise_for_status()
    init_data = response.json()
    if "errors" in init_data:
        raise RuntimeError(json.dumps(init_data["errors"], indent=2))

    flow = parse_flow_data(init_data)

    flow_session_id = flow.get("flowSessionId", "")
    clcs_session_id = flow.get("clcsSessionId", "")
    rendition_id = flow.get("renditionId", "")

    log.info("Flow session: %s", flow_session_id)
    log.info("CLCS session: %s", clcs_session_id)
    log.info("Mode: %s | Status: %s", flow.get("mode"), flow.get("membershipStatus"))

    if not flow_session_id or not clcs_session_id:
        raise RuntimeError(f"Failed to extract flow/session IDs from response: {json.dumps(init_data)[:800]}")

    log.info("Navigating to sign-in screen")
    trace_uuid = str(uuid.uuid4())
    session.headers.clear()
    session.headers.update(
        {
            "Language": "en-CA,en-US,en",
            "User-Agent": HEADERS["User-Agent"],
            "Accept": "*/*",
            "Accept-Language": "en-CA,en-US,en",
            "Accept-Encoding": "deflate,gzip",
            "Content-Type": "application/json",
            "Connection": "Keep-Alive",
            "x-netflix.context.sdk-version": "2025.2.3.0",
            "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
            "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
            "X-Gibbon-Cache-Control": "no-cache",
            "x-netflix.request.expiry.timeout": "20000",
            "x-Netflix.context.app-version": "44798.0.0",
            "x-Netflix.context.cloud-games-enabled": "false",
            "X-Netflix.context.device-height": "720",
            "x-Netflix.context.device-image-capability": "scalingFactor=1.0;supportedFormats=jpg,png,astc",
            "x-Netflix.context.dt": "",
            "x-Netflix.context.hawkins-version": "5.13.0",
            "X-Netflix.context.locales": '["en-CA","en-US","en"]',
            "X-Netflix.context.ui-flavor": "photon",
            "X-Netflix.request.device-model": quote(DEVICE_MODEL, safe=""),
            "X-Netflix.request.is-suspended": "false",
            "x-netflix.request.clcs.bucket": "high",
            "X-Netflix.request.toplevel.uuid": trace_uuid,
            "X-Netflix.tracing.cl.userActionId": trace_uuid,
            "x-netflix.client.last-interacted-days": "0",
            "X-Netflix.Request.NonJson.Headers": "true",
            "x-netflix.client.netjs.version": "3.0.5",
            "X-Netflix.request.attempt": "1",
            "X-Netflix.context.operation-name": "clcsLegacyMoneyballSubmit",
            "Referer": aui_referer,
        }
    )

    request_args_dict = request_args_to_dict(REQUEST_ARGS)

    server_state = json.dumps(
        {
            "realm": "moneyball",
            "flow": "tenfootSignUp",
            "mode": "welcomeContentLanding",
            "flowSessionId": flow_session_id,
            "requestArguments": request_args_dict,
            "clcsSessionId": clcs_session_id,
        },
        separators=(",", ":"),
    )

    cookie_values = []
    graphql_url = (
        "https://nrdp.prod.cloud.netflix.com/graphql"
        f"?device_type={DEVICE_TYPE}"
        f"&esn={quote(ESN, safe='')}"
        f"&o=clcsLegacyMoneyballSubmit"
    )
    body = {
        "extensions": {"persistedQuery": QUERY_IDS["clcsLegacyMoneyballSubmit"]},
        "operationName": "clcsLegacyMoneyballSubmit",
        "variables": {
            "action": "signInAction",
            "flow": "tenfootSignUp",
            "flwssn": flow_session_id,
            "imageFormat": "ASTC",
            "inputFields": [],
            "mode": "welcomeContentLanding",
            "requestArguments": REQUEST_ARGS,
            "resolutionMode": "TV_720P",
            "serverState": server_state,
        },
    }
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    headers = dict(session.headers)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(graphql_url, json=body, headers=headers, timeout=30)

    apply_set_cookie_headers(session, response, cookie_values)

    dedupe_important_cookies(session, IMPORTANT_COOKIE_NAMES)

    response.raise_for_status()
    submit_data = response.json()

    flow2 = parse_flow_data(submit_data)

    rendition_id = flow2.get("renditionId", rendition_id)
    log.info("Rendition: %s", rendition_id)

    nonce = session.cookies.get("netflix-mfa-nonce")
    if nonce:
        log.info("netflix-mfa-nonce: %s", f"{nonce[:80]}...")
    else:
        log.warning("netflix-mfa-nonce was not present after signInAction")

    log.info("Using phone / TV code sign-in")
    text = json.dumps(submit_data, ensure_ascii=False)
    tvcode_info: Dict[str, str] = {}

    match = re.search(r'"previousRendezvousCode":"(\d+)"', text)
    if match:
        tvcode_info["code"] = match.group(1)
    else:
        match = re.search(r'(?<!\d)(\d{8})(?!\d)', text)
        if match:
            tvcode_info["code"] = match.group(1)

    for key in ("tvLoginRendezvousId", "moneyballSessionUuid"):
        found = re.search(rf'"{key}".*?"value":"([^"]+)"', text)
        if found:
            tvcode_info[key] = found.group(1)

    code = tvcode_info.get("code", "")
    if not code:
        raise RuntimeError("Could not find the TV code in the sign-in response")

    log.info("Go to: https://www.netflix.com/tv2")
    log.info("Enter code: %s", code)
    log.info("Polling for activation every 5 seconds")

    continue_action = None
    last_poll_data: Dict[str, Any] = {}

    while True:
        time.sleep(5)
        log.info("Polling activation status...")

        trace_uuid = str(uuid.uuid4())
        session.headers.clear()
        session.headers.update(
            {
                "Language": "en-CA,en-US,en",
                "User-Agent": HEADERS["User-Agent"],
                "Accept": "*/*",
                "Accept-Language": "en-CA,en-US,en",
                "Accept-Encoding": "deflate,gzip",
                "Content-Type": "application/json",
                "Connection": "Keep-Alive",
                "x-netflix.context.sdk-version": "2025.2.3.0",
                "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
                "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
                "X-Gibbon-Cache-Control": "no-cache",
                "x-netflix.request.expiry.timeout": "20000",
                "x-Netflix.context.app-version": "44798.0.0",
                "x-Netflix.context.cloud-games-enabled": "false",
                "X-Netflix.context.device-height": "720",
                "x-Netflix.context.device-image-capability": "scalingFactor=1.0;supportedFormats=jpg,png,astc",
                "x-Netflix.context.dt": "",
                "x-Netflix.context.hawkins-version": "5.13.0",
                "X-Netflix.context.locales": '["en-CA","en-US","en"]',
                "X-Netflix.context.ui-flavor": "photon",
                "X-Netflix.request.device-model": quote(DEVICE_MODEL, safe=""),
                "X-Netflix.request.is-suspended": "false",
                "x-netflix.request.clcs.bucket": "high",
                "X-Netflix.request.toplevel.uuid": trace_uuid,
                "X-Netflix.tracing.cl.userActionId": trace_uuid,
                "x-netflix.client.last-interacted-days": "0",
                "X-Netflix.Request.NonJson.Headers": "true",
                "x-netflix.client.netjs.version": "3.0.5",
                "X-Netflix.request.attempt": "1",
                "X-Netflix.context.operation-name": "clcsScreenUpdate",
                "Referer": aui_referer,
            }
        )

        server_state = json.dumps(
            {
                "realm": "moneyball",
                "flow": "tenfootSignUp",
                "mode": "webSignIn",
                "flowSessionId": flow_session_id,
                "requestArguments": request_args_dict,
                "clcsSessionId": clcs_session_id,
            },
            separators=(",", ":"),
        )

        cookie_values = []
        graphql_url = (
            "https://nrdp.prod.cloud.netflix.com/graphql"
            f"?device_type={DEVICE_TYPE}"
            f"&esn={quote(ESN, safe='')}"
            f"&o=clcsScreenUpdate"
        )
        body = {
            "extensions": {"persistedQuery": QUERY_IDS["clcsScreenUpdate"]},
            "operationName": "clcsScreenUpdate",
            "variables": {
                "imageFormat": "PNG",
                "resolutionMode": "TV_720P",
                "serverScreenUpdate": json.dumps(
                    {
                        "realm": "custom",
                        "metadata": {"pollInterval": 5000, "previousRendezvousCode": code},
                        "name": "tenfootSignUp.loginRendezvous.polling",
                        "referrerRenditionId": rendition_id,
                    },
                    separators=(",", ":"),
                ),
                "serverState": server_state,
            },
        }
        cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
        headers = dict(session.headers)
        if cookie_header:
            headers["Cookie"] = cookie_header

        response = session.post(graphql_url, json=body, headers=headers, timeout=30)

        apply_set_cookie_headers(session, response, cookie_values)
        dedupe_important_cookies(session, IMPORTANT_COOKIE_NAMES)

        response.raise_for_status()
        poll_data = response.json()
        last_poll_data = poll_data

        continue_action = None
        stack = [poll_data]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                server_screen_update = value.get("serverScreenUpdate")
                if isinstance(server_screen_update, str) and '"action":"continueAction"' in server_screen_update:
                    try:
                        continue_action = json.loads(server_screen_update)
                        break
                    except Exception:
                        pass
                for child in value.values():
                    stack.append(child)
            elif isinstance(value, list):
                for item in value:
                    stack.append(item)

        if continue_action:
            log.info("Activation detected")
            break

        text = json.dumps(poll_data, ensure_ascii=False)
        updated = ""
        match = re.search(r'"previousRendezvousCode":"(\d+)"', text)
        if match:
            updated = match.group(1)
        else:
            match = re.search(r'(?<!\d)(\d{8})(?!\d)', text)
            if match:
                updated = match.group(1)

        if updated and updated != code:
            code = updated
            log.info("Code updated: %s", code)

    log.info("Completing OTP sign-in")
    trace_uuid = str(uuid.uuid4())
    session.headers.clear()
    session.headers.update(
        {
            "Language": "en-CA,en-US,en",
            "User-Agent": HEADERS["User-Agent"],
            "Accept": "*/*",
            "Accept-Language": "en-CA,en-US,en",
            "Accept-Encoding": "deflate,gzip",
            "Content-Type": "application/json",
            "Connection": "Keep-Alive",
            "x-netflix.context.sdk-version": "2025.2.3.0",
            "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
            "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
            "X-Gibbon-Cache-Control": "no-cache",
            "x-netflix.request.expiry.timeout": "20000",
            "x-Netflix.context.app-version": "44798.0.0",
            "x-Netflix.context.cloud-games-enabled": "false",
            "X-Netflix.context.device-height": "720",
            "x-Netflix.context.device-image-capability": "scalingFactor=1.0;supportedFormats=jpg,png,astc",
            "x-Netflix.context.dt": "",
            "x-Netflix.context.hawkins-version": "5.13.0",
            "X-Netflix.context.locales": '["en-CA","en-US","en"]',
            "X-Netflix.context.ui-flavor": "photon",
            "X-Netflix.request.device-model": quote(DEVICE_MODEL, safe=""),
            "X-Netflix.request.is-suspended": "false",
            "x-netflix.request.clcs.bucket": "high",
            "X-Netflix.request.toplevel.uuid": trace_uuid,
            "X-Netflix.tracing.cl.userActionId": trace_uuid,
            "x-netflix.client.last-interacted-days": "0",
            "X-Netflix.Request.NonJson.Headers": "true",
            "x-netflix.client.netjs.version": "3.0.5",
            "X-Netflix.request.attempt": "1",
            "X-Netflix.context.operation-name": "clcsScreenUpdate",
            "Referer": aui_referer,
        }
    )

    server_state = json.dumps(
        {
            "realm": "moneyball",
            "flow": "tenfootSignUp",
            "mode": "webSignIn",
            "flowSessionId": flow_session_id,
            "requestArguments": request_args_dict,
            "clcsSessionId": clcs_session_id,
        },
        separators=(",", ":"),
    )

    cookie_values = []
    graphql_url = (
        "https://nrdp.prod.cloud.netflix.com/graphql"
        f"?device_type={DEVICE_TYPE}"
        f"&esn={quote(ESN, safe='')}"
        f"&o=clcsScreenUpdate"
    )
    body = {
        "extensions": {"persistedQuery": QUERY_IDS["clcsScreenUpdate"]},
        "operationName": "clcsScreenUpdate",
        "variables": {
            "imageFormat": "PNG",
            "inputFields": [],
            "resolutionMode": "TV_720P",
            "serverScreenUpdate": json.dumps(continue_action, separators=(",", ":")) if continue_action else json.dumps(
                {
                    "realm": "moneyball",
                    "action": "continueAction",
                    "loggingAction": "Submitted",
                    "loggingCommand": "SubmitCommand",
                    "referrerRenditionId": rendition_id,
                },
                separators=(",", ":"),
            ),
            "serverState": server_state,
        },
    }
    cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
    headers = dict(session.headers)
    if cookie_header:
        headers["Cookie"] = cookie_header

    response = session.post(graphql_url, json=body, headers=headers, timeout=30)

    apply_set_cookie_headers(session, response, cookie_values)

    dedupe_important_cookies(session, IMPORTANT_COOKIE_NAMES)

    response.raise_for_status()
    login_data = response.json() 

    flow_result = parse_flow_data(login_data)

    membership = flow_result.get("membershipStatus", "")
    log.info("Membership: %s", membership)

    if membership != "CURRENT_MEMBER":
        log.warning("Expected CURRENT_MEMBER, got: %s", membership)
        errors = login_data.get("errors")
        if errors:
            log.warning("Structured errors: %s", json.dumps(errors, ensure_ascii=False))
        log.warning("Response: %s", json.dumps(login_data)[:1500])

    if membership == "CURRENT_MEMBER" and session.cookies.get("NetflixId") and not session.cookies.get("gsid"):
        log.info("Fetching post-login gsid cookie")
        trace_uuid = str(uuid.uuid4())
        session.headers.clear()
        session.headers.update(
            {
                "Language": "en-CA,en-US,en",
                "User-Agent": HEADERS["User-Agent"],
                "Accept": "*/*",
                "Accept-Language": "en-CA,en-US,en",
                "Accept-Encoding": "deflate,gzip",
                "Content-Type": "application/json",
                "Connection": "Keep-Alive",
                "x-netflix.context.sdk-version": "2025.2.3.0",
                "X-Netflix.request.id": generate_hex_id(32, uppercase=True),
                "X-Netflix.Request.Client.Context": '{"canvas":"OTHER","feature":"OTHER","appView":"appLoading","appstate":"foreground","reason":"unknown"}',
                "X-Gibbon-Cache-Control": "no-cache",
                "x-netflix.request.expiry.timeout": "20000",
                "x-Netflix.context.app-version": "44798.0.0",
                "x-Netflix.context.cloud-games-enabled": "false",
                "X-Netflix.context.device-height": "720",
                "x-Netflix.context.device-image-capability": "scalingFactor=1.0;supportedFormats=jpg,png,astc",
                "x-Netflix.context.dt": "",
                "x-Netflix.context.hawkins-version": "5.13.0",
                "X-Netflix.context.locales": '["en-CA","en-US","en"]',
                "X-Netflix.context.ui-flavor": "photon",
                "X-Netflix.request.device-model": quote(DEVICE_MODEL, safe=""),
                "X-Netflix.request.is-suspended": "false",
                "x-netflix.request.clcs.bucket": "high",
                "X-Netflix.request.toplevel.uuid": trace_uuid,
                "X-Netflix.tracing.cl.userActionId": trace_uuid,
                "x-netflix.client.last-interacted-days": "0",
                "X-Netflix.Request.NonJson.Headers": "true",
                "x-netflix.client.netjs.version": "3.0.5",
                "X-Netflix.request.attempt": "1",
                "X-Netflix.context.operation-name": "useNavItemsQuery",
                "Referer": runtime_referer,
            }
        )

        cookie_values = []
        graphql_url = "https://nrdp.prod.cloud.netflix.com/graphql?o=useNavItemsQuery"
        body = {
            "extensions": {"persistedQuery": QUERY_IDS["useNavItemsQuery"]},
            "operationName": "useNavItemsQuery",
            "query": None,
            "variables": {
                "artworkCapability": {
                    "artworkResolution": "TVUI_720P",
                    "deviceResolution": "TVUI_720P",
                    "disablePersonalization": False,
                    "supportsAstcFormat": True,
                    "useWebPForAllImages": True,
                    "useWebPForLargeImages": True,
                }
            },
        }

        cookie_header = build_cookie_header(session, IMPORTANT_COOKIE_NAMES)
        headers = dict(session.headers)
        if cookie_header:
            headers["Cookie"] = cookie_header

        try:
            response = session.post(graphql_url, json=body, headers=headers, timeout=30)
            raw_headers = getattr(response.raw, "headers", None)
            if raw_headers is not None and hasattr(raw_headers, "get_all"):
                cookie_values.extend(raw_headers.get_all("Set-Cookie") or [])
            header_value = response.headers.get("Set-Cookie")
            if header_value and header_value not in cookie_values:
                cookie_values.append(header_value)

            if response.ok and session.cookies.get("gsid"):
                log.info("gsid: %s", f"{session.cookies.get('gsid', 'N/A')[:80]}...")
            else:
                log.warning("Post-login nav bootstrap did not produce gsid")
        except Exception as exc:
            log.warning("Post-login gsid fetch failed: %s", exc)

    dedupe_important_cookies(session, IMPORTANT_COOKIE_NAMES)

    cookies: Dict[str, str] = {}
    for cookie in session.cookies:
        if cookie.name in IMPORTANT_COOKIE_NAMES and cookie.value and cookie.name not in cookies:
            cookies[cookie.name] = cookie.value

    if membership == "CURRENT_MEMBER" and "NetflixId" in cookies:
        log.info("LOGIN SUCCESSFUL")
        log.info("NetflixId: %s", f"{cookies['NetflixId'][:80]}...")
        log.info("SecureNetflixId: %s", f"{cookies.get('SecureNetflixId', 'N/A')[:80]}...")
        log.info("nfvdid: %s", f"{cookies.get('nfvdid', 'N/A')[:80]}...")
        log.info("gsid: %s", f"{cookies.get('gsid', 'N/A')[:80]}...")
        log.info("netflix-mfa-nonce: %s", f"{cookies.get('netflix-mfa-nonce', 'N/A')[:80]}...")
    else:
        log.error("LOGIN FAILED")
        if membership != "CURRENT_MEMBER":
            log.error("Reason: membership status is '%s' (expected CURRENT_MEMBER)", membership)
        if "NetflixId" not in cookies:
            log.error("No NetflixId cookie received")
        log.error("Cookies present: %s", [cookie.name for cookie in session.cookies])

    NETFLIX_COOKIES_PATH.write_text(json.dumps(cookies, indent=2), encoding="utf-8")

    result = {
        "code": code,
        "cookies": cookies,
        "session": session,
        "flow_session_id": flow_session_id,
        "clcs_session_id": clcs_session_id,
        "response": login_data,
        "poll_response": last_poll_data,
        "useridtoken_path": str(USER_ID_TOKEN_PATH) if USER_ID_TOKEN_PATH.exists() else None,
    }

    log.info("Cookies saved to %s", NETFLIX_COOKIES_PATH.name)
    if result["useridtoken_path"]:
        log.info("useridtoken saved to %s", Path(result["useridtoken_path"]).name)
    else:
        log.info("useridtoken was not observed during this run")


# ======================================================================
# WEB
# ======================================================================

def run_web(new_msl: bool = False, no_verify: bool = False,
            recaptcha_token: str = ''):
    log = logging.getLogger('BROWSER MSL')

    OUTPUT_DIR = ensure_output_dir("browser")
    MSL_CACHE_PATH = OUTPUT_DIR / "msl_keys_cache_web.json"
    PRELOGIN_COOKIES_PATH = OUTPUT_DIR / "netflix_prelogin_cookies.json"
    AUTH_COOKIES_PATH = OUTPUT_DIR / "netflix_auth_cookies.json"

    NETFLIX_HOME_URL = "https://www.netflix.com/"
    NETFLIX_CANONICAL_URL = "https://netflix.com/"
    GRAPHQL_URL = "https://web.prod.cloud.netflix.com/graphql"
    LOGIN_URL = "https://www.netflix.com/login"
    BROWSE_URL = "https://www.netflix.com/browse"
    MSL_ALE_ENDPOINT = "https://www.netflix.com/nq/msl_v1/nrdjs/pbo_tokens/%5E1.0.0/router"

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/146.0.0.0 Safari/537.36"
    )
    CLIENT_VERSION = "6.135.459.031"
    APP_VERSION = "ve300d66c"
    HAWKINS_VERSION = "5.16.0"
    UI_FLAVOR = "akira"
    MSL_ESN = f"NFCDCH-02-{generate_hex_id(32, uppercase=True)}"
    REQUEST_CLIENT_CONTEXT = '{"appstate":"foreground"}'
    RECAPTCHA_SITE_KEY = "6Lf8hrcUAAAAAIpQAFW2VFjtiYnThOjZOA5xvLyR"

    QUERY_IDS = {
        "MembershipStatus": {"id": "3f50f3b3-fff8-48c0-bbd3-5fa2cb04b3c1", "version": 102},
        "CLCSScreenUpdate": {"id": "1c276cdf-caef-49cf-b38e-384972c2b47e", "version": 102},
        "CLCSSendFeedback": {"id": "079b2271-196b-4edd-b65c-e9439b22e305", "version": 102},
        "CLCSInterstitialProfileGate": {"id": "b6e10c7d-0e6f-4921-83b5-177995a80d97", "version": 102},
    }

    recaptcha_token = ""

    verify_tls = True
    restore_prelogin_cookies = True
    restore_auth_cookies = False

    session = requests.Session()
    session.verify = verify_tls
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    })

    if restore_auth_cookies:
        MSL_WEB.load_cookiejar(session, AUTH_COOKIES_PATH)
    elif restore_prelogin_cookies:
        MSL_WEB.load_cookiejar(session, PRELOGIN_COOKIES_PATH)

    log.info("Bootstrapping anonymous browser session")
    response = session.get(NETFLIX_CANONICAL_URL, timeout=30, allow_redirects=True)
    response.raise_for_status()

    home_response = session.get(NETFLIX_HOME_URL, timeout=30)
    home_response.raise_for_status()

    log.info("Sending MembershipStatus probe")
    operation_name = "MembershipStatus"
    variables = {}
    referer = NETFLIX_HOME_URL
    originating_url = NETFLIX_HOME_URL

    headers = {
        "Host": "web.prod.cloud.netflix.com",
        "Connection": "keep-alive",
        "x-netflix.request.id": generate_request_id(),
        "x-netflix.context.operation-name": operation_name,
        "x-netflix.request.originating.url": originating_url,
        "x-netflix.context.app-version": APP_VERSION,
        "x-netflix.context.hawkins-version": HAWKINS_VERSION,
        "x-netflix.context.locales": "en-us",
        "x-netflix.context.ui-flavor": UI_FLAVOR,
        "x-netflix.request.toplevel.uuid": str(uuid.uuid4()),
        "x-netflix.request.attempt": "1",
        "x-netflix.request.client.context": REQUEST_CLIENT_CONTEXT,
        "x-netflix.request.clcs.bucket": "high",
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Origin": "https://www.netflix.com",
        "Referer": referer,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
        "x-netflix.request.client.version": CLIENT_VERSION,
        "x-netflix.request.client.id": "ui/akiraWeb",
    }
    body = {
        "operationName": operation_name,
        "variables": variables,
        "extensions": {"persistedQuery": QUERY_IDS[operation_name]},
    }
    response = session.post(GRAPHQL_URL, json=body, headers=headers, timeout=30)
    response.raise_for_status()
    membership_status_response = response.json()
    if "errors" in membership_status_response:
        raise RuntimeError(json.dumps(membership_status_response["errors"], indent=2))

    log.info("Fetching login page and extracting screen context")
    response = session.get(LOGIN_URL, timeout=30)
    response.raise_for_status()
    login_html = response.text

    clcs_session_id = extract_clcs_session_id(login_html)
    rendition_id = extract_rendition_id(login_html)

    screen_name = "IDENTIFICATION"
    screen_name = "PASSWORD_LOGIN"

    log.info("Submitting password step directly to PASSWORD_LOGIN")

    session_context: Dict[str, Any] = {
        "session-breadcrumbs": {"funnel_name": "loginWeb"},
    }
    session_context.update({
        "login.navigationSettings": {"hideOtpToggle": True},
    })
    full_server_state = {
        "realm": "growth",
        "name": "PASSWORD_LOGIN",
        "clcsSessionId": clcs_session_id,
        "sessionContext": session_context,
    }

    full_screen_update = {
        "realm": "custom",
        "name": "growthLoginByPassword",
        "metadata": {"recaptchaSiteKey": RECAPTCHA_SITE_KEY},
        "loggingAction": "Submitted",
        "loggingCommand": "SubmitCommand",
        "referrerRenditionId": rendition_id,
    }

    full_variables = {
        "format": "HTML",
        "imageFormat": "PNG",
        "locale": "en-US",
        "serverState": json.dumps(full_server_state, separators=(",", ":")),
        "serverScreenUpdate": json.dumps(full_screen_update, separators=(",", ":")),
        "inputFields": [
            {"name": "password", "value": {"stringValue": PASSWORD}},
            {"name": "userLoginId", "value": {"stringValue": EMAIL}},
            {"name": "countryCode", "value": {"stringValue": "1"}},
            {"name": "countryIsoCode", "value": {"stringValue": "US"}},
            {"name": "recaptchaResponseTime", "value": {"intValue": 445}},
            {"name": "recaptchaResponseToken", "value": {"stringValue": recaptcha_token}},
        ],
    }

    try:
        operation_name = "CLCSScreenUpdate"
        referer = NETFLIX_HOME_URL
        originating_url = f"{LOGIN_URL}?serverState={quote(json.dumps(full_server_state, separators=(',', ':')))}"

        headers = {
            "Host": "web.prod.cloud.netflix.com",
            "Connection": "keep-alive",
            "x-netflix.request.id": generate_request_id(),
            "x-netflix.context.operation-name": operation_name,
            "x-netflix.request.originating.url": originating_url,
            "x-netflix.context.app-version": APP_VERSION,
            "x-netflix.context.hawkins-version": HAWKINS_VERSION,
            "x-netflix.context.locales": "en-us",
            "x-netflix.context.ui-flavor": UI_FLAVOR,
            "x-netflix.request.toplevel.uuid": str(uuid.uuid4()),
            "x-netflix.request.attempt": "1",
            "x-netflix.request.client.context": REQUEST_CLIENT_CONTEXT,
            "x-netflix.request.clcs.bucket": "high",
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://www.netflix.com",
            "Referer": referer,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "x-netflix.request.client.version": CLIENT_VERSION,
            "x-netflix.request.client.id": "ui/akiraWeb",
        }
        body = {
            "operationName": operation_name,
            "variables": full_variables,
            "extensions": {"persistedQuery": QUERY_IDS[operation_name]},
        }
        response = session.post(GRAPHQL_URL, json=body, headers=headers, timeout=30)
        response.raise_for_status()
        login_response = response.json()
        if "errors" in login_response:
            raise RuntimeError(json.dumps(login_response["errors"], indent=2))

    except Exception as exc:
        log.warning("Full PASSWORD_LOGIN submit failed, retrying with minimal payload: %s", exc)

        session_context = {
            "session-breadcrumbs": {"funnel_name": "loginWeb"},
        }
        minimal_server_state = {
            "realm": "growth",
            "name": "PASSWORD_LOGIN",
            "clcsSessionId": clcs_session_id,
            "sessionContext": session_context,
        }

        minimal_screen_update = {
            "realm": "custom",
            "name": "growthLoginByPassword",
        }

        minimal_variables = {
            "format": "HTML",
            "imageFormat": "PNG",
            "locale": "en-US",
            "serverState": json.dumps(minimal_server_state, separators=(",", ":")),
            "serverScreenUpdate": json.dumps(minimal_screen_update, separators=(",", ":")),
            "inputFields": [
                {"name": "userLoginId", "value": {"stringValue": EMAIL}},
                {"name": "password", "value": {"stringValue": PASSWORD}},
            ],
        }

        operation_name = "CLCSScreenUpdate"
        referer = NETFLIX_HOME_URL
        originating_url = f"{LOGIN_URL}?serverState={quote(json.dumps(minimal_server_state, separators=(',', ':')))}"

        headers = {
            "Host": "web.prod.cloud.netflix.com",
            "Connection": "keep-alive",
            "x-netflix.request.id": generate_request_id(),
            "x-netflix.context.operation-name": operation_name,
            "x-netflix.request.originating.url": originating_url,
            "x-netflix.context.app-version": APP_VERSION,
            "x-netflix.context.hawkins-version": HAWKINS_VERSION,
            "x-netflix.context.locales": "en-us",
            "x-netflix.context.ui-flavor": UI_FLAVOR,
            "x-netflix.request.toplevel.uuid": str(uuid.uuid4()),
            "x-netflix.request.attempt": "1",
            "x-netflix.request.client.context": REQUEST_CLIENT_CONTEXT,
            "x-netflix.request.clcs.bucket": "high",
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://www.netflix.com",
            "Referer": referer,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "x-netflix.request.client.version": CLIENT_VERSION,
            "x-netflix.request.client.id": "ui/akiraWeb",
        }
        body = {
            "operationName": operation_name,
            "variables": minimal_variables,
            "extensions": {"persistedQuery": QUERY_IDS[operation_name]},
        }
        response = session.post(GRAPHQL_URL, json=body, headers=headers, timeout=30)
        response.raise_for_status()
        login_response = response.json()
        if "errors" in login_response:
            raise RuntimeError(json.dumps(login_response["errors"], indent=2))

    response_text = json.dumps(login_response, ensure_ascii=False)
    screen_names = re.findall(r'"name":"([A-Z_]+)"', response_text)
    rendition_ids = re.findall(r'"renditionId":"([0-9a-f\-]{36})"', response_text)
    clcs_match = re.search(r'"clcsSessionId":"([0-9a-f\-]{36})"', response_text)

    next_clcs_session_id = clcs_match.group(1) if clcs_match else clcs_session_id
    next_screen_name = screen_names[-1] if screen_names else "PASSWORD_LOGIN"
    next_rendition_id = rendition_ids[-1] if rendition_ids else rendition_id

    feedback_payload = None
    effect = login_response.get("data", {}).get("result", {}).get("effect", {})
    nodes = effect.get("nodes", []) if isinstance(effect, dict) else []
    for node in nodes:
        if node.get("__typename") == "CLCSSendFeedback" and node.get("serverFeedback"):
            feedback_payload = json.loads(node["serverFeedback"])
            break

    if feedback_payload:
        log.info("Sending CLCSSendFeedback after successful login")

        session_context = {
            "session-breadcrumbs": {"funnel_name": "loginWeb"},
        }
        session_context.update({
            "login.navigationSettings": {"hideOtpToggle": True},
        })
        feedback_server_state = {
            "realm": "growth",
            "name": "PASSWORD_LOGIN",
            "clcsSessionId": next_clcs_session_id,
            "sessionContext": session_context,
        }

        operation_name = "CLCSSendFeedback"
        feedback_variables = {
            "inputFields": [],
            "serverFeedback": json.dumps(feedback_payload, separators=(",", ":")),
            "serverState": json.dumps(feedback_server_state, separators=(",", ":")),
        }
        referer = NETFLIX_HOME_URL
        originating_url = f"{LOGIN_URL}?serverState={quote(json.dumps(feedback_server_state, separators=(',', ':')))}"

        headers = {
            "Host": "web.prod.cloud.netflix.com",
            "Connection": "keep-alive",
            "x-netflix.request.id": generate_request_id(),
            "x-netflix.context.operation-name": operation_name,
            "x-netflix.request.originating.url": originating_url,
            "x-netflix.context.app-version": APP_VERSION,
            "x-netflix.context.hawkins-version": HAWKINS_VERSION,
            "x-netflix.context.locales": "en-us",
            "x-netflix.context.ui-flavor": UI_FLAVOR,
            "x-netflix.request.toplevel.uuid": str(uuid.uuid4()),
            "x-netflix.request.attempt": "1",
            "x-netflix.request.client.context": REQUEST_CLIENT_CONTEXT,
            "x-netflix.request.clcs.bucket": "high",
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://www.netflix.com",
            "Referer": referer,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "x-netflix.request.client.version": CLIENT_VERSION,
            "x-netflix.request.client.id": "ui/akiraWeb",
        }
        body = {
            "operationName": operation_name,
            "variables": feedback_variables,
            "extensions": {"persistedQuery": QUERY_IDS[operation_name]},
        }
        response = session.post(GRAPHQL_URL, json=body, headers=headers, timeout=30)
        response.raise_for_status()
        feedback_response = response.json()
        if "errors" in feedback_response:
            raise RuntimeError(json.dumps(feedback_response["errors"], indent=2))
    else:
        log.info("No post-login feedback payload was found")

    log.info("Opening /browse to finalize the authenticated web session")
    session_context = {
        "session-breadcrumbs": {"funnel_name": "loginWeb"},
    }
    session_context.update({
        "login.navigationSettings": {"hideOtpToggle": True},
    })
    browse_server_state = {
        "realm": "growth",
        "name": "PASSWORD_LOGIN",
        "clcsSessionId": next_clcs_session_id,
        "sessionContext": session_context,
    }
    browse_originating_url = f"{LOGIN_URL}?serverState={quote(json.dumps(browse_server_state, separators=(',', ':')))}"

    response = session.get(
        BROWSE_URL,
        headers={
            "Referer": browse_originating_url,
            "Accept-Language": "en-US,en;q=0.9",
        },
        timeout=30,
    )
    response.raise_for_status()

    log.info("Probing the post-login profile gate")
    profile_gate_response = None
    try:
        operation_name = "CLCSInterstitialProfileGate"
        variables = {"format": "HTML", "resolutionMode": "WEB_1X"}
        referer = NETFLIX_HOME_URL
        originating_url = BROWSE_URL

        headers = {
            "Host": "web.prod.cloud.netflix.com",
            "Connection": "keep-alive",
            "x-netflix.request.id": generate_request_id(),
            "x-netflix.context.operation-name": operation_name,
            "x-netflix.request.originating.url": originating_url,
            "x-netflix.context.app-version": APP_VERSION,
            "x-netflix.context.hawkins-version": HAWKINS_VERSION,
            "x-netflix.context.locales": "en-us",
            "x-netflix.context.ui-flavor": UI_FLAVOR,
            "x-netflix.request.toplevel.uuid": str(uuid.uuid4()),
            "x-netflix.request.attempt": "1",
            "x-netflix.request.client.context": REQUEST_CLIENT_CONTEXT,
            "x-netflix.request.clcs.bucket": "high",
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://www.netflix.com",
            "Referer": referer,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "x-netflix.request.client.version": CLIENT_VERSION,
            "x-netflix.request.client.id": "ui/akiraWeb",
        }
        body = {
            "operationName": operation_name,
            "variables": variables,
            "extensions": {"persistedQuery": QUERY_IDS[operation_name]},
        }
        response = session.post(GRAPHQL_URL, json=body, headers=headers, timeout=30)
        response.raise_for_status()
        profile_gate_response = response.json()
        if "errors" in profile_gate_response:
            raise RuntimeError(json.dumps(profile_gate_response["errors"], indent=2))
    except Exception as exc:
        log.warning("Profile gate probe failed: %s", exc)

    log.info("Attempting post-login ALE provision")
    ale_response = None
    try:
        final_cookies = MSL_WEB.cookiejar_to_ordered_dict(session.cookies)

        req_id = generate_request_id()
        endpoint = (
            f"{MSL_ALE_ENDPOINT}?reqAttempt=1&reqName=aleProvision&reqId={req_id}"
            f"&clienttype={UI_FLAVOR}&uiversion={APP_VERSION}&browsername=chrome"
            f"&browserversion=146.0.0.0&osname=windows&osversion=10.0"
        )

        headers = MSL_WEB.build_request_headers(
            request_name="aleProvision",
            user_agent=USER_AGENT,
            referer=BROWSE_URL,
            esn=MSL_ESN,
            extra_headers={
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )

        ale_response = MSL_WEB.handshake(
            msl_keys_path=MSL_CACHE_PATH,
            session=session,
            sender=MSL_ESN,
            new_msl=False,
            cookies=final_cookies,
            endpoint=endpoint,
            headers=headers,
        )
    except Exception as exc:
        log.error("ALE provision failed: %s", exc)

    auth_cookies = MSL_WEB.cookiejar_to_ordered_dict(session.cookies)
    AUTH_COOKIES_PATH.write_text(json.dumps(auth_cookies, indent=2), encoding="utf-8")

    result = {
        "auth_cookies": auth_cookies,
    }

    #print(json.dumps(result, indent=2))


# ======================================================================
# MGK (Model Group Key)
# ======================================================================

def run_mgk(kpekph_path: Optional[Path], esnid: str,
            new_msl: bool = False):
    log = logging.getLogger('MGK MSL')

    OUTPUT_DIR = ensure_output_dir("mgk")
    MSL_CACHE_PATH = OUTPUT_DIR / "msl_keys_cache_mgk.json"
    AUTH_COOKIES_PATH = OUTPUT_DIR / "netflix_auth_cookies_mgk.json"

    DEVICE_TYPE = "NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019"
    ESN = esnid

    session = requests.Session()
    session.verify = True
    session.headers.update({
        "User-Agent": MSL_MGK.DEFAULT_USER_AGENT,
        "Accept": "*/*",
    })

    log.info("Starting MSL MGK handshake with ESN: %s", ESN)

    handshake_headers = MSL_MGK.build_request_headers(
        request_name="mintCookies",
        esn=ESN,
        expiry_timeout=12750,
    )

    msl_client = MSL_MGK.handshake(
        session=session,
        sender=ESN,
        kpekph_path=str(kpekph_path) if kpekph_path else None,
        msl_keys_path=str(MSL_CACHE_PATH),
        cookies=None,
        headers=handshake_headers,
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




# ===========================================================================
# ENTRY POINT
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="Netflix MSL multi-platform login")
    parser.add_argument("--platform", required=True, choices=["android", "android_rsa", "ios", "tv", "tv_otp", "web", "mgk"], help="Target platform")
    parser.add_argument("--wvd", type=Path, help="Path to Widevine .wvd device file")
    parser.add_argument("--kpekph", type=Path, default=None, help="Path to KpeKph file (mgk platform); auto-discovered if omitted")
    parser.add_argument("--esnid", type=str, help="ESN identity string (mgk platform)")
    parser.add_argument("--new-msl", action="store_true", help="Force new MSL key exchange")
    parser.add_argument("--no-verify", action="store_true", help="Skip TLS verification")

    args = parser.parse_args()
    
    if args.platform == "android_rsa":
        run_android_rsa(new_msl=args.new_msl, no_verify=args.no_verify)
        
    if args.platform == "android":
        if not args.wvd:
            parser.error("--wvd is required for android platform")
        run_android(wvd_path=args.wvd, new_msl=args.new_msl, no_verify=args.no_verify)

    elif args.platform == "ios":
        if not args.wvd:
            parser.error("--wvd is required for ios platform")
        run_ios(wvd_path=args.wvd, new_msl=args.new_msl, no_verify=args.no_verify)

    elif args.platform == "tv":
        if not args.wvd:
            parser.error("--wvd is required for tv platform")
        run_tv(wvd_path=args.wvd, new_msl=args.new_msl, no_verify=args.no_verify)

    elif args.platform == "tv_otp":
        if not args.wvd:
            parser.error("--wvd is required for tv_otp platform")
        run_tv_otp(wvd_path=args.wvd, new_msl=args.new_msl, no_verify=args.no_verify)

    elif args.platform == "web":
        run_web(new_msl=args.new_msl, no_verify=args.no_verify)

    elif args.platform == "mgk":
        if not args.esnid:
            parser.error("--esnid is required for mgk platform")
        run_mgk(kpekph_path=args.kpekph, esnid=args.esnid, new_msl=args.new_msl)


if __name__ == "__main__":
    if os.name == "nt":
        os.system('cls')
    else:
        os.system('clear')
    main()
