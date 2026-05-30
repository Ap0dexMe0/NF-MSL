from __future__ import annotations
import json
import random
import sys
from typing import Any, Dict, Optional
from pathlib import Path
from urllib.parse import quote
from pywidevine import Cdm as WidevineCdm, Device as WidevineDevice
from modules.msl.ios import MSL_IOS
from modules.helpers import (
    ensure_output_dir,
    get_nfvdid, get_flow_session_cookies,
    save_session_cookies,
    generate_request_id, generate_esn_random_suffix,
    decrypt_msl_header,
    extract_clcs_session_id, extract_rendition_id,
)
from modules.config import setup_config
from modules.logging import setup_logger
from modules.session import setup_session

config = setup_config()
EMAIL = config["NETFLIX"]["EMAIL"]
PASSWORD = config["NETFLIX"]["PASSWORD"]


def run_ios(wvd_path: Path,
            new_msl: bool = False, no_verify: bool = False,
            proxy: Optional[str] = None):
    log = setup_logger('IOS MSL')

    OUTPUT_DIR = ensure_output_dir("ios")

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

    if not wvd_path.exists():
        raise FileNotFoundError(f"Missing WVD file: {wvd_path}")
    device = WidevineDevice.load(wvd_path)
    cdm = WidevineCdm.from_device(device)
    _sid = device.system_id
    MSL_CACHE_PATH = OUTPUT_DIR / f"msl_keys_cache_ios_{_sid}.json"
    AUTH_COOKIES_PATH = OUTPUT_DIR / f"netflix_auth_cookies_{_sid}.json"

    ESN = f"NFANDROID1-PRV-P-IPHONE15=3-{_sid}-{generate_esn_random_suffix(64)}"
    log.info("ESN: %s", ESN)

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

    verify_tls = not no_verify
    restore_auth_cookies = False

    session = setup_session(verify_tls=verify_tls, proxy=proxy)
    _proxy = {"http": proxy, "https": proxy} if proxy else None

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
        proxy=_proxy,
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
