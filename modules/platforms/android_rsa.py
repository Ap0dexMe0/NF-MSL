from __future__ import annotations
import json
import random
import re
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import quote
from modules.msl.android import MSL_ANDROID
from modules.helpers import (
    ensure_output_dir, get_nfvdid,
    generate_hex_id,
)
from modules.config import setup_config
from modules.logging import setup_logger
from modules.session import setup_session

config = setup_config()
EMAIL = config["NETFLIX"]["EMAIL"]
PASSWORD = config["NETFLIX"]["PASSWORD"]


def run_android_rsa(new_msl: bool = False, no_verify: bool = False,
                    proxy: Optional[str] = None):
    logger = setup_logger('ANDROID MSL RSA')
    output_dir = ensure_output_dir("android")
    msl_cache_path = output_dir / "msl_keys_cache_android_rsa.json"
    auth_cookies_path = output_dir / "netflix_auth_cookies_rsa.json"
    useridtoken_path = output_dir / "netflix_auth_useridtoken_rsa.json"
    tokens_output_path = output_dir / "netflix_auth_tokens_rsa.json"

    # NFCDCH-02-* ESN is accepted by the Android FTL endpoint without a WVD
    esn = f"NFCDCH-02-{''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))}"
    user_agent = f"com.netflix.mediaclient/63988 (Linux; U; Android 15; en_US; SM-F711N; Build/AP3A.240905.015.A2; Cronet/143.0.7445.0)"
    device_model = "SM-F711N"

    session = setup_session(verify_tls=not no_verify, proxy=proxy)
    _proxy = {"http": proxy, "https": proxy} if proxy else None

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
        proxy=_proxy,
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
