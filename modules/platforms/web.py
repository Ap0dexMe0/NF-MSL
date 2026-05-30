from __future__ import annotations
import json
import random
import re
import sys
import uuid
from pathlib import Path
from typing import Optional
from urllib.parse import quote
from modules.msl.web import MSL_WEB
from modules.helpers import (
    ensure_output_dir,
    generate_request_id, generate_hex_id,
    extract_clcs_session_id, extract_rendition_id,
)
from modules.config import setup_config
from modules.logging import setup_logger
from modules.session import setup_session

config = setup_config()
EMAIL = config["NETFLIX"]["EMAIL"]
PASSWORD = config["NETFLIX"]["PASSWORD"]


def run_web(new_msl: bool = False, no_verify: bool = False,
            recaptcha_token: str = '', proxy: Optional[str] = None):
    log = setup_logger('BROWSER MSL')

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

    verify_tls = not no_verify
    restore_prelogin_cookies = True
    restore_auth_cookies = False

    session = setup_session(verify_tls=verify_tls, proxy=proxy)
    _proxy = {"http": proxy, "https": proxy} if proxy else None

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

    from typing import Any, Dict
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
