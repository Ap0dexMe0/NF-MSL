from __future__ import annotations
import json
import random
import sys
import time
import uuid
from typing import Any, Dict, List, Optional
from pathlib import Path
from urllib.parse import quote, urlencode
from pywidevine import Cdm as WidevineCdm, Device as WidevineDevice
from modules.msl.tv import MSL_TV
from modules.helpers import (
    ensure_output_dir,
    build_cookie_header, apply_set_cookie_headers,
    dedupe_important_cookies,
    generate_hex_id,
    parse_flow_data, parse_msl_payload, extract_useridtoken_from_payload,
    build_msl_trace_event, extract_key_id_from_mastertoken, request_args_to_dict,
    decrypt_msl_header,
)
from modules.config import setup_config
from modules.logging import setup_logger
from modules.session import setup_session

config = setup_config()
EMAIL = config["NETFLIX"]["EMAIL"]
PASSWORD = config["NETFLIX"]["PASSWORD"]


def run_tv(wvd_path: Path,
           new_msl: bool = False, no_verify: bool = False,
           proxy: Optional[str] = None):
    log = setup_logger('ANDROID TV MSL')

    OUTPUT_DIR = ensure_output_dir("tv")

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
    if not wvd_path.exists():
        raise FileNotFoundError(f"Missing WVD file: {wvd_path}")
    _wvd_device = WidevineDevice.load(wvd_path)
    _sid = _wvd_device.system_id
    MSL_CACHE_PATH = OUTPUT_DIR / f"msl_keys_cache_{_sid}.json"
    USER_ID_TOKEN_PATH = OUTPUT_DIR / f"useridtoken_{_sid}.json"
    MSL_TRACE_PATH = OUTPUT_DIR / f"msl_debug_trace_{_sid}.json"
    NETFLIX_COOKIES_PATH = OUTPUT_DIR / f"netflix_cookies_{_sid}.json"
    LOGIN_RESPONSE_PATH = OUTPUT_DIR / f"password_login_response_{_sid}.json"
    ESN = f"{DEVICE_TYPE}-{_sid}-{''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(64))}"
    log.info("ESN: %s", ESN)

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

    session = setup_session(verify_tls=not no_verify, proxy=proxy)
    _proxy = {"http": proxy, "https": proxy} if proxy else None

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
                proxy=_proxy,
            )
            log.info("Using cached MSL keys")
        else:
            device = _wvd_device
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
                proxy=_proxy,
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
                proxy=_proxy,
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
