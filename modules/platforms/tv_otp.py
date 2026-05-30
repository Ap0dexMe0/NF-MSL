from __future__ import annotations
import base64
import json
import random
import re
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
    generate_hex_id, generate_esn_random_suffix,
    parse_flow_data, parse_msl_payload, extract_useridtoken_from_payload,
    build_msl_trace_event, extract_key_id_from_mastertoken, request_args_to_dict,
)
from modules.config import setup_config
from modules.logging import setup_logger
from modules.session import setup_session

config = setup_config()
EMAIL = config["NETFLIX"]["EMAIL"]
PASSWORD = config["NETFLIX"]["PASSWORD"]


def run_tv_otp(wvd_path: Path, new_msl: bool = False, no_verify: bool = False,
               proxy: Optional[str] = None):
    log = setup_logger('ANDROID TV MSL')

    OUTPUT_DIR = ensure_output_dir()

    MSL_HANDSHAKE_ENDPOINT = "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_tokens/%5E1.0.0/router"
    MSL_TV_ENDPOINT = "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_tokens/%5E1.0.0/router"
    PBO_CONFIG_ENDPOINT = "https://nrdp25.prod.ftl.netflix.com/nq/nrdjs/pbo_config/%5E1.0.0/router?ab_ui_ver=darwin&nrdapp_version=2025.2.3.0"

    DEVICE_TYPE = "NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019"
    DEVICE_MODEL = "NVIDIA_SHIELD Android TV"
    DEVICE_NAME = "SHIELD"
    ANDROID_BUILD_FINGERPRINT = "12.1.9-23083 R 2025.2 android-30-JPLAYER2 ninja_6==NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4040.2147:user/release-keys"
    APP_VERSION = "UI-release-20260408_44798-gibbon-r100-aui-nrdjs=v3.12.55"
    if not wvd_path.exists():
        raise FileNotFoundError(f"Missing WVD file: {wvd_path}")
    _wvd_device = WidevineDevice.load(wvd_path)
    _sid = _wvd_device.system_id
    MSL_CACHE_PATH = OUTPUT_DIR / f"msl_keys_cache_{_sid}.json"
    USER_ID_TOKEN_PATH = OUTPUT_DIR / f"useridtoken_{_sid}.json"
    NETFLIX_COOKIES_PATH = OUTPUT_DIR / f"netflix_cookies_{_sid}.json"
    ESN = f"NFANDROID2-PRV-NVIDIASHIELDANDROIDTV2019-NVIDISHIELD=ANDROID=TV-{_sid}-{generate_esn_random_suffix(64)}"
    log.info("ESN: %s", ESN)

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

    session = setup_session(verify_tls=not no_verify, proxy=proxy)
    _proxy = {"http": proxy, "https": proxy} if proxy else None

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
        device = _wvd_device
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
            proxy=_proxy,
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
