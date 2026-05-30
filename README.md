# Netflix MSL Universal Handshake

> A cross-platform MSL (Message Security Layer) authentication toolkit for Netflix. Implements a unified handshake layer that works across Android, iOS, Smart TV, Web, and MGK all driven from a single entry point with shared credential management.

---

## Table of Contents

- [Requirements](#requirements)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Platforms](#platforms)
  - [Android RSA](#android-rsa-no-wvd)
  - [Android](#android)
  - [iOS](#ios)
  - [TV (email/password)](#tv-emailpassword)
  - [TV OTP (pairing code)](#tv-otp-pairing-code)
  - [Web](#web)
  - [MGK (Model Group Key)](#mgk-model-group-key)
- [Usage](#usage)
- [Flags](#flags)
- [WVD Glob Testing](#wvd-glob-testing)
- [Proxy Support](#proxy-support)
- [Output Files](#output-files)

---

## Requirements

```bash
pip install -r requirements.txt
```

Key dependencies: `pywidevine`, `pycryptodome`, `requests`, `coloredlogs`, `certifi`, `jsonpickle`.

---

## Configuration

Edit `config.ini` before running:

```ini
[NETFLIX]
EMAIL    = your@email.com
PASSWORD = yourpassword
```

Credentials are read once at startup. They are **never** accepted as command-line arguments.

---

## Project Structure

```
NF-MSL/
├── main.py                      # CLI entry point
├── config.ini                   # Netflix credentials
├── devices/                     # WVD device files (gitignored)
├── output/                      # Per-platform output (gitignored)
└── modules/
    ├── config.py                # Config loader
    ├── logging.py               # Coloredlogs setup
    ├── session.py               # requests.Session factory (TLS + proxy)
    ├── helpers.py               # Shared utilities
    ├── msl/                     # MSL protocol layer
    │   ├── base.py              # MSLBase, MSLKeys, send_message
    │   ├── android.py           # MSL_ANDROID (Widevine + RSA)
    │   ├── ios.py               # MSL_IOS
    │   ├── tv.py                # MSL_TV
    │   ├── web.py               # MSL_WEB (RSA)
    │   └── mgk.py               # MSL_MGK (AUTHENTICATED_DH)
    └── platforms/               # Per-platform login orchestration
        ├── android_rsa.py       # run_android_rsa
        ├── android.py           # run_android
        ├── ios.py               # run_ios
        ├── tv.py                # run_tv
        ├── tv_otp.py            # run_tv_otp
        ├── web.py               # run_web
        └── mgk.py               # run_mgk
```

---

## Platforms

### Android RSA (no WVD)

Emulates a **Samsung Galaxy Z Flip3 (SM-F711N)** running Android 15. Uses an RSA/ASYMMETRIC_WRAPPED key exchange — no Widevine device file required.

**MSL flow:**
1. Bootstrap HTTP session → `nfvdid` cookie via `appboot`
2. RSA key exchange (MSL handshake) using `NFCDCH-02-*` ESN
3. `CLCSScreenUpdate` GraphQL — submit email + password via MSL
4. Load `/browse` to finalize session

**Output:** `android/netflix_auth_cookies_rsa.json`, `netflix_auth_tokens_rsa.json`

---

### Android

Emulates a **Samsung Galaxy Z Flip3 (SM-F711N)** running Android 15 with full Widevine L3 authentication.

**MSL flow:**
1. Bootstrap HTTP session → `nfvdid` via `appboot`
2. Widevine key exchange using the provided `.wvd`
3. Load login page → `CLCSScreenUpdate` (CLCS web login) to obtain `NetflixId`/`SecureNetflixId` cookies
4. `VerifyLoginMslRequest` (samurai) — binds the MSL session to the authenticated account
5. Decrypt response header → extract `useridtoken`

> If `VerifyLoginMslRequest` returns `incorrect_password`, the CLCS login fallback is triggered automatically and the request is retried with the fresh auth cookies.

**Output (per WVD system ID):** `android/netflix_auth_tokens_{sid}.json`, `netflix_auth_useridtoken_{sid}.json`, `netflix_auth_cookies_{sid}.json`

---

### iOS

Emulates an **iPhone 15 Pro Max** running iOS 18.

**MSL flow:**
1. Bootstrap HTTP session → `nfvdid` via `appboot`
2. Widevine key exchange using the provided `.wvd`
3. `MembershipStatus` GraphQL probe (anonymous)
4. Load login page → extract `clcsSessionId` + `renditionId`
5. `CLCSScreenUpdate` — submit email + password via MSL to `ios.prod.cloud.netflix.com/graphql`

**Output (per WVD system ID):** `ios/netflix_auth_cookies_{sid}.json`

---

### TV (email/password)

Emulates an **NVIDIA SHIELD Android TV (2019)**.

**MSL flow:**
1. Obtain `nfvdid` from the Android TV config endpoint
2. Bootstrap AUI + pre-login `pathEvaluator`
3. Widevine key exchange using the provided `.wvd` → `mintCookies`
4. CLCS session initiation (`clcsLegacyMoneyballInitiateSession`)
5. Multi-step credential flow:
   - Welcome landing → web sign-in → email → password
   - Submit credentials via `clcsScreenUpdate`
6. Post-login PBO config + token refresh (`getPartnerToken`, `ping`)
7. Save cookies including `NetflixId`, `SecureNetflixId`, `gsid`

**Output (per WVD system ID):** `tv/netflix_cookies_{sid}.json`, `useridtoken_{sid}.json`, `msl_debug_trace_{sid}.json`, `password_login_response_{sid}.json`

---

### TV OTP (pairing code)

Same device profile as **TV**, but authenticates via a **one-time pairing code** instead of email/password.

**MSL flow:**
1–3. Same as TV up through `mintCookies`
4. CLCS session initiation
5. Navigate to `webSignIn` mode → extract an **8-digit TV code**
6. **Display the code and poll** `https://www.netflix.com/tv2` every 5 seconds until the user activates it
7. Send `continueAction` to complete sign-in

> **Interactive:** visit `https://www.netflix.com/tv2` in a browser and enter the displayed code to proceed.

**Output (per WVD system ID):** `tv_otp/netflix_cookies_{sid}.json`, `useridtoken_{sid}.json`

---

### Web

Emulates **Chrome 146 on Windows 10**.

**MSL flow:**
1. Bootstrap anonymous browser session (`netflix.com` → `/login`)
2. `MembershipStatus` GraphQL probe
3. Extract `clcsSessionId` + `renditionId` from login page HTML
4. `CLCSScreenUpdate` — submit email + password to `PASSWORD_LOGIN`
5. Optional `CLCSSendFeedback` if the server returns a feedback payload
6. Load `/browse` to finalize session
7. `CLCSInterstitialProfileGate` probe
8. ALE provision via MSL RSA handshake

**Output:** `browser/netflix_auth_cookies.json`

---

### MGK (Model Group Key)

Uses the **MGK / AUTHENTICATED_DH** MSL key-exchange scheme, authenticating with a pre-provisioned `KpeKph` key pair rather than a Widevine device.

**Requires two sidecar files:**

| File | Content |
|------|---------|
| `KpeKph` | Base64 AES-128 encryption key + Base64 HMAC-SHA256 key, comma-separated |
| `ESNID` | Model-group identity string (the MGK sender ESN) |

Files are auto-discovered in the working directory, any subdirectory, or via environment variables:

```bash
export MSL_KPEKPH_PATH=/path/to/KpeKph
```

Or pass `--kpekph` and `--esnid` on the command line.

**MSL flow:**
1. Load `KpeKph` → derive wrapping key
2. Generate DH keypair → build `AUTHENTICATED_DH` key-request (`mechanism=MGK`)
3. Handshake → derive session encryption + HMAC keys from shared secret
4. Send `EMAIL_PASSWORD` user-auth message → receive `useridtoken`

**Output:** `mgk/netflix_auth_cookies_mgk.json`

---

## Usage

```bash
# Android RSA (no WVD needed)
python main.py --platform android_rsa

# Android with a single WVD
python main.py --platform android --wvd devices/my_device_l3.wvd

# iOS
python main.py --platform ios --wvd devices/my_device_l3.wvd

# TV (email/password)
python main.py --platform tv --wvd devices/my_device.wvd

# TV OTP (pairing code — interactive)
python main.py --platform tv_otp --wvd devices/my_device.wvd

# Web (Chrome emulation)
python main.py --platform web

# MGK
python main.py --platform mgk --esnid path/to/ESNID --kpekph path/to/KpeKph

# Force fresh MSL handshake (ignore cached keys)
python main.py --platform tv --wvd devices/my_device.wvd --new-msl

# Skip TLS verification
python main.py --platform web --no-verify

# Use a proxy
python main.py --platform tv --wvd devices/my_device.wvd --proxy http://127.0.0.1:8080
python main.py --platform tv --wvd devices/my_device.wvd --proxy http://user:pass@proxy.example.com:3128
```

---

## Flags

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--platform` | all | **Required.** One of `android_rsa`, `android`, `ios`, `tv`, `tv_otp`, `web`, `mgk` |
| `--wvd` | android, ios, tv, tv_otp | Path or glob to `.wvd` file(s). **Required** for these platforms |
| `--kpekph` | mgk | Path to `KpeKph` key file (auto-discovered if omitted) |
| `--esnid` | mgk | ESN identity string or file path. **Required** for mgk |
| `--new-msl` | all | Force a fresh MSL handshake, ignoring cached keys |
| `--no-verify` | all | Disable TLS certificate verification |
| `--proxy` | all | Proxy URL — `http://ip:port` or `http://user:pass@ip:port` |

---

## WVD Glob Testing

Pass a glob pattern to `--wvd` to test multiple `.wvd` files in sequence. Only `.wvd` files are matched.

```bash
python main.py --platform android --wvd "devices/*.wvd"
python main.py --platform tv      --wvd "devices/*"
```

The tool loops through all matching files sorted by name, waits **10 seconds between each** to avoid throttling, and prints a pass/fail summary at the end:

```
MSL HANDSHAKE - INFO - Found 14 .wvd file(s) to test
MSL HANDSHAKE - INFO - --- [1/14] WVD: changhong_androidtv_22594_l3.wvd ---
...
MSL HANDSHAKE - INFO - === Results: 3/14 passed ===
MSL HANDSHAKE - INFO -   PASS: changhong_androidtv_22594_l3.wvd
MSL HANDSHAKE - WARNING -   FAIL: amlogic_mbox_22594_l3.wvd
```

Output files include the WVD's Widevine system ID, so runs never overwrite each other:

```
output/tv/netflix_cookies_22594.json
output/tv/useridtoken_22594.json
```

---

## Proxy Support

All platforms support an HTTP/HTTPS proxy. The proxy is applied at both the session level (all HTTP requests) and explicitly on every MSL `send_message` call.

```bash
# IP:port
python main.py --platform tv --wvd devices/device.wvd --proxy http://192.168.1.1:8080

# Authenticated
python main.py --platform tv --wvd devices/device.wvd --proxy http://user:pass@proxy.host:3128
```

---

## Output Files

All output is written under the `output/` directory, organised by platform. Files that depend on a WVD include the Widevine **system ID** in their name so multiple WVDs can be tested without overwriting results.

| Platform | Output files |
|----------|-------------|
| `android_rsa` | `android/netflix_auth_cookies_rsa.json`, `netflix_auth_tokens_rsa.json`, `netflix_auth_useridtoken_rsa.json` |
| `android` | `android/netflix_auth_cookies_{sid}.json`, `netflix_auth_tokens_{sid}.json`, `netflix_auth_useridtoken_{sid}.json` |
| `ios` | `ios/netflix_auth_cookies_{sid}.json` |
| `tv` | `tv/netflix_cookies_{sid}.json`, `useridtoken_{sid}.json`, `msl_debug_trace_{sid}.json`, `password_login_response_{sid}.json` |
| `tv_otp` | `tv_otp/netflix_cookies_{sid}.json`, `useridtoken_{sid}.json` |
| `web` | `browser/netflix_auth_cookies.json` |
| `mgk` | `mgk/netflix_auth_cookies_mgk.json` |

MSL key caches are also stored per platform (and per WVD system ID where applicable) and reused across runs. They expire automatically when the master token has fewer than **10 hours** remaining.

---

**Big thanks to [Hugoved](https://github.com/Hugoved)**  
- for the foundational work on MSL (Message Security Layer) reverse engineering and the original pywidevine implementation that made this unified handshake toolkit possible.
