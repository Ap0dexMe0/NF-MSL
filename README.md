# Netflix MSL Universal Handshake

> A cross-platform MSL (Message Security Layer) authentication toolkit for Netflix.  
> Implements a unified handshake layer that works across Android, iOS, Smart TV, Web, and MGK — all driven from a single entry point with shared credential management.

---

## Table of Contents

- [Requirements](#requirements)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Devices (WVD Files)](#devices-wvd-files)
- [Platforms](#platforms)
  - [Android](#android)
  - [iOS](#ios)
  - [TV (email/password)](#tv-emailpassword)
  - [TV OTP (pairing code)](#tv-otp-pairing-code)
  - [Web](#web)
  - [MGK (Model Group Key)](#mgk-model-group-key)
- [Usage](#usage)
- [Output Files](#output-files)
- [Module Overview](#module-overview)

---

## Requirements

```
Python >= 3.9
requests
pycryptodome  (Cryptodome)
pywidevine
jsonpickle
```

Install all dependencies:

```bash
pip install -r requirements.txt
```

---

## Project Structure

```
.
├── main.py                  # Entry point — platform router
├── config.ini               # Credentials (EMAIL / PASSWORD)
├── devices/
│   ├── l3.wvd   # L3 Android/iOS WVD
│   └── l1.wvd          # L1 TV WVD
│   └── KpeKph          MGK KpeKph platform: base64 encryption + HMAC keys (comma-separated)
│   └── ESNID           # MGK platform: model-group identity string
├── modules/
│   ├── __init__.py
│   ├── config.py            # config.ini loader
│   ├── msl_android.py       # MSL_ANDROID class
│   ├── msl_ios.py           # MSL_IOS class
│   ├── msl_tv.py            # MSL_TV class
│   ├── msl_web.py           # MSL_WEB class
│   └── msl_mgk.py           # MSL_MGK class (Model Group Key)                   
```

---

## Configuration

Edit `config.ini` before running anything:

```ini
[NETFLIX]
EMAIL    = your@email.com
PASSWORD = yourpassword
```

Credentials are read once at startup and passed internally to every platform function. They are **never** accepted as command-line arguments.

---

## Devices (WVD Files)

Two Widevine Device (`.wvd`) files are included in the `devices/` folder:

| File | Security Level | Used by |
|------|---------------|---------|
| `l3.wvd` | L3 | Android, iOS |
| `l1.wvd` | L1 | TV, TV OTP |

The correct WVD is selected automatically for each platform. The `--wvd` flag lets you override with a custom device file if needed.

---

## Platforms

### Android

Emulates a **Samsung Galaxy Z Flip3 (SM-F711N)** running Android 15.

**MSL flow:**
1. Bootstrap HTTP session → obtain `nfvdid` cookie via `appboot`
2. Widevine key exchange (MSL handshake) using L3 WVD
3. `VerifyLoginMslRequest` — submits email + password via MSL
4. Decrypts the response header to extract `useridtoken`

**Output:** `netflix_auth_tokens.json`, `netflix_auth_useridtoken.json`, `netflix_auth_cookies.json`

---

### iOS

Emulates an **iPhone 15 Pro Max** running iOS 18.

**MSL flow:**
1. Bootstrap HTTP session → obtain `nfvdid` via `appboot`
2. Widevine key exchange using L3 WVD
3. `MembershipStatus` GraphQL probe (anonymous)
4. `CLCSScreenUpdate` — submits email + password via MSL to `ios.prod.cloud.netflix.com/graphql`
5. Decrypts the response header to extract `useridtoken`

**Output:** `netflix_auth_cookies.json`

---

### TV (email/password)

Emulates an **NVIDIA SHIELD Android TV (2019)**.

**MSL flow:**
1. Obtain `nfvdid` from the Android TV config endpoint
2. Bootstrap AUI + pre-login `pathEvaluator`
3. Widevine key exchange using L1 WVD → `mintCookies`
4. CLCS session initiation (`clcsLegacyMoneyballInitiateSession`)
5. Multi-step sign-in flow:
   - Navigate welcome landing → web sign-in → email → password path
   - Submit credentials via `clcsScreenUpdate`
6. Post-login PBO config + token refresh (`getPartnerToken`, `ping`)
7. Save cookies including `NetflixId`, `SecureNetflixId`, `gsid`

**Output:** `netflix_cookies.json`, `useridtoken.json`, `msl_debug_trace.json`, `password_login_response.json`

---

### TV OTP (pairing code)

Same device profile as **TV**, but authenticates via a **one-time pairing code** instead of email/password.

**MSL flow:**
1–3. Same as TV up through `mintCookies`
4. CLCS session initiation
5. Navigate to `webSignIn` mode → extract an **8-digit TV code**
6. **Display the code and poll** `https://www.netflix.com/tv2` until the user activates it from a browser
7. Send `continueAction` to complete sign-in

> **Interactive:** you must visit `https://www.netflix.com/tv2` in a browser and enter the displayed code to proceed.

**Output:** `netflix_cookies.json`, `useridtoken.json`

---

### Web

Emulates **Chrome 146 on Windows 10**.

**MSL flow:**
1. Bootstrap anonymous browser session (`netflix.com` → `netflix.com/login`)
2. `MembershipStatus` GraphQL probe
3. Extract `clcsSessionId` and `renditionId` from the login page HTML
4. `CLCSScreenUpdate` — submit email + password directly to `PASSWORD_LOGIN` screen
5. Optional `CLCSSendFeedback` if the response contains a feedback payload
6. Open `/browse` to finalize the authenticated session
7. `CLCSInterstitialProfileGate` probe
8. ALE provision via MSL (`aleProvision` handshake)

**Output:** `netflix_auth_cookies.json`

---

### MGK (Model Group Key)

Uses the **MGK / AUTHENTICATED_DH** MSL key-exchange scheme, authenticating with a pre-provisioned `KpeKph` key pair rather than a Widevine device.

**Requires two sidecar files:**

| File | Content |
|------|---------|
| `KpeKph` | Base64 AES-128 encryption key + Base64 HMAC-SHA256 key, comma-separated |
| `ESNID` | Model-group identity string (the MGK sender ESN) |

These files are discovered automatically in the working directory, any subdirectory, or via environment variables:

```bash
export MSL_KPEKPH_PATH=/path/to/KpeKph
export MSL_ESNID_PATH=/path/to/ESNID
```

Or pass `--kpekph` on the command line.

**MSL flow:**
1. Load `KpeKph` → derive wrapping key
2. Generate a DH keypair; build `AUTHENTICATED_DH` key-request with `mechanism=MGK`
3. Perform handshake → derive session encryption + HMAC keys from shared secret
4. Send `EMAIL_PASSWORD` user-auth message → receive `useridtoken`

**Output:** `useridtoken_mgk.json`, `netflix_auth_cookies_mgk.json`

---

## Usage

```bash
# Android
python main.py --platform android

# iOS
python main.py --platform ios

# TV (email/password)
python main.py --platform tv

# TV OTP (pairing code — interactive)
python main.py --platform tv_otp

# Web (Chrome emulation)
python main.py --platform web

# MGK (Model Group Key)
python main.py --platform mgk

# MGK with explicit KpeKph path
python main.py --platform mgk --kpekph /path/to/KpeKph

# Override WVD device for Android/iOS/TV/TV-OTP
python main.py --platform android --wvd /path/to/device.wvd

# Force a fresh MSL key exchange (ignore cached keys)
python main.py --platform tv --new-msl

# Disable TLS verification (not recommended)
python main.py --platform web --no-verify

# Pass a reCAPTCHA token for web login
python main.py --platform web --recaptcha-token <token>
```

### All flags

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--platform` / `-p` | all | **Required.** `android`, `ios`, `tv`, `tv_otp`, `web`, `mgk` |
| `--wvd` | android, ios, tv, tv_otp | Path to `.wvd` Widevine device file (optional override) |
| `--kpekph` | mgk | Path to `KpeKph` key file |
| `--new-msl` | all | Force a fresh MSL handshake, ignoring any cached keys |
| `--no-verify` | all | Disable TLS certificate verification |
| `--recaptcha-token` | web | reCAPTCHA v2 response token |

---

## Output Files

Each platform writes its results to the same directory as `main.py`:

| File | Platform(s) | Contents |
|------|-------------|----------|
| `netflix_auth_cookies.json` | android, ios, web | Session cookies (`NetflixId`, `SecureNetflixId`, etc.) |
| `netflix_auth_tokens.json` | android | Full MSL header data including `useridtoken` |
| `netflix_auth_useridtoken.json` | android | Extracted `useridtoken` only |
| `netflix_cookies.json` | tv, tv_otp | Filtered important cookies |
| `useridtoken.json` | tv, tv_otp | MSL `useridtoken` |
| `msl_debug_trace.json` | tv | Decrypted MSL payload trace log |
| `password_login_response.json` | tv | Raw CLCS credential-submit response |
| `useridtoken_mgk.json` | mgk | MSL `useridtoken` from MGK flow |
| `netflix_auth_cookies_mgk.json` | mgk | Session cookies from MGK flow |
| `msl_keys_cache_android.json` | android | Cached MSL session keys |
| `msl_keys_cache_ios.json` | ios | Cached MSL session keys |
| `msl_keys_cache.json` | tv, tv_otp | Cached MSL session keys |
| `msl_keys_cache_web.json` | web | Cached MSL session keys |
| `msl_keys_cache_mgk.json` | mgk | Cached MSL session keys |

MSL key caches are reused across runs to avoid a full handshake every time. They expire automatically when the master token has fewer than 10 hours remaining.

---

**Big thanks to [Hugoved](https://github.com/Hugoved)**
- for the foundational work on MSL (Message Security Layer) reverse engineering, and the original pywidevine implementation that made this unified handshake toolkit possible. This project builds upon years of community research into Netflix's authentication protocols.