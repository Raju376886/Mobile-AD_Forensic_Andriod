# Mobile-AD_Forensic_Andriod
# 📄 Android App Infrastructure & Spoofing Investigation Report

**Prepared by:** RAJU  
**Date:** July 6, 2025  
**Scope:** Investigate relationships, shared infrastructure, and potential spoofing behavior across selected Android apps.

---

## 📦 Target Apps for Analysis

| App Name               | Package Name                  | Publisher              |
|------------------------|-------------------------------|------------------------|
| Downhill Racer         | io.supercent.downhill         | Supercent, Inc.        |
| Ball Drop Game ASMR    | io.supercent.plinko           | Supercent, Inc.        |
| Italian Radio          | com.appmind.radios.it         | AppMind                |
| Radio Romania Online   | radio.online.romania          | AppMind-Radio FM       |
| Word Find              | word.find                     | Unknown                |
| Idle Painter           | com.hwg.idlepainter           | SayGames Ltd.          |

---

## 🧬 Related Apps (Suspected Shared Infrastructure)

- io.supercent.powerdig  
- io.supercent.noodle  
- radio.saudi.arabia  
- radio.player.ireland  
- radio.algerie.gratuite  
- radio.serbia  

---

## 🛠️ Tools & Techniques Used

| Category              | Tools / Techniques                                                                 |
|-----------------------|-------------------------------------------------------------------------------------|
| Static Analysis       | MobSF, APKTool, JADX                                                                |
| Dynamic Analysis      | mitmproxy, Charles Proxy, Frida, Objection                                          |
| Network Intelligence  | Shodan, Censys, VirusTotal, WHOIS, IPinfo                                           |
| Runtime Logging       | Android emulator with SSL unpinning, Logcat, Frida hooks                            |

---

## 🔍 Findings

### 1. SDK & Permission Overlap

| SDK / Tracker           | Found In Apps                                      |
|-------------------------|----------------------------------------------------|
| AppLovin                | io.supercent.downhill, io.supercent.plinko         |
| Unity Ads               | io.supercent.downhill, io.supercent.plinko         |
| Firebase Analytics      | All Supercent and AppMind apps                     |
| Google AdMob            | All except `word.find` (APK not available)         |
| Facebook Audience Net   | AppMind radio apps                                 |

**Suspicious Permissions Observed:**
- `android.permission.REQUEST_INSTALL_PACKAGES` (Supercent apps)
- `android.permission.READ_PHONE_STATE` (AppMind apps)
- `android.permission.SYSTEM_ALERT_WINDOW` (Idle Painter)

---

### 2. Network Behavior & Shared Infrastructure

| Indicator                  | Observation                                                                 |
|----------------------------|------------------------------------------------------------------------------|
| Shared IPs / Domains       | `ads.applovin.com`, `track.appsflyer.com`, `firebaseinstallations.googleapis.com` |
| TLS Certificate Reuse      | Supercent apps share wildcard certs issued to `*.supercent.io`               |
| CDN Usage                  | All apps use Cloudflare or Google CDN                                        |
| Ad Request Patterns        | Similar payload structure, reused `ad_unit_id`, and inflated impression counts |
| User-Agent Spoofing        | Some apps report generic `Dalvik/2.1.0` or mismatched Android versions       |

---

### 3. Code-Based Indicators

#### A. Obfuscated SDKs
- Supercent apps use ProGuard-obfuscated SDKs with class names like `a.a.a.a` and `b.b.b.b`
- Shared analytics SDKs (e.g., AppLovin, Firebase) use identical initialization logic

#### B. Hardcoded Endpoints
- `io.supercent.downhill` and `io.supercent.plinko` both reference:


#### C. Frida Runtime Hooks
- Hooking `WebView.loadUrl()` and `AdRequest.build()` revealed:
- Reused ad tags across unrelated apps
- Dynamic injection of `packageName` into payloads

---

## 🧠 Hypothesis

Based on the evidence, the behavior observed is likely due to:

### 🔸 Option 1: Poorly Architected SDK
- SDKs like AppLovin and Unity Ads may be reusing identifiers or misreporting package names due to improper integration.
- Developers may be unaware of the implications.

### 🔸 Option 2: Coordinated Ad Fraud (More Likely)
- Shared infrastructure, obfuscated SDKs, and inflated ad metrics suggest intentional behavior.
- The reuse of ad tags and spoofed package names aligns with known ad fraud tactics.

### 🔸 Option 3: Botnet-Like Behavior
- If traffic is automated or emulated (e.g., via Android emulators), this may indicate a click fraud botnet.
- Further investigation needed via behavioral sandboxing.

---

## ✅ Recommendations

- Flag all Supercent and AppMind apps for enhanced scrutiny in ad attribution pipelines.
- Monitor for:
- Reused `ad_unit_id` across apps
- Suspicious `User-Agent` and `X-Requested-With` headers
- High-frequency ad requests with low user interaction
- Use Frida or Xposed modules to hook ad SDKs at runtime for deeper inspection.

---
Python script to automate this investigation -

import json
from collections import defaultdict
import re

# === Known Legitimate Packages ===
KNOWN_PACKAGES = {
    "io.supercent.downhill": "Downhill Racer",
    "io.supercent.plinko": "Ball Drop Game",
    "com.appmind.radios.it": "Italian Radio",
    "radio.online.romania": "Radio Romania",
    "com.hwg.idlepainter": "Idle Painter"
}

# === Suspected Shared Network or Spoofing Targets ===
SUSPECTED_NETWORK = {
    "io.supercent.powerdig",
    "io.supercent.noodle",
    "radio.saudi.arabia",
    "radio.player.ireland",
    "radio.algerie.gratuite",
    "radio.serbia"
}

# === Helper Functions ===
def extract_package(payload):
    for key in ['package', 'package_name', 'app_package', 'app_id']:
        if key in payload:
            return payload[key]
    return None

def extract_user_agent(headers):
    for h in headers:
        if h['name'].lower() == 'user-agent':
            return h['value']
    return None

def is_suspicious_ua(ua):
    return bool(re.search(r'Dalvik|curl|python|okhttp/1|Android 2', ua, re.IGNORECASE))

def extract_ad_unit(payload):
    for key in ['ad_unit_id', 'placement_id', 'slot_id']:
        if key in payload:
            return payload[key]
    return None

# === Main Analysis ===
def analyze_traffic(log_file):
    with open(log_file, 'r') as f:
        traffic = json.load(f)

    anomalies = []
    package_usage = defaultdict(set)
    ad_unit_map = defaultdict(set)

    for entry in traffic:
        try:
            req = entry['request']
            headers = req.get('headers', [])
            body = req.get('postData', {}).get('text', '{}')
            payload = json.loads(body) if body.strip().startswith('{') else {}

            pkg = extract_package(payload)
            ua = extract_user_agent(headers)
            url = req.get('url', '')
            ad_unit = extract_ad_unit(payload)

            if pkg:
                package_usage[pkg].add(url)
                if pkg not in KNOWN_PACKAGES and pkg in SUSPECTED_NETWORK:
                    anomalies.append({
                        'type': 'Shared Infrastructure or Spoofed Package',
                        'package': pkg,
                        'url': url
                    })

            if ua and is_suspicious_ua(ua):
                anomalies.append({
                    'type': 'Suspicious User-Agent',
                    'user_agent': ua,
                    'url': url
                })

            if ad_unit and pkg:
                ad_unit_map[ad_unit].add(pkg)

        except Exception as e:
            print(f"[!] Error parsing entry: {e}")

    return anomalies, package_usage, ad_unit_map

# === Entry Point ===
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Analyze Android traffic logs for spoofing and shared infrastructure")
    parser.add_argument("log_file", help="Path to HTTP traffic log (JSON format)")
    args = parser.parse_args()

    anomalies, usage, ad_units = analyze_traffic(args.log_file)

    print("\n=== 🚨 Detected Anomalies ===")
    for a in anomalies:
        print(f"[{a['type']}] → {a.get('package') or a.get('user_agent')} @ {a['url']}")

    print("\n=== 📦 Package Usage Summary ===")
    for pkg, urls in usage.items():
        print(f"{pkg} → {len(urls)} unique endpoints")

    print("\n=== 🎯 Ad Unit Reuse Across Packages ===")
    for ad, pkgs in ad_units.items():
        if len(pkgs) > 1:
            print(f"Ad Unit `{ad}` used by: {', '.join(pkgs)}")


            
