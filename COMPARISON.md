#!/usr/bin/env python3
"""
Comparison: extract_apk_endpoints.py vs apkleaks
====================================================

TOOL 1: extract_apk_endpoints.py (بتاعتك)
- يشتغل على APK مباشرة
- يستخدم ZIP walking + jadx decompilation
- يطلع third-party و business logic endpoints
- يطلع أقل نتايج لكن أقرب للـ real

TOOL 2: apkleaks
- يشتغل على APK مباشرة (نفسه تقريباً)
- يستخدم grep + multiple passes
- يطلع كل الـ strings الممكنة
- يطلع نتايج أكتر + Google/internal APIs
- يطلع secrets وكلمات مرور hardcoded

====================================================

PROS & CONS:

extract_apk_endpoints.py:
✅ يركز على real API endpoints فقط
✅ فلترة ذكية للـ false positives
✅ نتايج clean ومشفوفة
✅ سهل الاستخدام
❌ قد يطلع endpoints أقل
❌ ممكن يتخطى بعض الـ endpoints المخفية

apkleaks:
✅ يطلع endpoints أكتر من الـ extract tool
✅ يطلع secrets وAPI keys hardcoded
✅ يطلع Google/Firebase endpoints كاملة
✅ يطلع class names والـ internal APIs
❌ فيها false positives كتير
❌ نتايج مخلوطة وفيها noise
❌ محتاج parsing/filtering يدوي

====================================================
"""

COMPARISON = """
REAL-WORLD TEST: YouTube APK
=============================

TOOL: extract_apk_endpoints.py
-------------------------------
Found 7 endpoints:

GET http://filter.smart.com.ph/api/youtube/
POST https://clarorecarga.claro.com.br/claro_youtube/login
GET https://identity.safaricom.com/youtube-upsell/api/v1/product/subscription
GET https://webview.static.ddt.telenor.io/v2/webshop/youtube
POST https://www.microsoft.com/...

[Type: Third-party carrier/billing endpoints]


TOOL: apkleaks
---------------
Found 20+ endpoints:

GET https://autopush-notifications-pa.sandbox.googleapis.com:443
GET https://c2paregistration.pa.googleapis.com:443
GET https://fcmregistrations.googleapis.com/v1/projects/
GET https://green-youtubei.sandbox.googleapis.com
GET https://notifications-pa.googleapis.com:443
GET https://staging-qual-c2paregistration.sandbox.googleapis.com
GET https://test-youtubei.sandbox.googleapis.com
GET https://www.googleapis.com/auth/accounts.reauth
GET https://www.googleapis.com/auth/assistant-sdk-prototype
GET https://www.googleapis.com/auth/youtube
GET https://www.youtube.com/api/lounge
GET https://www.youtube.com/api/loungedev
GET https://www.youtube.com/api/loungesandbox
GET https://www.youtube.com/api/loungestaging
GET https://www.youtube.com/api/stats/reliability_probe
GET https://www.youtube.com/api/syncwatch/bc/bind
GET https://youtubei.googleapis.com
GET https://youtubei.googleapis.com/generate_204

+ SECRETS FOUND:
- Google API Keys
- OAuth credentials
- Internal environment URLs (dev, staging, sandbox)

[Type: Google/YouTube internal + infrastructure endpoints]

=============================

VERDICT:
--------

1️⃣ FOR PENTEST / BUG BOUNTY:
   ➜ استخدم extract_apk_endpoints.py
   ➜ بتطلع business logic endpoints بسرعة
   ➜ أقل noise وأسهل في الـ testing

2️⃣ FOR FULL RECONNAISSANCE:
   ➜ استخدم apkleaks
   ➜ بتطلع كل حاجة (secrets + internal APIs)
   ➜ محتاج manual review للـ false positives
   ➜ بتطلع environment URLs (dev/staging/sandbox)

3️⃣ FOR MAXIMUM COVERAGE:
   ➜ استخدم الاثنين معاً!
   ➜ parse output من apkleaks بالـ parse_apkleaks.py
   ➜ اجمع النتايج من extract_apk_endpoints.py
   ➜ اطرح duplicates
   ➜ بتطلع comprehensive list من كل الـ endpoints

=============================

RECOMMENDATION:
---------------

✅ الـ BEST APPROACH:

1. شغّل apkleaks أولاً:
   $ apkleaks -f app.apk > secrets.txt

2. استخرج الـ APIs من apkleaks:
   $ python3 parse_apkleaks.py secrets.txt -o apis_from_apkleaks.txt

3. شغّل extract_apk_endpoints.py:
   $ python3 extract_apk_endpoints.py app.apk -o apis_from_extract.txt

4. اجمع النتايج (remove duplicates):
   $ cat apis_from_*.txt | sort -u > final_endpoints.txt

بتطلع أقوى وأشمل نتايج! 🎯
"""

print(COMPARISON)
