# SecretoBoot Enterprise v7.1 Stable

نسخة مستقرة من SecretoBoot Enterprise لإدارة الإقلاع المزدوج بين **Windows 11** و **Google TV OS** باستعمال rEFInd.

## المميزات

- واجهة احترافية باسم Secretofnet.
- إدخالات يدوية فقط.
- منع تكرار Windows وGoogle TV.
- إصلاح أيقونة Google TV.
- نسخ احتياطي تلقائي من `refind.conf`.
- سكريبت تثبيت بضغطة واحدة.
- أدوات فحص واسترجاع.

## طريقة التثبيت

1. قم بفك الضغط عن الملف.
2. افتح مجلد `Scripts`.
3. اضغط بزر الفأرة الأيمن على:
   `Install_SecretoBoot_Enterprise_v7_1.cmd`
4. اختر **Run as administrator**.
5. أعد تشغيل الجهاز.

## المتطلبات

- جهاز يعمل بنظام UEFI.
- rEFInd مثبت مسبقًا.
- Windows 11.
- قسم Google TV باسم `BOOT`.
- وجود الملف:
  `EFI\BOOT\BOOTx64.EFI`

## الاسترجاع

افتح:

`Scripts\Open_Backups.cmd`

ثم استرجع نسخة `refind.conf` المناسبة من مجلد النسخ الاحتياطية.

© 2026 Secretofnet - جميع الحقوق محفوظة.
