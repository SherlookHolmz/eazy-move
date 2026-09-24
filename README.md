[README.md](https://github.com/user-attachments/files/32607625/README.md)
# PasarGuard Manager

ابزار ساده برای **بکاپ، ریستور و انتقال PasarGuard Panel + PG-Node** از سرور قدیمی به سرور جدید.

**Developer:** Sherlook

## نصب آسان

هیچ نیازی نیست Python، pip، Paramiko، Docker یا Docker Compose را دستی نصب کنید.

روی سرور Ubuntu/Debian فقط اجرا کنید:

```bash
sudo bash install.sh
```

Installer خودش:

- پیش‌نیازهای سیستم را نصب می‌کند.
- Docker را در صورت نبودن نصب می‌کند.
- Docker Compose را در صورت نبودن نصب می‌کند.
- محیط Python را می‌سازد.
- وابستگی‌های Python را نصب می‌کند.
- برنامه را اجرا می‌کند.

بعد از نصب:

```bash
sudo ./run.sh
```

## استفاده

برنامه به‌صورت پیش‌فرض یک منوی ساده ترمینالی دارد و مراحل را خودش هدایت می‌کند:

```bash
sudo ./run.sh
```

امکانات اصلی:

- Backup کامل PasarGuard و PG-Node
- Restore بکاپ
- انتقال مستقیم از سرور قدیمی به سرور جدید با SSH/SFTP
- تشخیص خودکار دیتابیس
- بررسی سلامت و صحت Backup
- بررسی SHA-256 فایل انتقالی
- مدیریت NATS و Caddy در صورت شناسایی
- مدیریت فایل‌های SSL خارجی
- غیرفعال کردن Nodeهای منتقل‌شده برای جلوگیری از تداخل
- ارسال Backup به Telegram

## روند انتقال

```text
Old Server
    ↓
Backup
    ↓
SHA-256 Verification
    ↓
SSH/SFTP Transfer
    ↓
Restore
    ↓
Start Services
    ↓
Health Check
```

سرور قدیمی به‌صورت خودکار حذف یا خاموش نمی‌شود و فایل Backup نیز بعد از انتقال نگه داشته می‌شود.

## اجرای دستورات مستقیم

```bash
sudo ./run.sh check
sudo ./run.sh backup
sudo ./run.sh restore ./backup.zip
sudo ./run.sh migrate --host SERVER_IP
```

## نکته امنیتی

Backup ممکن است شامل `.env`، پسورد دیتابیس، API Key، اطلاعات Node و Private Key مربوط به SSL باشد.

**هرگز فایل Backup را داخل GitHub قرار ندهید.**

## ساختار پروژه

```text
pasarguard_manager.py   هسته اصلی برنامه
install.sh              Easy Installer
requirements.txt        وابستگی‌های Python
run.sh                  فایل اجرای برنامه
README.md               مستندات
```

## سیستم‌های پشتیبانی‌شده

در حال حاضر Easy Installer برای سرورهای **Ubuntu/Debian** طراحی شده است.

نسخه انگلیسی مستندات: [README.en.md](README.en.md)
