# PasarGuard Manager

ابزار ساده برای **بکاپ، ریستور و انتقال PasarGuard Panel + PG-Node** از سرور قدیمی به سرور جدید.

**Developer:** Sherlook

## نصب آسان

فقط روی سرور **Ubuntu/Debian** این دستور را اجرا کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/SherlookHolmz/eazy-move/main/install.sh | sudo bash
```

Installer خودش:

- Python و پیش‌نیازها را نصب می‌کند.
- Docker و Docker Compose را در صورت نیاز نصب می‌کند.
- پروژه را از همین GitHub دریافت می‌کند.
- محیط Python می‌سازد و وابستگی‌ها را نصب می‌کند.
- برنامه را اجرا می‌کند.

### نصب دستی

```bash
git clone https://github.com/SherlookHolmz/eazy-move.git
cd eazy-move
sudo bash install.sh
```

بعد از نصب، برای اجرای دوباره:

```bash
sudo /opt/eazy-move/run.sh
```

## امکانات

- Backup و Restore
- انتقال مستقیم با SSH/SFTP
- تشخیص دیتابیس
- بررسی SHA-256 بکاپ
- بررسی سلامت سرویس‌ها
- پشتیبانی از NATS و Caddy در صورت شناسایی
- مدیریت Certificateهای خارجی
- جلوگیری از تداخل Nodeهای منتقل‌شده
- ارسال Backup به Telegram

## دستورات

```bash
sudo /opt/eazy-move/run.sh check
sudo /opt/eazy-move/run.sh backup
sudo /opt/eazy-move/run.sh restore ./backup.zip
sudo /opt/eazy-move/run.sh migrate --host SERVER_IP
```

منوی داخل برنامه و تمام پیام‌های ترمینال **انگلیسی** هستند تا در SSH و ترمینال‌های مختلف مشکل RTL نداشته باشند.

## هشدار امنیتی

Backup ممکن است شامل `.env`، رمز دیتابیس، API Key، اطلاعات Node و Private Keyهای SSL باشد.

**فایل Backup را داخل GitHub قرار ندهید.**

## ساختار پروژه

```text
install.sh              Easy Installer
run.sh                  اجرای برنامه
pasarguard_manager.py   هسته اصلی برنامه
requirements.txt        وابستگی‌های Python
README.md               راهنمای فارسی
README.en.md            English README
```

[نسخه انگلیسی](README.en.md)
