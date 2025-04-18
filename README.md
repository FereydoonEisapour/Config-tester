# V2Ray Multi-Protocol Server Tester

این پروژه برای پردازش و تست لینک‌های V2Ray از فایل‌های GitHub طراحی شده است.

## اجرای خودکار در GitHub Actions

با هر Push به پروژه، فایل `app.py` اجرا می‌شود و لینک‌های موجود در `Files/git_links.txt` را تست می‌کند.

## استفاده

1. لینک‌ها را در فایل `Files/git_links.txt` قرار دهید.
2. فایل را به مخزن Push کنید.
3. نتایج در `Tested Servers/` و `logs/` ذخیره خواهد شد.
