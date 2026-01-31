# 🚀 Hướng dẫn Build FakeInfo bằng GitHub Actions

## Bước 1: Tạo Repository mới trên GitHub

1. Vào https://github.com/new
2. Đặt tên repo, ví dụ: `FakeInfo-Fixed`
3. Chọn **Public** (GitHub Actions miễn phí cho public repos)
4. Click **Create repository**

## Bước 2: Upload code lên GitHub

Mở Terminal/PowerShell tại thư mục `fakeinfo-fix` và chạy:

```powershell
cd "c:\Users\b0ydeptrai\OneDrive\Documents\prompt-genius\fakeinfo-fix"
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/FakeInfo-Fixed.git
git push -u origin main
```

> ⚠️ Thay `YOUR_USERNAME` bằng username GitHub của bạn

## Bước 3: Chờ GitHub Actions build

1. Vào tab **Actions** trong repo của bạn
2. Bạn sẽ thấy workflow **Build iOS Tweak** đang chạy
3. Đợi khoảng 2-5 phút để build xong

## Bước 4: Tải file .dylib

1. Click vào workflow run đã hoàn thành (có ✓ xanh)
2. Kéo xuống phần **Artifacts**
3. Tải **FakeInfo-dylib** (chứa file .dylib để dùng với TrollFools)
4. Hoặc tải **FakeInfo-deb** (chứa file .deb đầy đủ)

## Sử dụng với TrollFools

1. Giải nén file đã tải để lấy `FakeInfo.dylib`
2. Mở TrollFools trên iPhone
3. Chọn app muốn inject
4. Thêm `FakeInfo.dylib` vào app
5. Khởi động app - giữ 4 ngón tay 0.3s hoặc 1.5s để mở Settings

---

**Nếu gặp lỗi**, screenshot và gửi cho tôi!
