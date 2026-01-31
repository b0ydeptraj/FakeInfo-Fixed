# Hướng dẫn Build FakeInfo Tweak (Fixed)

## Files đã tạo

Thư mục `fakeinfo-fix/` chứa:
- `Tweak.xm` - Source code đã fix
- `Makefile` - Build configuration  
- `control` - Package info
- `FakeInfo.plist` - Injection filter

## Build trên Mac/Linux với Theos

```bash
# 1. Clone Theos nếu chưa có
git clone --recursive https://github.com/theos/theos.git ~/theos
export THEOS=~/theos

# 2. Copy files vào thư mục project
mkdir -p ~/fakeinfo-fix
cp Tweak.xm Makefile FakeInfo.plist ~/fakeinfo-fix/
mkdir -p ~/fakeinfo-fix/layout/DEBIAN
cp control ~/fakeinfo-fix/layout/DEBIAN/

# 3. Build
cd ~/fakeinfo-fix
make package FINALPACKAGE=1
```

File `.deb` sẽ xuất hiện trong `packages/`.

## Những gì đã fix

### 1. Thêm original function pointers
```objc
static int (*orig_sysctlbyname_ptr)(...) = NULL;
// ... tương tự cho uname, stat, access, fopen, getifaddrs
```

### 2. MSHookFunction lưu orig pointer
```objc
// Trước (LỖI):
MSHookFunction(ptr, &fake_fn, NULL);

// Sau (FIX):
MSHookFunction(ptr, &fake_fn, (void**)&orig_ptr);
```

### 3. Fake functions gọi qua orig pointer
```objc
// Trước (LỖI - infinite recursion):
return sysctlbyname(...);

// Sau (FIX):
return orig_sysctlbyname_ptr(...);
```

## Test sau khi build

1. Inject `.deb` mới vào app qua TrollFools
2. App không được crash khi khởi động
3. Giữ 4 ngón tay 0.3s hoặc 1.5s để mở Settings UI
