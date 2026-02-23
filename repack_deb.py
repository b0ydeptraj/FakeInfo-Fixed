"""
Repack HelloChinese .deb:
- Sửa control: Architecture iphoneos-arm → iphoneos-arm64
- Giữ nguyên dylib (đã là arm64 bên trong)
- Output: HelloChinese_5.2.6_arm64.deb + HelloChinese.dylib riêng
"""
import struct, gzip, tarfile, io, os, time

DEB_IN   = r"C:\Users\b0ydeptrai\Downloads\com.laxus.hellochinese_5.2.6+iOSGods.com_iphoneos-arm.deb"
DEB_OUT  = r"C:\Users\b0ydeptrai\Downloads\HelloChinese_5.2.6_arm64.deb"
DYLIB_OUT = r"C:\Users\b0ydeptrai\Downloads\HelloChinese_arm64.dylib"

print("=== Reading .deb ===")
with open(DEB_IN, "rb") as f:
    assert f.read(8) == b"!<arch>\n"
    entries = {}
    while True:
        hdr = f.read(60)
        if len(hdr) < 60: break
        name = hdr[0:16].decode("ascii","replace").strip().rstrip("/")
        size = int(hdr[48:58].decode("ascii","replace").strip())
        data = f.read(size)
        if size % 2 == 1: f.read(1)
        entries[name] = (hdr, data)
        print(f"  Found: {name!r} ({size:,} bytes)")

# ─── Fix control ───────────────────────────────────────────────────────────
print("\n=== Fixing control ===")
old_ctrl_gz = entries["control.tar.gz"][1]
old_ctrl_tar = gzip.decompress(old_ctrl_gz)

# Read and patch control file in tar
tar_in = io.BytesIO(old_ctrl_tar)
tar_out_buf = io.BytesIO()
old_ctrl_content = None
new_ctrl_content = None

# Parse tar manually
while True:
    blk = tar_in.read(512)
    if not blk or blk == b'\x00' * 512: break
    fname = blk[0:100].rstrip(b'\x00').decode('ascii','replace')
    fsize_oct = blk[124:136].rstrip(b'\x00 ').decode('ascii','replace')
    fsize = int(fsize_oct, 8) if fsize_oct.strip() else 0
    content = tar_in.read(fsize)
    pad_size = (512 - fsize % 512) % 512 if fsize > 0 else 0
    tar_in.read(pad_size)
    if fname.endswith("control"):
        old_ctrl_content = content.decode("utf-8","replace")
        new_ctrl_content = old_ctrl_content.replace("Architecture: iphoneos-arm\n", "Architecture: iphoneos-arm64\n")
        print(f"  OLD: Architecture: iphoneos-arm")
        print(f"  NEW: Architecture: iphoneos-arm64")

# Rebuild control.tar.gz with patched control
new_ctrl_bytes = new_ctrl_content.encode("utf-8")
new_tar_buf = io.BytesIO()
with tarfile.open(fileobj=new_tar_buf, mode="w:gz") as t:
    ti = tarfile.TarInfo(name="./control")
    ti.size = len(new_ctrl_bytes)
    ti.mode = 0o644
    t.addfile(ti, io.BytesIO(new_ctrl_bytes))
new_ctrl_gz = new_tar_buf.getvalue()
print(f"  New control.tar.gz: {len(new_ctrl_gz)} bytes (was {len(old_ctrl_gz)})")

# ─── Extract dylib ─────────────────────────────────────────────────────────
print("\n=== Extracting HelloChinese.dylib ===")
data_gz = entries["data.tar.gz"][1]
data_tar = gzip.decompress(data_gz)
with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:") as t:
    m = t.getmember("Library/MobileSubstrate/DynamicLibraries/HelloChinese.dylib")
    dylib_data = t.extractfile(m).read()
    with open(DYLIB_OUT, "wb") as out:
        out.write(dylib_data)
    print(f"  Saved: {DYLIB_OUT} ({len(dylib_data):,} bytes)")

# ─── Write new .deb ────────────────────────────────────────────────────────
print("\n=== Writing new .deb ===")

def ar_entry(name, data):
    """Build an ar archive entry."""
    name_field = name.ljust(16)[:16]
    ts   = "0           "[:12]
    uid  = "0     "[:6]
    gid  = "0     "[:6]
    mode = "100644  "[:8]
    size = str(len(data)).ljust(10)[:10]
    fmag = "`\n"
    hdr  = (name_field + ts + uid + gid + mode + size + fmag).encode("ascii")
    assert len(hdr) == 60
    entry = hdr + data
    if len(data) % 2 == 1:
        entry += b"\n"
    return entry

with open(DEB_OUT, "wb") as f:
    f.write(b"!<arch>\n")
    # debian-binary
    f.write(ar_entry("debian-binary", entries["debian-binary"][1]))
    # control.tar.gz (patched)
    f.write(ar_entry("control.tar.gz", new_ctrl_gz))
    # data.tar.gz (original)
    f.write(ar_entry("data.tar.gz", data_gz))

size_mb = os.path.getsize(DEB_OUT) / 1024 / 1024
print(f"  Saved: {DEB_OUT} ({size_mb:.1f} MB)")
print("\n=== DONE ===")
print(f"  .deb (arm64) : {DEB_OUT}")
print(f"  .dylib (arm64): {DYLIB_OUT}")
print("\nTiêm vào app bằng TrollFools: dùng file HelloChinese_arm64.dylib")
