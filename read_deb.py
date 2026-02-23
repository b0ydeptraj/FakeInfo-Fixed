"""
Đọc chỉ phần đầu của HelloChinese.dylib trong .deb để xác định Mach-O architecture.
Dùng streaming reader - không load cả file vào RAM.
"""
import struct, gzip, io, zlib

DEB = r"C:\Users\b0ydeptrai\Downloads\com.laxus.hellochinese_5.2.6+iOSGods.com_iphoneos-arm.deb"

CPU_NAMES = {
    12:         "armv7 (32-bit)",
    0xC:        "armv7 (32-bit)",
    0x100000C:  "arm64",
    0x200000C:  "arm64e",
}

def parse_fat(data28):
    """Parse first 28 bytes: FAT magic + nfat + first fat_arch entry."""
    magic  = struct.unpack_from(">I", data28, 0)[0]
    nfat   = struct.unpack_from(">I", data28, 4)[0]
    print(f"  FAT magic : 0x{magic:08X}")
    print(f"  Num slices: {nfat}")
    for i in range(min(nfat, 4)):
        off = 8 + i * 20
        if off + 16 > len(data28):
            break
        cpu_type    = struct.unpack_from(">I", data28, off)[0]
        cpu_subtype = struct.unpack_from(">I", data28, off + 4)[0]
        sl_off      = struct.unpack_from(">I", data28, off + 8)[0]
        sl_size     = struct.unpack_from(">I", data28, off + 12)[0]
        name = CPU_NAMES.get(cpu_type, f"cpu=0x{cpu_type:08X}")
        print(f"  Slice {i}   : {name}  subtype=0x{cpu_subtype:08X}  offset={sl_off}  size={sl_size:,}")

# ─── Parse .deb ar format ───────────────────────────────────────────────────
print(f"Reading: {DEB}\n")
with open(DEB, "rb") as f:
    assert f.read(8) == b"!<arch>\n"

    while True:
        hdr = f.read(60)
        if len(hdr) < 60:
            break
        name    = hdr[0:16].decode("ascii", "replace").strip().rstrip("/")
        size    = int(hdr[48:58].decode("ascii", "replace").strip())
        pos     = f.tell()
        
        print(f"[ar] {name!r}  ({size:,} bytes)")

        if name == "control.tar.gz":
            raw = f.read(size)
            if size % 2 == 1: f.read(1)
            # gunzip then find control file in tar
            gz = gzip.decompress(raw)
            # tar: 512-byte blocks, header then data
            tar = io.BytesIO(gz)
            while True:
                blk = tar.read(512)
                if not blk or blk == b'\x00' * 512: break
                fname = blk[0:100].rstrip(b'\x00').decode('ascii','replace')
                fsize_oct = blk[124:136].rstrip(b'\x00 ').decode('ascii','replace')
                fsize = int(fsize_oct, 8) if fsize_oct.strip() else 0
                content = tar.read(fsize)
                # pad to 512 boundary
                pad = (512 - fsize % 512) % 512
                tar.read(pad)
                if fname.endswith("control") and fsize > 0:
                    print(content.decode("utf-8", "replace"))
                    break

        elif name == "data.tar.gz":
            # Stream decompress gzip, find dylib tar entry, read only its header
            # Read enough to find the dylib offset in tar
            raw = f.read(size)
            if size % 2 == 1: f.read(1)
            gz = gzip.decompress(raw)
            tar = io.BytesIO(gz)
            while True:
                blk = tar.read(512)
                if not blk or blk == b'\x00' * 512: break
                fname = blk[0:100].rstrip(b'\x00').decode('ascii','replace')
                fsize_oct = blk[124:136].rstrip(b'\x00 ').decode('ascii','replace')
                fsize = int(fsize_oct, 8) if fsize_oct.strip() else 0
                if fname.endswith("HelloChinese.dylib") and fsize > 0:
                    # Read only first 128 bytes for FAT+Mach-O header
                    header = tar.read(min(128, fsize))
                    print(f"\n=== {fname} ===")
                    print(f"  Size: {fsize:,} bytes")
                    print(f"  First 8 bytes: {header[:8].hex().upper()}")
                    magic = struct.unpack_from(">I", header, 0)[0]
                    if magic == 0xCAFEBABE:
                        parse_fat(header[:min(128, len(header))])
                    else:
                        m_le = struct.unpack_from("<I", header, 0)[0]
                        print(f"  Magic LE: 0x{m_le:08X} → {CPU_NAMES.get(m_le, 'unknown')}")
                    break
                else:
                    pad = (512 - fsize % 512) % 512 if fsize > 0 else 0
                    tar.seek(fsize + pad, 1)
        else:
            f.seek(size, 1)
            if size % 2 == 1: f.seek(1, 1)

print("\nDone.")
