import os
import time
import psutil
import pymem as pm
import ctypes
from ctypes import wintypes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

target_exes = ["v1.exe", "v2.exe", "v3.exe", "v4.exe"]
USERPROFILE = os.getenv("USERPROFILE")
ORIG_PUBKEY = "5586b4bc69c7a4b487e4563a4cd96afd39140f919bd31cea7d1c6a1e8439422b".encode()

with open(f"{USERPROFILE}\\Documents\\cert\\ed.key", "rb") as f:
    privkey = serialization.load_pem_private_key(f.read(), password=None)
pubkey = privkey.public_key()
pubkey_bytes = pubkey.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
NEW_PUBKEY = pubkey_bytes.hex().encode()

def find_proc(procname):
    procname = procname.lower()
    for process in psutil.process_iter(['pid', 'name']):
        name = process.info['name']
        if name and name.lower() == procname:
            return process
    return None

def mem_scan(proc_con, orig_key, new_key, base_addr):
    patched_count = 0
    try:
        orig_hex = orig_key.decode().upper().encode()
        new_hex = new_key.decode().upper().encode()
        current_addr = 0x400000
        chunk_size = 0x1000
        max_addr = 0x700000
        found_in_unmapped = False
        while current_addr < max_addr:
            try:
                data = proc_con.read_bytes(current_addr, chunk_size)
                offset = 0
                while True:
                    pos = data.find(orig_key, offset)
                    if pos == -1:
                        break
                    addr = current_addr + pos
                    print(f"[scan] Found pubkey (pre-main): 0x{addr:X}")
                    if writemem(proc_con, addr, new_key, len(orig_key)):
                        patched_count += 1
                        if not found_in_unmapped:
                            found_in_unmapped = True
                    offset = pos + 1
                offset = 0
                while True:
                    pos = data.find(orig_hex, offset)
                    if pos == -1:
                        break
                    addr = current_addr + pos
                    print(f"[scan] Found pubkey (pre-main HEX): 0x{addr:X}")
                    if writemem(proc_con, addr, new_hex, len(orig_hex)):
                        print(f"[write] Patched pubkey (pre-main HEX): 0x{addr:X}")
                        patched_count += 1
                        if not found_in_unmapped:
                            found_in_unmapped = True
                    offset = pos + 1
            except Exception:
                pass
            current_addr += chunk_size
        current_addr = base_addr
        max_scan = 0x300000
        while current_addr < base_addr + max_scan:
            try:
                data = proc_con.read_bytes(current_addr, chunk_size)
                pos = data.find(orig_key)
                if pos != -1:
                    addr = current_addr + pos
                    print(f"[scan] Found pubkey (main): 0x{addr:X}")
                    if writemem(proc_con, addr, new_key, len(orig_key)):
                        print(f"[write] Patched pubkey (main): 0x{addr:X}")
                        patched_count += 1
                        break
                pos = data.find(orig_hex)
                if pos != -1:
                    addr = current_addr + pos
                    print(f"[scan] Found pubkey (main HEX): 0x{addr:X}")
                    if writemem(proc_con, addr, new_hex, len(orig_hex)):
                        print(f"[write] Patched pubkey (main HEX): 0x{addr:X}")
                        patched_count += 1
                        break
            except Exception:
                pass
            current_addr += chunk_size
    except Exception as e:
        print(f"[scan] Complete failure: {e}")
    return patched_count > 0

def writemem(proc_con, addr, new, expect_len):
    if len(new) != expect_len:
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        VirtualProtectEx = kernel32.VirtualProtectEx
        VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        VirtualProtectEx.restype = wintypes.BOOL
        old_protect = wintypes.DWORD()
        success = VirtualProtectEx(proc_con.process_handle, addr, len(new), 0x40, ctypes.byref(old_protect))
        if success:
            proc_con.write_bytes(addr, new, len(new))
            VirtualProtectEx(proc_con.process_handle, addr, len(new), old_protect.value, ctypes.byref(wintypes.DWORD()))
            readback = proc_con.read_bytes(addr, len(new))
            return readback == new
        else:
            return False
    except Exception:
        return False

def patch_exe(proc_name):
    exe_path = os.path.join(os.getcwd(), proc_name)
    if not os.path.exists(exe_path):
        print(f"[skip] {proc_name} 파일 없음")
        return
    proc = find_proc(proc_name)
    if proc:
        print(f"[kill] 기존 {proc_name} 프로세스 종료")
        try:
            psutil.Process(proc.pid).terminate()
            time.sleep(1)
        except Exception:
            pass
    print(f"[start] {proc_name} 실행")
    try:
        os.startfile(exe_path)
    except Exception as e:
        print(f"[err] {proc_name} 실행 실패: {e}")
        return
    for i in range(40):
        proc = find_proc(proc_name)
        if proc: break
        time.sleep(0.5)
    if not proc:
        print(f"[fail] {proc_name} 프로세스 못 찾음")
        return
    print(f"[info] {proc_name} 패치 시도 (pid {proc.pid})")
    try:
        proc_con = pm.Pymem(proc.pid)
        base_addr = proc_con.process_base.lpBaseOfDll
        patched = mem_scan(proc_con, ORIG_PUBKEY, NEW_PUBKEY, base_addr)
        if patched:
            print(f"[ok] {proc_name} 패치 성공")
        else:
            print(f"[fail] {proc_name} 패치 실패(키 미발견)")
        proc_con.close_process()
    except Exception as e:
        print(f"[err] {proc_name} 패치 중 오류: {e}")

if __name__ == "__main__":
    for exe in target_exes:
        patch_exe(exe)
        time.sleep(1)
    print("작업 완료")
