// language: Rust, file: src/vmm.rs, target: Windows x86_64, MSVC
use libloading::{Library, Symbol};
use std::ffi::CString;
use std::path::Path;
use std::os::windows::ffi::OsStrExt;

#[link(name = "kernel32")]
extern "system" {
    fn SetDllDirectoryW(lpPathName: *const u16) -> i32;
}

type VmmHandle = *mut std::ffi::c_void;

type FnVmmdllInitialize = unsafe extern "system" fn(argc: u32, argv: *const *const i8) -> VmmHandle;
type FnVmmdllClose = unsafe extern "system" fn(hVMM: VmmHandle) -> bool;
type FnVmmdllPidGetFromName = unsafe extern "system" fn(hVMM: VmmHandle, szProcName: *const i8, pdwPID: *mut u32) -> bool;
type FnVmmdllProcessGetModuleBaseU = unsafe extern "system" fn(hVMM: VmmHandle, dwPID: u32, uszModuleName: *const i8) -> u64;
type FnVmmdllMemReadEx = unsafe extern "system" fn(hVMM: VmmHandle, dwPID: u32, qwA: u64, pb: *mut u8, cb: u32, pcbReadOpt: *mut u32, flags: u64) -> bool;
type FnVmmdllConfigSet = unsafe extern "system" fn(hVMM: VmmHandle, fOption: u64, qwValue: u64) -> bool;
type FnVmmdllMapGetVadU = unsafe extern "system" fn(hVMM: VmmHandle, dwPID: u32, fIdentifyModules: bool, ppVadMap: *mut *mut u8) -> bool;
type FnVmmdllMemFree = unsafe extern "system" fn(pv: *mut std::ffi::c_void);

const VMMDLL_OPT_REFRESH_ALL: u64 = 0x2001ffff00000000;
const VMMDLL_OPT_REFRESH_FREQ_MEDIUM: u64 = 0x2001000100000000;

pub struct Vmm {
    _lib: Library,
    handle: VmmHandle,
    fn_close: FnVmmdllClose,
    fn_pid_get: FnVmmdllPidGetFromName,
    fn_mod_base: FnVmmdllProcessGetModuleBaseU,
    fn_mem_read: FnVmmdllMemReadEx,
    fn_config_set: Option<FnVmmdllConfigSet>,
    fn_map_get_vad: Option<FnVmmdllMapGetVadU>,
    fn_mem_free: Option<FnVmmdllMemFree>,
}

unsafe impl Send for Vmm {}
unsafe impl Sync for Vmm {}

impl Vmm {
    pub fn new(dll_path: &Path, args: &[&str]) -> Result<Self, String> {
        if let Some(parent) = dll_path.parent() {
            let wide: Vec<u16> = parent.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
            unsafe { SetDllDirectoryW(wide.as_ptr()); }
        }

        let lib = unsafe { Library::new(dll_path).map_err(|e| format!("Failed to load vmm.dll: {}", e))? };

        let fn_init: FnVmmdllInitialize = *unsafe {
            let s: Symbol<FnVmmdllInitialize> = lib.get(b"VMMDLL_Initialize\0").map_err(|e| format!("Symbol VMMDLL_Initialize: {}", e))?;
            s
        };
        let fn_close: FnVmmdllClose = *unsafe {
            let s: Symbol<FnVmmdllClose> = lib.get(b"VMMDLL_Close\0").map_err(|e| format!("Symbol VMMDLL_Close: {}", e))?;
            s
        };
        let fn_pid_get: FnVmmdllPidGetFromName = *unsafe {
            let s: Symbol<FnVmmdllPidGetFromName> = lib.get(b"VMMDLL_PidGetFromName\0").map_err(|e| format!("Symbol VMMDLL_PidGetFromName: {}", e))?;
            s
        };
        let fn_mod_base: FnVmmdllProcessGetModuleBaseU = *unsafe {
            let s: Symbol<FnVmmdllProcessGetModuleBaseU> = lib.get(b"VMMDLL_ProcessGetModuleBaseU\0").map_err(|e| format!("Symbol VMMDLL_ProcessGetModuleBaseU: {}", e))?;
            s
        };
        let fn_mem_read: FnVmmdllMemReadEx = *unsafe {
            let s: Symbol<FnVmmdllMemReadEx> = lib.get(b"VMMDLL_MemReadEx\0").map_err(|e| format!("Symbol VMMDLL_MemReadEx: {}", e))?;
            s
        };
        let fn_config_set: Option<FnVmmdllConfigSet> = unsafe {
            lib.get::<FnVmmdllConfigSet>(b"VMMDLL_ConfigSet\0").ok().map(|s| *s)
        };
        let fn_map_get_vad: Option<FnVmmdllMapGetVadU> = unsafe {
            lib.get::<FnVmmdllMapGetVadU>(b"VMMDLL_Map_GetVadU\0").ok().map(|s| *s)
        };
        let fn_mem_free: Option<FnVmmdllMemFree> = unsafe {
            lib.get::<FnVmmdllMemFree>(b"VMMDLL_MemFree\0").ok().map(|s| *s)
        };

        // Convert args to C strings
        let c_strings: Vec<CString> = args.iter().map(|&s| CString::new(s).unwrap()).collect();
        let c_ptrs: Vec<*const i8> = c_strings.iter().map(|cs| cs.as_ptr()).collect();

        let handle = unsafe { fn_init(c_ptrs.len() as u32, c_ptrs.as_ptr()) };
        if handle.is_null() {
            return Err("VMMDLL_Initialize returned NULL. Check FPGA connection and LeechCore.".into());
        }

        Ok(Self {
            _lib: lib,
            handle,
            fn_close,
            fn_pid_get,
            fn_mod_base,
            fn_mem_read,
            fn_config_set,
            fn_map_get_vad,
            fn_mem_free,
        })
    }

    pub fn refresh_all(&self) {
        if let Some(set_fn) = self.fn_config_set {
            unsafe {
                (set_fn)(self.handle, VMMDLL_OPT_REFRESH_ALL, 1);
                (set_fn)(self.handle, VMMDLL_OPT_REFRESH_FREQ_MEDIUM, 1);
            }
        }
    }

    pub fn get_pid(&self, proc_name: &str) -> Option<u32> {
        let c_name = CString::new(proc_name).ok()?;
        let mut pid: u32 = 0;
        let ok = unsafe { (self.fn_pid_get)(self.handle, c_name.as_ptr(), &mut pid) };
        if ok && pid != 0 {
            Some(pid)
        } else {
            None
        }
    }

    pub fn get_module_base(&self, pid: u32, mod_name: &str) -> Option<u64> {
        let c_name = CString::new(mod_name).ok()?;
        let base = unsafe { (self.fn_mod_base)(self.handle, pid, c_name.as_ptr()) };
        if base != 0 {
            Some(base)
        } else {
            None
        }
    }

    pub fn read(&self, pid: u32, va: u64, buf: &mut [u8]) -> bool {
        let mut read_bytes: u32 = 0;
        // VMMDLL_FLAG_NOCACHE = 0x0001
        unsafe { (self.fn_mem_read)(self.handle, pid, va, buf.as_mut_ptr(), buf.len() as u32, &mut read_bytes, 0x0001) }
    }

    pub fn read_val<T: Copy>(&self, pid: u32, va: u64) -> Option<T> {
        let mut val = std::mem::MaybeUninit::<T>::uninit();
        let buf = unsafe {
            std::slice::from_raw_parts_mut(val.as_mut_ptr() as *mut u8, std::mem::size_of::<T>())
        };
        if self.read(pid, va, buf) {
            Some(unsafe { val.assume_init() })
        } else {
            None
        }
    }

    pub fn read_string(&self, pid: u32, va: u64, max_len: usize) -> String {
        let mut buf = vec![0u8; max_len];
        if !self.read(pid, va, &mut buf) {
            return String::new();
        }
        if let Some(pos) = buf.iter().position(|&b| b == 0) {
            buf.truncate(pos);
        }
        String::from_utf8_lossy(&buf).trim().to_string()
    }

    pub fn get_vad_ranges(&self, pid: u32) -> Vec<(u64, u64)> {
        let mut ranges = Vec::new();
        let Some(fn_map) = self.fn_map_get_vad else { return ranges; };
        let mut p_map: *mut u8 = std::ptr::null_mut();
        if !unsafe { (fn_map)(self.handle, pid, false, &mut p_map) } || p_map.is_null() {
            return ranges;
        }

        unsafe {
            let c_map = *(p_map.add(36) as *const u32) as usize;
            let entries_ptr = p_map.add(40);
            for i in 0..c_map {
                let entry_ptr = entries_ptr.add(i * 96);
                let va_start = *(entry_ptr as *const u64);
                let va_end = *(entry_ptr.add(8) as *const u64);
                let flags0 = *(entry_ptr.add(24) as *const u32);
                let flags1 = *(entry_ptr.add(28) as *const u32);

                // Filter: must be committed memory
                let is_commit = (flags1 & 0x8000_0000) != 0;
                if !is_commit { continue; }

                // Filter: exclude image and file mappings (bit 3: fImage, bit 4: fFile)
                let is_image = (flags0 & (1 << 3)) != 0;
                let is_file = (flags0 & (1 << 4)) != 0;
                if is_image || is_file { continue; }

                // Filter: private memory allocations or native heaps (bit 5: fPrivateMemory, bit 15: fHeap)
                let is_private = (flags0 & (1 << 5)) != 0;
                let is_heap = (flags0 & (1 << 15)) != 0;
                if !is_private && !is_heap { continue; }

                if va_start > 0 && va_end > va_start {
                    ranges.push((va_start, va_end));
                }
            }
            if let Some(fn_free) = self.fn_mem_free {
                (fn_free)(p_map as *mut _);
            }
        }
        ranges
    }
}

impl Drop for Vmm {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.fn_close)(self.handle) };
        }
    }
}
