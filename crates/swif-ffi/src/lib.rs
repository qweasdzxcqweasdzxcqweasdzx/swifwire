//! C ABI — `swifwire.dll` / `libswifwire.so` / `libswifwire.dylib`.
//! Free every non-NULL `char*` from `*_alloc` / `err_out` with `swif_string_free`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::{Mutex, OnceLock};

use swif_core::{
    core_apply_mask_pack, core_import_subscription, core_legacy_fallback_uri, core_outbound_json,
    core_set_route_mode, core_start, core_status, core_stop, core_version, panel_inbound_edge_argv,
    panel_share_uri, CoreHandle,
};

struct HandleSlot {
    h: Option<CoreHandle>,
}

fn slot() -> &'static Mutex<HandleSlot> {
    static SLOT: OnceLock<Mutex<HandleSlot>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(HandleSlot { h: None }))
}

fn c_err(msg: &str) -> *mut c_char {
    CString::new(msg).unwrap_or_default().into_raw()
}

fn c_ok(s: String) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

#[no_mangle]
pub extern "C" fn swif_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

#[no_mangle]
pub extern "C" fn swif_abi_version() -> i32 {
    // Bump only on C ABI breaks. 0.3.0-prod keeps ABI = 1.
    1
}

#[no_mangle]
pub extern "C" fn swif_core_legacy_fallback_alloc(err_out: *mut *mut c_char) -> *mut c_char {
    let g = slot().lock().unwrap();
    let Some(h) = g.h.as_ref() else {
        set_err(err_out, "not started");
        return ptr::null_mut();
    };
    match core_legacy_fallback_uri(h) {
        Ok(Some(u)) => c_ok(u),
        Ok(None) => c_ok(String::new()),
        Err(e) => {
            set_err(err_out, &e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn swif_version() -> *mut c_char {
    c_ok(core_version())
}

#[no_mangle]
pub extern "C" fn swif_core_start(config_json: *const c_char, err_out: *mut *mut c_char) -> i32 {
    let cfg = unsafe {
        if config_json.is_null() {
            set_err(err_out, "null config");
            return 1;
        }
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(_) => {
                set_err(err_out, "config not utf8");
                return 1;
            }
        }
    };
    match core_start(cfg) {
        Ok(h) => {
            slot().lock().unwrap().h = Some(h);
            0
        }
        Err(e) => {
            set_err(err_out, &e.to_string());
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn swif_core_stop() {
    if let Some(h) = slot().lock().unwrap().h.take() {
        core_stop(h);
    }
}

#[no_mangle]
pub extern "C" fn swif_core_set_route_mode(mode: *const c_char, err_out: *mut *mut c_char) -> i32 {
    let mode = unsafe {
        if mode.is_null() {
            return 1;
        }
        CStr::from_ptr(mode).to_str().unwrap_or("")
    };
    let g = slot().lock().unwrap();
    let Some(h) = g.h.as_ref() else {
        set_err(err_out, "not started");
        return 1;
    };
    match core_set_route_mode(h, mode) {
        Ok(()) => 0,
        Err(e) => {
            set_err(err_out, &e.to_string());
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn swif_core_import_subscription(
    url_or_blob: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    let s = unsafe {
        if url_or_blob.is_null() {
            return 1;
        }
        CStr::from_ptr(url_or_blob).to_str().unwrap_or("")
    };
    let g = slot().lock().unwrap();
    let Some(h) = g.h.as_ref() else {
        set_err(err_out, "not started");
        return 1;
    };
    match core_import_subscription(h, s) {
        Ok(()) => 0,
        Err(e) => {
            set_err(err_out, &e.to_string());
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn swif_core_apply_mask_pack(
    data: *const u8,
    len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    if data.is_null() {
        return 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    let g = slot().lock().unwrap();
    let Some(h) = g.h.as_ref() else {
        set_err(err_out, "not started");
        return 1;
    };
    match core_apply_mask_pack(h, bytes) {
        Ok(()) => 0,
        Err(e) => {
            set_err(err_out, &e.to_string());
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn swif_core_status_alloc(err_out: *mut *mut c_char) -> *mut c_char {
    let g = slot().lock().unwrap();
    let Some(h) = g.h.as_ref() else {
        set_err(err_out, "not started");
        return ptr::null_mut();
    };
    match core_status(h) {
        Ok(s) => c_ok(s),
        Err(e) => {
            set_err(err_out, &e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn swif_core_outbound_alloc(err_out: *mut *mut c_char) -> *mut c_char {
    let g = slot().lock().unwrap();
    let Some(h) = g.h.as_ref() else {
        set_err(err_out, "not started");
        return ptr::null_mut();
    };
    match core_outbound_json(h) {
        Ok(s) => c_ok(s),
        Err(e) => {
            set_err(err_out, &e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn swif_panel_edge_argv_alloc(
    inbound_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = unsafe {
        if inbound_json.is_null() {
            return ptr::null_mut();
        }
        CStr::from_ptr(inbound_json).to_str().unwrap_or("")
    };
    match panel_inbound_edge_argv(s) {
        Ok(j) => c_ok(j),
        Err(e) => {
            set_err(err_out, &e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn swif_panel_share_uri_alloc(
    inbound_json: *const c_char,
    public_host: *const c_char,
    server_pub_hex: *const c_char,
    remark: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    unsafe {
        let ib = cstr(inbound_json);
        let host = cstr(public_host);
        let pubk = cstr(server_pub_hex);
        let rem = cstr(remark);
        match panel_share_uri(ib, host, pubk, rem) {
            Ok(u) => c_ok(u),
            Err(e) => {
                set_err(err_out, &e.to_string());
                ptr::null_mut()
            }
        }
    }
}

unsafe fn cstr(p: *const c_char) -> &'static str {
    if p.is_null() {
        ""
    } else {
        CStr::from_ptr(p).to_str().unwrap_or("")
    }
}

fn set_err(err_out: *mut *mut c_char, msg: &str) {
    if !err_out.is_null() {
        unsafe {
            *err_out = c_err(msg);
        }
    }
}
