#![allow(non_snake_case)]

use std::{ffi::c_void, mem::transmute};

use gethostbyname::hook_host_lookup;
use log::{debug, info, LevelFilter};
use simplelog::{
    ColorChoice, CombinedLogger, Config, ConfigBuilder, TermLogger, TerminalMode, WriteLogger,
};
use windows::{
    core::{s, w, IUnknown, GUID, HRESULT},
    Win32::{
        Foundation::{HINSTANCE, HMODULE},
        System::LibraryLoader::{DisableThreadLibraryCalls, GetProcAddress, LoadLibraryW},
    },
};

mod gethostbyname;
mod mem;

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

type DirectInput8CreateFunc =
    extern "system" fn(HINSTANCE, u32, *const GUID, *mut *mut c_void, IUnknown) -> HRESULT;

type IPHLPAPIGetAdaptersInfo = extern "system" fn(*const c_void, *const c_void) -> HRESULT; //Specific handling for rotf

static mut PROXY_FUNCTION: Option<DirectInput8CreateFunc> = None;
static mut PROXY_FUNCTION_IPHLPAPI: Option<IPHLPAPIGetAdaptersInfo> = None; //Specific handling for rotf

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(
    dll_module: windows::Win32::Foundation::HMODULE,
    call_reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    DisableThreadLibraryCalls(dll_module).unwrap_unchecked();

    match call_reason {
        DLL_PROCESS_ATTACH => init(dll_module),
        DLL_PROCESS_DETACH => free(dll_module),
        _ => (),
    }
    true.into()
}

pub unsafe fn init(module: HMODULE) {
    let cfg = ConfigBuilder::new()
        .set_time_offset_to_local()
        .unwrap()
        .build();

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            cfg,
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Trace,
            Config::default(),
            std::fs::File::create(".\\uwhr.log".to_owned())
                .expect("Couldn't create log file: .\\uwhr.log"),
        ),
    ])
    .unwrap();

    debug!("uwhr base: {module:X?}");

    let module = LoadLibraryW(w!("C:\\Windows\\System32\\dinput8.dll")).unwrap_unchecked();
    PROXY_FUNCTION = Some(transmute(GetProcAddress(module, s!("DirectInput8Create"))));

    let module = LoadLibraryW(w!("C:\\Windows\\System32\\iphlpapi.dll")).unwrap_unchecked();
    PROXY_FUNCTION_IPHLPAPI = Some(transmute(GetProcAddress(module, s!("GetAdaptersInfo"))));
    info!("Proxy set");

    hook_host_lookup();
    debug!("Done!");
}

pub fn free(_module: HMODULE) {}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DirectInput8Create(
    hinst: HINSTANCE,
    dwversion: u32,
    riidltf: *const GUID,
    ppvout: *mut *mut c_void,
    punkouter: IUnknown,
) -> HRESULT {
    PROXY_FUNCTION.unwrap_unchecked()(hinst, dwversion, riidltf, ppvout, punkouter)
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn GetAdaptersInfo(
    adapter_info: *const c_void,
    size: *const c_void,
) -> HRESULT {
    PROXY_FUNCTION_IPHLPAPI.unwrap_unchecked()(adapter_info, size)
}
