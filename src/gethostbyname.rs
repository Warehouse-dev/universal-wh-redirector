use crate::mem::{find_pattern, use_memory};
use log::{debug, error, info, warn};
use std::{
    ffi::{CStr, CString},
    ptr::{self},
};
use windows::{
    core::PCSTR,
    Win32::Networking::WinSock::{gethostbyname, HOSTENT},
};

// Blur, Wfc, Foc, Singularity
const HOST_LOOKUP_MASK_DW2: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxx????xxxxxxx";

const HOST_LOOKUP_OP_CODES_DW2: &[u8] = &[
    0x55, 0x8b, 0xec, 0x83, 0xec, 0x18, 0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xfc,
    0x00, 0x00, 0x00, 0x00, 0x8b, 0x45, 0x08, 0x0f, 0xbe, 0x08, 0x51, 0xe8, 0x92, 0x28, 0x02,
    0x00, // MSVCR90.DLL::isalpha
    0x83, 0xc4, 0x04, 0x85, 0xc0, 0x74, 0x71, 0x8b, 0x55, 0x08, 0x52, 0xff, 0x15, 0x2c, 0x36, 0xe5,
    0x00, //gethostbyname(param_1)
    0x89, 0x45, 0xfc, 0x83, 0x7d, 0xfc, 0x00,
];

//This is from grid.
const HOST_LOOKUP_MASK_DW1: &str = "xxxxxxxxxxxxx????xxxxxxxxxxx????";

const HOST_LOOKUP_OP_CODES_DW1: &[u8] = &[
    0x53, 0x56, 0x8b, 0x74, 0x24, 0x0c, 0x0f, 0xbe, 0x06, 0x50, 0x33, 0xdb, 0xe8, 0x80, 0x9d, 0x1b,
    0x00, //_isalpha
    0x83, 0xc4, 0x04, 0x85, 0xc0, 0x74, 0x45, 0x57, 0x56, 0xff, 0x15, 0x74, 0x94, 0xc8,
    0x00, // dword ptr [->WS2_32.DLL::gethostbyname]
];

//Rotf. I suspect that due to MSVCR80 it produced a slightly different asm
const HOST_LOOKUP_MASK_ROTF: &str = "xxxxxxxxxxxxxx????xxxxxxxxxx????";

const HOST_LOOKUP_OP_CODES_ROTF: &[u8] = &[
    0x53, 0x56, 0x57, 0x8b, 0xf9, 0x8b, 0xf0, 0x0f, 0xbe, 0x07, 0x50, 0x33, 0xdb, 0xe8, 0x9e, 0x57,
    0x58, 0x00, //_isalpha
    0x83, 0xc4, 0x04, 0x85, 0xc0, 0x57, 0x74, 0x34, 0xff, 0x15, 0x6c, 0xb5, 0xae,
    0x00, // dword ptr [->WS2_32.DLL::gethostbyname]
];

//GH3 and GHWT. Potentially game specific, but other functions doesn't match with Grid.
const HOST_LOOKUP_MASK_GH3: &str = "x????xxxxxxxxxxxxxxxxxxxx";
const HOST_LOOKUP_OP_CODES_GH3: &[u8] = &[
    0xe8, 0xe3, 0xdb, 0xfe, 0xff, // dword ptr [->WS2_32.DLL::gethostbyname]
    0x85, 0xc0, 0x74, 0x5c, 0x0f, 0xbf, 0x50, 0x0a, 0x8b, 0x40, 0x0c, 0x8b, 0x08, 0x52, 0x51, 0x8d,
    0x54, 0x24, 0x10, 0x52,
];

/// Address to start matching from
const HOST_LOOKUP_START_OFFSET: usize = 0x401000;
/// Address to end matching at
const HOST_LOOKUP_END_OFFSET: usize = 0xEA7000;

#[derive(PartialEq)]
enum Method {
    DW2Generic,
    DW1Generic,
    GH3,
    ROTF,
    None,
}

pub unsafe fn hook_host_lookup() {
    info!("Setting gethostbyname hook.");
    let mut sig_match: Method = Method::None;
    let mut offset: *const u8 = ptr::null();

    let Ok(mut sker) = sigmatch::Seeker::with_name("main") else {
        return;
    };

    match sker.raw_search(HOST_LOOKUP_OP_CODES_DW2, HOST_LOOKUP_MASK_DW2) {
        Ok(found_addr) => {
            sig_match = Method::DW2Generic;
            offset = found_addr as *const u8;
        }
        Err(_e) => {
            info!("DW2 signature wasn't found");
        }
    }

    if sig_match == Method::None {
        match sker.raw_search(HOST_LOOKUP_OP_CODES_DW1, HOST_LOOKUP_MASK_DW1) {
            Ok(found_addr) => {
                sig_match = Method::DW1Generic;
                offset = found_addr as *const u8;
            }
            Err(_e) => {
                info!("DW1 signature wasn't found");
            }
        }
    }

    if sig_match == Method::None {
        match sker.raw_search(HOST_LOOKUP_OP_CODES_GH3, HOST_LOOKUP_MASK_GH3) {
            Ok(found_addr) => {
                sig_match = Method::GH3;
                offset = found_addr as *const u8;
            }
            Err(_e) => {
                info!("GH3 signature wasn't found");
            }
        }
    }

    if sig_match == Method::None {
        match sker.raw_search(HOST_LOOKUP_OP_CODES_ROTF, HOST_LOOKUP_MASK_ROTF) {
            Ok(found_addr) => {
                sig_match = Method::ROTF;
                offset = found_addr as *const u8;
            }
            Err(_e) => {
                info!("ROTF signature wasn't found");
            }
        }
    }


    //Very special fix for Grid upx packed binary. Might cause 
    if sig_match == Method::None {
        match find_pattern(
            HOST_LOOKUP_START_OFFSET,
            HOST_LOOKUP_END_OFFSET,
            HOST_LOOKUP_MASK_DW1,
            HOST_LOOKUP_OP_CODES_DW1,
        ) {
            Some(found_addr) => {
                sig_match = Method::DW1Generic;
                offset = found_addr;
            }
            None => info!("DW1 signature via raw mem wasn't found"),
        };
    }

    if offset.is_null() {
        warn!("Failed to find gethostbyname hook position");
        return;
    }

    info!("Found gethostbyname @ {:#08x}", offset as usize);

    let sig_offset: usize = match sig_match {
        Method::DW2Generic => 45,
        Method::DW1Generic => 28,
        Method::GH3 => {
            //Special handling for GH3, since it actually utilize jumps.

            let distance = *(offset.add(1 /* Skip call opcode */) as *const usize);

            let jmp_address = offset.add(5 /* Skip call opcode + address */ + distance);

            let address = *(jmp_address.add(2 /* Skip ptr jmp opcode */) as *const usize);

            let addr = address as *const u8;

            use_memory(addr, 4, |addr| {
                // Replace the address with our faker function
                let ptr: *mut usize = addr as *mut usize;
                *ptr = fake_gethostbyname as usize;
            });

            return;
        }
        Method::ROTF => 28,
        Method::None => todo!(),
    };

    let gethostname_ptr = *(offset.add(sig_offset /* Skip bytes */) as *const usize);
    debug!("Got gethostname ptr: {:#08x}", gethostname_ptr);

    use_memory(gethostname_ptr as *const usize, 4, |addr| {
        // Replace the address with our faker function
        let ptr: *mut usize = addr as *mut usize;
        *ptr = fake_gethostbyname as usize;
    });
}

#[no_mangle]
pub unsafe extern "system" fn fake_gethostbyname(hostname: PCSTR) -> *mut HOSTENT {
    //debug!("Got Host Lookup Request. ptr: {:p}", hostname.as_ptr());

    let requested_hostname_to_resolve = {
        match unsafe { CStr::from_ptr(hostname.0.cast()).to_str() } {
            Ok(host_str) => &host_str.to_lowercase(),
            Err(e) => {
                error!("Failed to parse domain name: {e}");
                &"placeholder".to_string()
            }
        }
    };

    if requested_hostname_to_resolve.contains("demonware") {
        info!(
            "Got host lookup request for {}",
            requested_hostname_to_resolve
        );

        let official_stuns: [&str; 4] = [
            "stun.us.demonware.net",
            "stun.eu.demonware.net",
            "stun.au.demonware.net",
            "stun.jp.demonware.net",
        ];

        if official_stuns.contains(&requested_hostname_to_resolve.as_ref()) {
            info!("Performing stun detour");
            let host = CString::new("stun.aiwarehouse.xyz").unwrap();
            return unsafe { gethostbyname(PCSTR::from_raw(host.as_ptr().cast())) };
        }

        if requested_hostname_to_resolve.contains("lsg") {
            info!("LSG in domain, performing lsg detour");
            let host = CString::new("wh-lsg.aiwarehouse.xyz").unwrap();
            return unsafe { gethostbyname(PCSTR::from_raw(host.as_ptr().cast())) };
        };

        if requested_hostname_to_resolve.contains("auth") {
            info!("AUTH in domain, performing auth detour");
            let host = CString::new("wh-auth.aiwarehouse.xyz").unwrap();
            return unsafe { gethostbyname(PCSTR::from_raw(host.as_ptr().cast())) };
        };
    } else {
        debug!(
            "Got host lookup request for {}",
            requested_hostname_to_resolve
        );
        return unsafe { gethostbyname(hostname) };
    };

    return unsafe { gethostbyname(hostname) };
}
