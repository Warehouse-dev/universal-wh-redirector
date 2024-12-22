//! Module for memory manipulation and searching logic

//Borrowed from PocketRelayClientPlugin. Thanks, jacobtread!

use log::error;
use windows::Win32::{
    Foundation::GetLastError,
    System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
};

/// Attempts to apply virtual protect READ/WRITE access
/// over the memory at the provided address for the length
/// provided. Restores the original flags after the action
/// is complete
///
/// ## Safety
///
/// This function acquires the proper write permissions over
/// `addr` for the required `length` but it is unsound if
/// memory past `length` is accessed
///
/// ## Arguments
/// * addr - The address to protect
/// * length - The protected region
/// * action - The action to execute on the memory
#[inline]
pub unsafe fn use_memory<F, P>(addr: *const P, length: usize, action: F)
where
    F: FnOnce(*mut P),
{
    // Tmp variable to store the old state
    let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);

    // Apply the new read write flags
    if VirtualProtect(addr.cast(), length, PAGE_READWRITE, &mut old_protect).is_err() {
        let error = GetLastError();

        error!(
            "Failed to protect memory region @ {:#016x} length {} error: {:?}",
            addr as usize, length, error
        );
        return;
    }

    // Apply the action on the now mutable memory area
    action(addr.cast_mut());

    // Restore the original flags
    let _ = VirtualProtect(addr.cast(), length, old_protect, &mut old_protect);
}
