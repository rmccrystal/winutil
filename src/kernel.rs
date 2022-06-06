use std::ffi::CString;
use ntapi::ntexapi::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS, SystemModuleInformation};
use ntapi::ntldr::PRTL_PROCESS_MODULES;
use winapi::shared::ntdef::NT_ERROR;

/// Finds the base address of the specified kernel module (e.g. `ntoskrnl.exe`,
/// `win32k.sys`, ...).
pub fn get_kernel_module_base(module_name: &str) -> Option<usize> {
    let mut buffer = Vec::new();
    let mut size = 0;
    loop {
        let result = unsafe {
            NtQuerySystemInformation(
                SystemModuleInformation as _,
                buffer.as_mut_ptr() as _,
                size,
                std::ptr::addr_of_mut!(size),
            )
        };
        if NT_ERROR(result) {
            buffer.extend(vec![0u8; size as usize]);
        } else {
            break;
        }
    }

    let modules = buffer.as_mut_ptr() as PRTL_PROCESS_MODULES;
    let module_count = unsafe { (*modules).NumberOfModules };

    for i in 0..module_count {
        let module = unsafe { (*modules).Modules.as_mut_ptr().offset(i as _).as_ref().unwrap() };

        let image_base = unsafe { (*module).ImageBase } as usize;

        let name_offset = unsafe { (*module).OffsetToFileName } as usize;
        let name = unsafe { &(*module).FullPathName[name_offset..] };
        let (zero_byte, _) = name.iter().enumerate().find(|(_, &c)| c == 0).unwrap();
        let name = &name[..=zero_byte];

        let name = CString::from_vec_with_nul(name.to_vec()).ok()?;
        log::trace!("Found module {:?} with image base {:x}", name, image_base);

        if name.to_string_lossy().eq_ignore_ascii_case(module_name) {
            return Some(image_base);
        }
    }

    None
}
