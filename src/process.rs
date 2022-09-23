use std::mem::MaybeUninit;
use std::ptr;
use winapi::_core::mem;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};

use anyhow::*;
use log::*;
use memlib::{MemoryReadExt, Module};
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::{NtQueryInformationProcess, PEB_LDR_DATA, PROCESS_BASIC_INFORMATION, ProcessBasicInformation};
use widestring::U16CString;

#[derive(Clone, Debug)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32
}

pub fn get_process_list() -> Result<Vec<Process>> {
    // https://stackoverflow.com/a/865201/11639049
    // Create an empty PROCESSENTRY32 struct
    let mut entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    // Take a snapshot of every process
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    let mut process_list = Vec::new();

    unsafe {
        // TODO: This doesn't include the first process
        // TODO: This doesn't have error handling for Process32First/Next. use GetLastError
        if Process32First(snapshot, &mut entry) == 1 {
            while Process32Next(snapshot, &mut entry) == 1 {
                // Construct the process name from the bytes in the szExeFile array
                let name = super::c_char_array_to_string(entry.szExeFile.to_vec());
                let pid = entry.th32ProcessID;
                let parent_pid = entry.th32ParentProcessID;

                process_list.push(Process {
                    name,
                    pid,
                    parent_pid
                })
            }
        }
    };

    trace!("Found {} processes", process_list.len());

    Ok(process_list)
}

/// Returns a PID by a process name
pub fn get_pid_by_name(name: &str) -> Option<u32> {
    get_process_list().unwrap()
        .iter()
        .find(|&proc| proc.name.to_lowercase() == name.to_lowercase())
        .map(|proc| proc.pid)
}


use winapi::shared::ntdef::NT_SUCCESS;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;

/// Gets the peb base address of a process. Returns None if OpenProcess fails
pub fn get_peb_base(pid: u32) -> Option<u64> {
    // Open a handle to the process
    //
    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false as _, pid) };
    if handle == INVALID_HANDLE_VALUE {
        return None;
    }

    // Find the peb address using NtQueryInformationProcess
    //
    let mut pbi = MaybeUninit::uninit();
    if !unsafe {
        NT_SUCCESS(NtQueryInformationProcess(
            handle as _,
            ProcessBasicInformation,
            pbi.as_mut_ptr() as _,
            core::mem::size_of::<PROCESS_BASIC_INFORMATION>() as _,
            ptr::null_mut(),
        ))
    } {
        unsafe { CloseHandle(handle) };
        return None;
    }
    unsafe { CloseHandle(handle) };
    let pbi: PROCESS_BASIC_INFORMATION = unsafe { pbi.assume_init() };

    Some(pbi.PebBaseAddress as u64)
}

/// Returns the list of modules in a process
pub fn get_module_list(process: &(impl memlib::MemoryRead + memlib::ProcessInfo)) -> Option<Vec<memlib::Module>> {
    let peb_base = process.peb_base_address();

    // PEB and PEB_LDR_DATA
    //
    let peb: PEB = unsafe { process.try_read_unchecked(peb_base)? };
    let peb_ldr_data: PEB_LDR_DATA = unsafe { process.try_read_unchecked(peb.Ldr as u64)? };

    // LIST_ENTRY
    //
    let ldr_list_head = peb_ldr_data.InLoadOrderModuleList.Flink;
    let mut ldr_current_node = peb_ldr_data.InLoadOrderModuleList.Flink;

    let mut modules = Vec::new();
    loop {
        // LDR_DATA_TABLE_ENTRY
        //
        let list_entry = {
            let memory = process.try_read_bytes(
                ldr_current_node as u64,
                core::mem::size_of::<LDR_DATA_TABLE_ENTRY>(),
            )?;
            unsafe { (memory.as_ptr() as *mut LDR_DATA_TABLE_ENTRY).read_volatile() }
        };

        // Add the module to the list
        //
        if !list_entry.BaseDllName.Buffer.is_null()
            && !list_entry.DllBase.is_null()
            && list_entry.SizeOfImage != 0
            && list_entry.BaseDllName.MaximumLength != 0
            && process.try_read_bytes(list_entry.BaseDllName.Buffer as _, 1).is_some()
        {
            let name = list_entry.BaseDllName;
            let size = name.MaximumLength as usize;

            let base_name = process.try_read_bytes(name.Buffer as u64, size).unwrap();
            let base_name = unsafe { U16CString::from_ptr_str(base_name.as_ptr() as _) };

            modules.push(Module {
                name: base_name.to_string_lossy(),
                base: list_entry.DllBase as u64,
                size: list_entry.SizeOfImage as u64,
            });
        }

        ldr_current_node = list_entry.InLoadOrderLinks.Flink;
        if ldr_list_head as u64 == ldr_current_node as u64 {
            break;
        }
    }

    Some(modules)
}