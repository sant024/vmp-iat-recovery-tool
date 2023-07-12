use std::mem::size_of;

use anyhow::anyhow;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, HINSTANCE, MAX_PATH};
use windows::Win32::Globalization::lstrcmpiA;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_READONLY, PAGE_READWRITE,
};
use windows::Win32::System::ProcessStatus::{
    K32EnumProcessModulesEx, K32GetModuleFileNameExA, K32GetModuleInformation, LIST_MODULES_ALL,
    MODULEINFO,
};
//use windows::{s, w};

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub module_path: String,
    pub base_address: u64,
    pub module_size: u32,
}

impl ModuleInfo {
    pub fn new(module_path: String, base_address: u64, module_size: u32) -> Self {
        ModuleInfo {
            module_path: module_path,
            base_address: base_address,
            module_size: module_size,
        }
    }
}

pub unsafe fn get_proc_id_by_name(process_name: &str) -> Result<u32, anyhow::Error> {
    let handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
    let mut entry = PROCESSENTRY32::default();
    entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
    if Process32First(handle, &mut entry).into() {
        loop {
            if lstrcmpiA(
                PCSTR(entry.szExeFile.as_ptr() as _),
                PCSTR(format!("{}\0", process_name).as_ptr()), // https://github.com/microsoft/windows-rs/issues/2344
            ) == 0
            {
                println!("Found target process pid={}", entry.th32ProcessID);
                break;
            }
            if !Process32Next(handle, &mut entry).as_bool() {
                return Err(anyhow!("Can't find process name."));
            }
        }
    } else {
        return Err(anyhow!("Failed to get first process!"));
    }
    return Ok(entry.th32ProcessID);
}

pub unsafe fn get_modules_in_process(process_handle: HANDLE) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();
    let mut instance = [HINSTANCE::default(); 1024];
    let cb_needed = size_of::<HINSTANCE>() as u32 * 1024;
    let mut lpcb_needed = 0;
    K32EnumProcessModulesEx(
        process_handle,
        instance.as_mut_ptr(),
        cb_needed,
        &mut lpcb_needed,
        LIST_MODULES_ALL,
    )
    .unwrap();
    //println!("cb_neeeded={}", cb_needed);
    //println!("lpcb_needed={}", lpcb_needed);
    for module in instance.iter() {
        // make it stop 1024 (prints DISCORD)
        let mut info = MODULEINFO::default();
        //println!("module={:?}", module);
        K32GetModuleInformation(
            process_handle,
            *module,
            &mut info,
            size_of::<MODULEINFO>() as _,
        )
        .unwrap();
        let mut name = vec![0 as u8; MAX_PATH as usize];

        let length = K32GetModuleFileNameExA(process_handle, *module, &mut name);

        let name = String::from_utf8(name[..length as usize].to_vec()).unwrap();
        //println!("NAME: {}", name);

        let m = ModuleInfo::new(name, info.lpBaseOfDll as u64, info.SizeOfImage);

        if info.lpBaseOfDll as u64 != 0 {
            modules.push(m.clone());
            println!(
                "Pushing module {} located at @{}",
                m.module_path, m.base_address
            );
        }

        // if name == "smthn.dll" {
        //     base_addr = info.lpBaseOfDll as usize;
        //     println!("smthn=0x{:x}", base_addr);
        //     break;
        // }
    }

    modules
}

pub unsafe fn read_module_memory(process_handle: HANDLE, module: &ModuleInfo) -> Vec<u8> {
    let mut mem_basic_info = MEMORY_BASIC_INFORMATION::default();
    let mut start_addr = module.base_address as usize;

    let mut full_buffer: Vec<u8> = Vec::new();
    let mut last_size = 0;

    loop {
        let ret = VirtualQueryEx(
            process_handle,
            Some(start_addr as _),
            &mut mem_basic_info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if ret == 0 {
            //GetLastError().ok().unwrap();
            break;
        } else {
        }

        if (mem_basic_info.Protect == PAGE_READONLY
            || mem_basic_info.Protect == PAGE_READWRITE
            || mem_basic_info.Protect == PAGE_EXECUTE_READ
            || mem_basic_info.Protect == PAGE_EXECUTE_READWRITE)
            && mem_basic_info.RegionSize != 1
        {
            let buf_length =
                mem_basic_info.BaseAddress as usize + mem_basic_info.RegionSize - start_addr;
            if buf_length > 0xF000000 {
                start_addr += mem_basic_info.RegionSize;
                continue;
            }
            let mut buf = vec![0u8; buf_length];
            if ReadProcessMemory(
                process_handle,
                start_addr as _,
                buf.as_mut_ptr() as _,
                buf_length,
                None,
            )
            .into()
            {
                full_buffer.append(&mut buf);
            }
        }
        start_addr += mem_basic_info.RegionSize;

        last_size += mem_basic_info.RegionSize;
        if last_size >= module.module_size as usize {
            //println!("last_size{}", start_addr);
            break;
        }
    }

    full_buffer
}
