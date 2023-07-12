use windows::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Threading::{GetProcessId, OpenProcess, PROCESS_ACCESS_RIGHTS},
    },
};

// For future use

#[allow(dead_code)]
struct Process {
    m_process_id: u32,
    m_handle: HANDLE,
}

#[allow(dead_code)]
impl Process {
    fn new(process_id: u32) -> Process {
        Process {
            m_process_id: process_id,
            m_handle: HANDLE(0 as isize),
        }
    }

    fn with_handle(process_handle: HANDLE) -> Process {
        let process_id = unsafe { GetProcessId(process_handle) };
        Process {
            m_process_id: process_id,
            m_handle: process_handle,
        }
    }

    fn create_handle(&mut self, flag: PROCESS_ACCESS_RIGHTS) -> bool {
        self.m_handle = unsafe { OpenProcess(flag, false, self.m_process_id).unwrap() };
        println!("create_handle: {:?}", self.m_handle);

        return self.m_handle.ne(&HANDLE(0 as isize));
    }

    fn create_handle_with_id(&mut self, process_id: u32, flag: PROCESS_ACCESS_RIGHTS) -> bool {
        self.m_process_id = process_id;
        self.m_handle = unsafe { OpenProcess(flag, false, self.m_process_id).unwrap() };
        return self.m_handle.ne(&HANDLE(0 as isize));
    }

    fn read_page(
        handle: HANDLE,
        address: usize,
        _buffer: &Vec<u8>,
        size: usize,
        bytes_read: &mut Option<*mut usize>,
    ) -> bool {
        let mut buffer = vec![0u8; size];

        unsafe {
            let res: windows::Win32::Foundation::BOOL = ReadProcessMemory(
                handle,
                address as _,
                buffer.as_mut_ptr() as _,
                size,
                *bytes_read,
            );

            if res != windows::Win32::Foundation::FALSE {
                return true;
            } else {
                return false;
            }
        }
        // change the memory protection settings for a memory range
        // let mut old_protect: u32 = 0;
        // if unsafe { VirtualProtectEx(handle, address, size, PAGE_READONLY, &mut old_protect) } == 0
        // {
        //     return false;
        // }

        // let result = unsafe { ReadProcessMemory(handle, address, buffer, size, bytes_read) } != 0;
        // unsafe { VirtualProtectEx(handle, address, size, old_protect, &mut old_protect) };
        // result
    }

    // fn read_memory(&self, address: usize, buffer: &Vec<u8>, size: usize) -> bool {
    //     if self.m_handle.is_invalid() || buffer.is_empty() || size == 0 {
    //         return false;
    //     }

    //     let mut bytes_read: usize = 0;

    //     const PAGE_SIZE: usize = 0x1000;
    //     let mut offset: usize = 0;
    //     let mut requested_size = size;
    //     let size_left_in_first_page = PAGE_SIZE - (address as usize & (PAGE_SIZE - 1));
    //     let mut read_size = std::cmp::min(size_left_in_first_page, requested_size);

    //     while read_size > 0 {
    //         let mut bytes_read_safe: usize = 0;
    //         let mut bytes_read_safe_option = Some(&mut bytes_read_safe as *mut usize);

    //         let read_success = Process::read_page(
    //             self.m_handle,
    //             (address as usize + offset),
    //             buffer[..offset as usize],
    //             read_size,
    //             &mut bytes_read_safe_option,
    //         );

    //         bytes_read += bytes_read_safe;
    //         if !read_success {
    //             break;
    //         }

    //         offset += read_size;
    //         requested_size -= read_size;
    //         read_size = std::cmp::min(PAGE_SIZE, requested_size);
    //     }

    //     let success = bytes_read == size;
    //     unsafe { winapi::um::errhandlingapi::SetLastError(if success { 0 } else { 0x12b }) };
    //     success
    // }

    // fn write_memory(&self, address: LPVOID, buffer: *const c_void, size: usize) -> bool {
    //     if self.m_handle.is_null() {
    //         return false;
    //     }

    //     unsafe {
    //         WriteProcessMemory(self.m_handle, address, buffer, size, std::ptr::null_mut()) != 0
    //     }
    // }
}
