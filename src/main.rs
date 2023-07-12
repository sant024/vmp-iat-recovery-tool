use std::collections::HashMap;
use std::ffi::CString;
use std::ptr;
use std::sync::{Arc, Mutex};

use exe::{
    align, CChar, CCharString, ExportDirectory, ImageDirectoryEntry, ImageImportDescriptor,
    ImageSectionHeader, ImportData, ImportDirectory, SectionCharacteristics, Thunk64, ThunkData,
};
use exe::{
    pe::{VecPE, PE},
    Buffer, HDR32_MAGIC, HDR64_MAGIC,
};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use unicorn_engine::{RegisterX86, Unicorn};
use windows::Win32::{
    Foundation::HANDLE,
    System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
};

use anyhow::Result;

mod emu;
mod module;
mod patch;
mod process;
use crate::emu::{hook_ready, map_and_write_memory};
use crate::module::*;
use zydis::{
    ffi, Decoder, Formatter, FormatterProperty, FormatterStyle, Hook, OutputBuffer,
    Result as ZydisResult, Status, VisibleOperands, TOKEN_SYMBOL,
};

#[derive(Clone, Debug)]
pub struct ExportData {
    name: String,
    rva: u64,
    #[allow(dead_code)]
    base_ordinal: u64,
    #[allow(dead_code)]
    name_ordinal: u64,
}

impl ExportData {
    fn new() -> Self {
        ExportData {
            name: String::new(),
            rva: 0,
            base_ordinal: 0xffffffff,
            name_ordinal: 0xffffffff,
        }
    }
}

fn collect_images(process_handle: HANDLE, module_list: &Vec<ModuleInfo>) -> Vec<VecPE> {
    let mut image_list: Vec<VecPE> = Vec::new();
    let mut count = 0;
    for module in module_list.iter() {
        count += 1;
        println!("Collect images - Iter: {}/{}", count, module_list.len());
        let full_buffer = unsafe { read_module_memory(process_handle, module) };

        println!(
            "Collect images-  mod-name: {} mod size: {} full_buffer_len:{}",
            module.module_path,
            module.module_size,
            full_buffer.len()
        );

        let image = VecPE::from_memory_data(full_buffer);
        let nt_magic = image.get_nt_magic();

        if let Ok(nt_magic) = nt_magic {
            println!("Collect image - magic: {} {}", nt_magic, module.module_path);
            if nt_magic == HDR32_MAGIC || nt_magic == HDR64_MAGIC {
                if let Some(index) = module.module_path.rfind('\\') {
                    let substring = &module.module_path[(index + 1)..];
                    println!("Collect image - Name dll: {}", substring);
                    //image.save(substring);
                    image_list.push(image);
                }
            }
        } else {
            println!("Collect images - failed for: {}", module.module_path);
        }
    }

    println!("Total collected images : {}", image_list.len());
    image_list
}

fn main() -> Result<()> {
    let process_id = unsafe { get_proc_id_by_name("your vmprotected exe .vmp.exe")? };
    let rebuild_iat = false;
    println!("Process ID: {}", process_id);
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            process_id,
        )
        .unwrap()
    };

    let module_list = unsafe { get_modules_in_process(process_handle) };
    let image_list: Vec<VecPE> = collect_images(process_handle, &module_list);

    let mut image_map: HashMap<u64, VecPE> = HashMap::new();
    for img in &image_list {
        let image_base = img
            .clone()
            .get_nt_headers_64()
            .unwrap()
            .optional_header
            .image_base;
        image_map.insert(image_base, img.clone());
    }

    let target_image: &VecPE = image_list.first().unwrap();

    let image_base = target_image
        .clone()
        .get_nt_headers_64()
        .unwrap()
        .optional_header
        .image_base;

    println!("Image base address is : {} ", image_base);

    let sec_text = target_image
        .get_section_by_name(".text".to_string())
        .unwrap();

    let sec_vmp = &target_image
        .get_section_by_name(".vmp0".to_string())
        .unwrap();

    let search_result = target_image.search(&[0xE8]).unwrap();

    // for i in search_result {
    //     println!("Found: {}", i);
    //     let found = &target_image.to_vec()[i..i + 10]; // Slow print
    //     println!("{:?}", found);
    // }

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).expect("failed to initalize the emulator");

    let stack_space = map_and_write_memory(&mut uc, &target_image, sec_text, sec_vmp, image_base);

    uc.reg_write(RegisterX86::RSP, stack_space as u64).unwrap();

    let pair: (String, ExportData) = (String::from(""), ExportData::new());

    let shared_map: Arc<Mutex<(String, ExportData)>> = Arc::new(Mutex::new(pair));
    hook_ready(&mut uc, &shared_map, module_list, image_map);

    let decoder = Decoder::new64();

    let mut count = 0;
    let mut count_real = 0;
    let mut prev_i = 0;

    let mut vmp_import_calls: HashMap<u64, u64> = HashMap::new();
    for i in search_result {
        count += 1;
        if prev_i + 5000 < i {
            // check that its <-> not too far apart
            if prev_i != 0 {
                break;
            }
        }

        for item in
            decoder.decode_all::<VisibleOperands>(&target_image.to_vec()[i..i + 5], image_base)
        {
            let (_, _raw_bytes, insn) = item.unwrap();

            let dest_addr = insn
                .calc_absolute_address(image_base + i as u64, &insn.operands()[0]) // https://doc.zydis.re/v3.2.0/html/group__utils
                .unwrap();
            //println!("calling {:x}", dest_addr);

            if image_base < dest_addr {
                let rva = dest_addr.checked_sub(image_base);
                if let Some(offset) = rva {
                    if sec_vmp.has_rva(exe::RVA::from(offset as u32)) {
                        println!("[{:x}] Call to: {:x}", i, dest_addr);
                        count_real += 1;
                    }
                }
                vmp_import_calls.insert(i as u64, dest_addr);
            }
        }
        prev_i = i;
    }

    println!("Count: {}", count);
    println!("Count Real: {}", count_real);
    //         Count: 172    vs orig  match count : 157
    //         Count Real: 68   after check in RVA section

    // https://github.com/zyantific/zydis-rs/blob/master/examples/formatter_symbols.rs#L31
    // example uses calcabsoluteaddr

    let mut target_image_i: VecPE = target_image.clone();
    let target_image_o: VecPE = target_image.clone();
    let mut check_new_address_test = 0;
    for address in vmp_import_calls {
        uc.reg_write(RegisterX86::RSP, stack_space as u64).unwrap(); // reset stack

        let stack_ptr = uc.reg_read(RegisterX86::RSP).unwrap();
        let rdr = image_base + address.0 + 5;
        uc.mem_write(stack_ptr, &rdr.to_le_bytes()).unwrap();

        if let Err(err) = uc.emu_start(address.1, 0, 0, 0) {
            println!("Error occured: {:?}", err);
        }

        let map = shared_map.lock().unwrap();
        let exp_resolve = map.clone();

        println!(
            "\t Located -> Module:{}  Import:{}",
            exp_resolve.0, exp_resolve.1.name
        );

        let module_name = exp_resolve.0.clone();

        let module_import_name = exp_resolve.1.name.clone();

        if !module_name.to_lowercase().contains(".dll") {
            continue;
        }

        if rebuild_iat {
            patch::rebuild_import_address_table(
                &mut target_image_i,
                &target_image_o,
                module_name,
                module_import_name,
                &mut check_new_address_test,
            );
        }
    }

    Ok(())
}
