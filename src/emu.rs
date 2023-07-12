use exe::{align, Buffer, ExportDirectory, ImageSectionHeader, ThunkData, VecPE};
use unicorn_engine::unicorn_const::Permission;
use unicorn_engine::{RegisterX86, Unicorn};

use crate::module::ModuleInfo;
use crate::ExportData;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
pub fn map_and_write_memory(
    uc: &mut Unicorn<()>,
    target_image: &VecPE,
    sec_text: &ImageSectionHeader,
    sec_vmp: &ImageSectionHeader,
    image_base: u64,
) -> isize {
    let mapped_text_address: u64 = sec_text.virtual_address.0 as u64 + image_base;
    let text_virtual_address = sec_text.virtual_address.0 as u64;

    let mapped_text_size = align(sec_text.virtual_size + 0x1000, 0x1000) as usize;

    println!(
        "Emu - mapped text addr: {}, mapped text size: {}",
        mapped_text_address, mapped_text_size
    );

    uc.mem_map(mapped_text_address, mapped_text_size, Permission::ALL)
        .unwrap();

    // https://docs.rs/exe/latest/exe/pe/trait.Buffer.html#method.search

    uc.mem_write(
        mapped_text_address,
        &target_image.to_vec()
            [text_virtual_address as usize..text_virtual_address as usize + mapped_text_size],
    )
    .unwrap();

    let mapped_vmp_address = sec_vmp.virtual_address.0 as u64 + image_base;
    let vmp_virtual_address = sec_vmp.virtual_address.0 as u64;
    let mapped_vmp_size = align(sec_vmp.virtual_size + 0x1000, 0x1000) as usize;
    println!(
        "Emu = mapped vmp addr: {}, mapped vmp size: {}",
        mapped_vmp_address, mapped_vmp_size
    );

    uc.mem_map(mapped_vmp_address, mapped_vmp_size, Permission::ALL)
        .unwrap();

    uc.mem_write(
        mapped_vmp_address,
        &target_image.to_vec()
            [vmp_virtual_address as usize..vmp_virtual_address as usize + mapped_vmp_size],
    )
    .unwrap();
    let stack_space = (mapped_vmp_address as isize + (mapped_vmp_size - 0x1000) as isize) & !0x10;

    println!(
        "Emu - stack space check (subtraction only): {}",
        (mapped_vmp_address as isize + (mapped_vmp_address - 0x1000) as isize)
    );
    println!("Emu - stack space final: {}", stack_space);
    stack_space
}

#[allow(dead_code)]
fn find_executable_region(uc: &mut Unicorn<()>) {
    let regions = uc.mem_regions().unwrap();
    let mut exec_start = None;
    let mut exec_stop = None;

    for region in regions {
        if !region.perms.intersects(Permission::EXEC) {
            continue;
        }
        if exec_start == None || region.begin < exec_start.unwrap() {
            exec_start = Some(region.begin)
        };
        if exec_stop == None || region.end > exec_stop.unwrap() {
            exec_stop = Some(region.end)
        };
    }

    println!("exec start (debug): {}", exec_start.unwrap());
    println!("exec end (debug): {}", exec_stop.unwrap());
}

pub fn hook_ready(
    uc: &mut Unicorn<()>,
    shared_map: &Arc<Mutex<(String, ExportData)>>,
    module_list: Vec<ModuleInfo>,
    image_map: HashMap<u64, VecPE>,
) {
    // Add hook https://www.cs.brandeis.edu/~cs146a/rust/doc-02-21-2015/book/closures.html
    let closure_map = Arc::clone(&shared_map);

    let callback = move |_uc: &mut Unicorn<()>, addr: u64, _size: u32| {
        let mut insnbuf = [0; 0xf];

        _uc.mem_read(addr, &mut insnbuf).unwrap(); // turn uc (outside) to this in call back_uc

        if insnbuf[0] == 0xC3 || insnbuf[0] == 0xC2 {
            let mut u_import_address = _uc.reg_read(RegisterX86::RSP).unwrap();
            //println!("[user import address] reg read only : {}", u_import_address);
            //_uc.mem_read(u_import_address, &mut u_import_address.to_le_bytes())
            //.unwrap();

            let mut buffer = u_import_address.to_le_bytes();
            _uc.mem_read(u_import_address, &mut buffer).unwrap();

            u_import_address = u64::from_le_bytes(buffer);

            //println!("[user import address] after mem read : {}", u_import_address);

            for module in module_list.iter() {
                if u_import_address >= module.base_address
                    && u_import_address <= module.base_address + module.module_size as u64
                {
                    //println!("[Found match] -> {}", module.module_path);

                    let our_img = &image_map[&module.base_address];
                    let rva = u_import_address - module.base_address;
                    //println!("search for rva: {}", rva);
                    if let Ok(export_directory) = ExportDirectory::parse(our_img) {
                        for ii in export_directory.get_export_map(our_img).unwrap() {
                            let thunk: ThunkData = ii.1;

                            if let ThunkData::Function(value) = thunk {
                                if value.0 == rva as u32 {
                                    // println!(
                                    //     "Thunk is a Function variant with RVA equal to {}",
                                    //     rva
                                    // );
                                    // println!("called {}", ii.0);
                                    let mut map = closure_map.lock().unwrap();

                                    if let Some(index) = module.module_path.rfind('\\') {
                                        let substring = &module.module_path[(index + 1)..];
                                        map.0 = substring.to_string();
                                        map.1.name = ii.0.to_string();
                                        map.1.rva = rva;
                                    }
                                }
                            }
                        }
                    } else {
                        //println!("Not working its an .exe file and not .dll so cant get exports");
                        //println!(" see : {}", module.module_path);
                    }

                    // make mov so this works
                }
            }

            _uc.emu_stop().unwrap();
        }
    };
    //https://github.com/unicorn-engine/unicorn/blob/next/bindings/rust/tests/unicorn.rs

    uc.add_code_hook(1, 0, callback).unwrap(); // :: emu start
    println!("Added code hook.");
}
