use std::{ffi::CString, ptr};

use exe::{
    Buffer, CChar, CCharString, ImageDirectoryEntry, ImageImportDescriptor, ImageSectionHeader,
    ImportData, ImportDirectory, SectionCharacteristics, Thunk64, VecPE, PE,
};

fn import_module_name(target: &VecPE, module_in: String) -> u32 {
    // get NAME rva
    // return an rva
    let import_directory = ImportDirectory::parse(target).unwrap();

    for descriptor in import_directory.descriptors {
        let module_name = descriptor.get_name(target).unwrap().as_str().unwrap();
        println!("target image - Module search..: {}", module_name);

        if module_in.eq_ignore_ascii_case(module_name) {
            println!("target image - [match] {}", module_name);
            return descriptor.name.0;
        }
    }
    0
}

fn has_module_import(
    target: &VecPE,
    module_in: String,
    import_in: String,
    check_change: usize,
) -> bool {
    // return an rva

    println!("check change rva should debug: {}", check_change);
    println!(
        "cmp rva value NEW AFTER COPIED (x2): {:?}",
        &target.as_slice()[check_change..check_change + 12]
    );
    println!("Out of bounds?");
    let import_directory = ImportDirectory::parse(target).unwrap();

    for descriptor in import_directory.descriptors {
        let module_name = descriptor.get_name(target).unwrap().as_str().unwrap();
        //println!("target image - Module search..: {}", module_name);

        let descriptor_bytes = unsafe {
            std::slice::from_raw_parts(
                &descriptor as *const _ as *const u8,
                std::mem::size_of::<ImageImportDescriptor>(),
            )
        };

        println!("descriptors source orig\n: {:?}", descriptor_bytes);

        if module_in.eq_ignore_ascii_case(module_name) {
            if let Ok(imports) = descriptor.get_imports(target) {
                for import in imports {
                    if let ImportData::ImportByName(s) = import {
                        println!("\t Target {} Compare: {}?", import_in, s);
                        if import_in.eq_ignore_ascii_case(s) {
                            //println!("[** FOUND IMPORT **] ");
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn find_padding(target: &VecPE, section: &ImageSectionHeader, v: u8, n: usize) -> Option<usize> {
    let buffer = target.get_buffer().as_ref();

    let start_offset = section.pointer_to_raw_data.0; // ptr to raw data?
                                                      //let start_offset = 890200 as u32; // just to test if find_padding is 1:1

    // let header = target.get_valid_nt_headers_64().unwrap();
    // let num_sections = header.file_header.number_of_sections;
    // if num_sections > 0 {
    //     //{FOR USE ONLY IF CREATE SECTION IS EMPTY.
    //     // get last section

    //     let section_table = target.get_section_table().unwrap();

    //     start_offset = section_table[(num_sections as usize) - 1 as usize]
    //         .pointer_to_raw_data
    //         .0;
    // // m_raw_section_headers
    // } else {
    //     return None;
    // }

    let mut it: Option<usize> = None;
    println!("(inside padding start_offset: {}", start_offset); // last section of header
                                                                // Start from bottom to top, or vice versa?

    // traverse up
    // let tmp_data: Vec<u8> = vec![v; n];
    // for i in (n..=start_offset as usize + section.size_of_raw_data as usize)
    //     .rev()
    //     .step_by(n)
    // {
    //     if buffer[i - n..i] == tmp_data[..] {
    //         it = Some(i - n);
    //         break;
    //     }
    // }

    let tmp_data = vec![v; n];
    // i needs to be aligned align() ; or else out of range of start_offset () 8978976
    //let end_offset = cmp::min(start_offset + n, buffer.len() as isize) as usize;

    let mut i = start_offset as usize;

    println!(
        "buffer len minus start offset / buffer.len  {}/{},",
        buffer.len() - start_offset as usize,
        buffer.len()
    );
    loop {
        if i >= start_offset as usize + (buffer.len() as usize - start_offset as usize) {
            break;
        }
        //println!("emptu buffer? {:?}", &buffer[i..i + n]); // 204 204 244
        if buffer[i..i + n] == tmp_data[..] {
            println!("buffer padding found: {}", i);
            it = Some(i);
            break;
        }

        //println!("not align i: {}", i + n);
        //println!("aligned i : {}", exe::align(i + n, 8));
        i = i + n;
        //i = i + n; // Assumes you have a suitable align function
    }

    it
}

pub fn rebuild_import_address_table(
    target_image_i: &mut VecPE,
    target_image_o: &VecPE,
    module_name: String,
    module_import_name: String,
    check_new_address_test: &mut usize,
) {
    //error here on next loop. Maybe &target_image_i was not properly aligned..

    if !has_module_import(
        &target_image_i,
        module_name.clone(),
        module_import_name.clone(),
        *check_new_address_test,
    ) {
        println!("Import not found.");
        // Add IAT

        let vsize = target_image_i
            .get_data_directory(ImageDirectoryEntry::Import)
            .unwrap()
            .size as usize; // wev(1)
        println!("data directory size: {}", vsize);
        let mut descriptors: Vec<u8> = Vec::new();

        let import_directory = ImportDirectory::parse(target_image_i).unwrap();

        let mut d_counter: usize = 0;
        for descriptor in import_directory.descriptors {
            let descriptor_bytes = unsafe {
                std::slice::from_raw_parts(
                    &descriptor as *const _ as *const u8,
                    std::mem::size_of::<ImageImportDescriptor>(),
                )
            };
            d_counter += std::mem::size_of::<ImageImportDescriptor>();
            descriptors.extend_from_slice(descriptor_bytes);
            println!(
                "accumulated size (cmp this to data directory size): {}",
                d_counter
            );
        }

        // Create a new section for the descriptors
        let mut default_new_section = ImageSectionHeader::default(); // this was previously new_seciton ( i mixed it up , should be updated ptr)
                                                                     //new_section.virtual_address.0
        let name = CString::new(".xxxx").unwrap();
        let name_bytes = name.as_bytes_with_nul();
        let mut i = 0;
        for &byte in name_bytes.iter().take(8) {
            default_new_section.name[i] = CChar::from(byte);
            i += 1;
        }
        let created_section = target_image_i.append_section(&default_new_section);
        let created_section_check = created_section.unwrap();

        created_section_check.virtual_size = (20 * 0x1000) as u32;
        created_section_check.size_of_raw_data = (20 * 0x1000) as u32;
        created_section_check.characteristics = SectionCharacteristics::MEM_EXECUTE
            | SectionCharacteristics::MEM_READ
            | SectionCharacteristics::CNT_CODE;

        let new_section = created_section_check.clone(); //created_section.as_ref().unwrap();

        //  MEMSET 0XCC HERE
        println!("size of 0xcc: {}", new_section.size_of_raw_data as usize);
        unsafe {
            ptr::write_bytes(
                target_image_i
                    .as_mut_ptr()
                    .add(new_section.pointer_to_raw_data.0 as usize),
                0xcc,
                new_section.size_of_raw_data as usize, // https://doc.rust-lang.org/core/intrinsics/fn.write_bytes.html
            )
        };

        // let empty_bytes: Vec<u8> = vec![0x0; 20 * 0x1000];
        // &target_image_i.append(empty_bytes);
        // why isnt the imageb uffer len increasing.

        let new_sec_ptr = new_section.pointer_to_raw_data.0 as usize + (10 * 0x1000);
        println!(
            "new sec ptr: {} sec ptr to raw data (add) : {}",
            new_sec_ptr, new_section.pointer_to_raw_data.0 as u32
        );

        println!("descriptors copied\n: {:?}", descriptors);
        let descriptors_ptr = descriptors.as_ptr();

        let buffer_ptr = unsafe { &target_image_i.as_mut_ptr().add(new_sec_ptr) };
        unsafe {
            std::ptr::copy_nonoverlapping(descriptors_ptr, *buffer_ptr, vsize);
            // BUFFER SHOULD HAVE BEEN COPIED  so no error in next loop
        }
        *check_new_address_test = new_sec_ptr;

        println!(
            "cmp rva value NEW COPIED: {:?}",
            &target_image_i.as_slice()[new_sec_ptr..new_sec_ptr + 12]
        );

        // ** PAGE_SIZE = 0x1000
        // Fill in the original descriptors (Put the empty Vec<u8> (that copied originall data)descripts to newSec)
        // After creating new section, set the new directory

        {
            let ia_va: &mut u32 = &mut target_image_i
                .get_mut_data_directory(ImageDirectoryEntry::Import)
                .unwrap()
                .virtual_address
                .0;
            println!("(get_mut_data_directory) old ia_vaaddress: {}", ia_va);
            *ia_va = new_section.virtual_address.0 + (10 * 0x1000);
            println!("(get_mut_data_directory) new ia_vaaddress: {}", ia_va);

            // let to_write = new_section.virtual_address.0 + (10 * 0x1000);
            // &target_image_i
            //     .write_ref(*ia_va as usize, &to_write)
            //     .unwrap();
            // warning (size va smaller t)
        }
        {
            let ia_size = &mut target_image_i
                .get_mut_data_directory(ImageDirectoryEntry::Import)
                .unwrap()
                .size; // Changed typo from VrtualAddress to size. Now next loop wont work.. 7/9/23 (Recent change)
            println!("(get_mut_data_directory) old ia_ size: {}", ia_size);
            *ia_size = vsize as u32 + std::mem::size_of::<ImageImportDescriptor>() as u32;
            // new size should increment by 20 every iteration (eg new imoport added) (ahh maybe vsize should be rememebred)
            println!("(get_mut_data_directory) new ia_s ize: {}", ia_size); // wev(1)
        }

        if target_image_i.fix_image_size().is_ok() {
            println!("Fixed image size..");
        }
        // CAUSE OF ERROR IN NEXT LOOP

        // Fill in default values (forwarder chain, time data stamp (idk?)) 7/7/23 7:57am

        let descriptor_offset = new_section.pointer_to_raw_data.0 as usize + (10 * 0x1000) + vsize
            - std::mem::size_of::<ImageImportDescriptor>() as usize;
        let descriptor_buffer_ptr = unsafe { target_image_i.as_mut_ptr().add(descriptor_offset) };
        let our_descriptor = descriptor_buffer_ptr as *mut _ as *mut ImageImportDescriptor;
        let descriptor_modify = unsafe { &mut *our_descriptor };

        (*descriptor_modify).forwarder_chain = 0;
        (*descriptor_modify).time_date_stamp = 0;
        // 1.) Check if requested module already exists as string, and use that RVA
        let module_name_rva = import_module_name(&target_image_o, module_name.clone()); // use unchanged image
        (*descriptor_modify).name = exe::types::RVA::from(module_name_rva);

        let mut to_save_debug = false;
        if module_name_rva != 0 {
            println!(
                "(check ) [ues module name rva from imports] RVA of module name: {}",
                module_name_rva
            );
            to_save_debug = true;
        }

        let thunks: [Thunk64; 2] = [Thunk64 { 0: 0 as u64 }; 2];

        let size_of_thunks = std::mem::size_of::<[exe::types::Thunk64; 2]>();
        // 3) Join First thunk

        let temp_offset: usize =
            find_padding(&target_image_i, &new_section, 0xcc, size_of_thunks).unwrap();

        println!("3) Join first thunk) temp_offset: {}", temp_offset);

        let iat_rva = &target_image_i
            .offset_to_rva(exe::types::Offset::from(temp_offset as u32))
            .unwrap();
        let iat_rva_actual = iat_rva.0;

        println!("3) Join first thunk) iat_rva_actual: {}", iat_rva_actual);

        //memset
        unsafe {
            ptr::write_bytes(
                target_image_i.as_mut_ptr().add(temp_offset as usize),
                0x00,
                size_of_thunks,
            )
        };

        target_image_i.fix_image_size().unwrap();
        let first_thunk_raw = unsafe {
            target_image_i // remember target_image_i (mut ) vs target_image_o imut
                .as_mut_ptr()
                .offset(temp_offset.try_into().unwrap())
        };

        // https://stackoverflow.com/a/74614200 mutable reference to first thunk (0x0 empty byte)
        let first_thunk: &mut Thunk64 = unsafe { std::mem::transmute(first_thunk_raw) }; // undefined behavior errorr when using : let first_thunk_raw = >>&<<target_image_i..
        unsafe {
            (*first_thunk).0 = iat_rva_actual as u64;
        }

        (*descriptor_modify).first_thunk = exe::types::RVA::from(iat_rva_actual);

        // >> added 8:23 am
        // 4) Join originalFirstThunk

        let temp_offset: usize =
            find_padding(&target_image_i, &new_section, 0xcc, size_of_thunks).unwrap();

        println!(
            "4) Join first originalFirstThunk) temp_offset: {}",
            temp_offset
        );
        let tmp_rva_check = &target_image_i
            .offset_to_rva(exe::types::Offset::from(temp_offset as u32))
            .unwrap();
        let tmp_rva = tmp_rva_check.0;

        println!("4) Join first originalFirstThunk) tmp_rva: {}", tmp_rva);

        // memset
        unsafe {
            ptr::write_bytes(
                target_image_i.as_mut_ptr().add(temp_offset as usize),
                0x00,
                size_of_thunks,
            )
        };

        let oft_offset: usize =
            find_padding(&target_image_i, &new_section, 0xcc, size_of_thunks).unwrap();

        let oft_rva_check = &target_image_i
            .offset_to_rva(exe::types::Offset::from(temp_offset as u32))
            .unwrap();
        let oft_rva = oft_rva_check.0;

        // Copy in name to the oft rva
        let imp_raw_name = unsafe {
            target_image_i // image_im,port_byname
                .as_mut_ptr()
                .offset(oft_offset as isize + 2 as isize)
        }; // + 2 skip first member
           //    let imp: *mut ImageImportByName = std::mem::transmute(oft_offset); // &mut

        let name = CString::new(module_import_name.clone()).unwrap();
        let name_bytes = name.as_bytes_with_nul();

        // idea offset .add() not the struct lmfao
        unsafe {
            std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), imp_raw_name, name_bytes.len())
        }; //  method 2

        // Copy the byte array into the `name` field of `ImageImportByName`
        // name_slice.copy_from_slice(name_bytes);

        let og_first_thunk = unsafe {
            target_image_i // remember target_image_i (mut ) vs target_image_o imut
                .as_mut_ptr()
                .offset(temp_offset.try_into().unwrap())
        };

        // https://stackoverflow.com/a/74614200 mutable reference to first thunk (0x0 empty byte)
        let og_first_thunk: &mut Thunk64 = unsafe { std::mem::transmute(first_thunk_raw) }; // undefined behavior errorr when using : let first_thunk_raw = >>&<<target_image_i..

        (*og_first_thunk).0 = oft_rva as u64;

        (*descriptor_modify).original_first_thunk = exe::types::RVA::from(tmp_rva);

        // now nullbytes

        unsafe {
            ptr::write_bytes(
                descriptor_buffer_ptr as *mut _,
                0,
                std::mem::size_of::<ImageImportDescriptor>() as usize,
            )
        };

        println!("IAT fix loop Done!");
        println!("target img len: {}", &target_image_i.len());
        // debug
        let mut line = String::new();
        let input = std::io::stdin()
            .read_line(&mut line)
            .expect("Failed to read line");

        if (to_save_debug) {
            println!(
                "heres the saved PE: (rva was in for this improt)\n details{} <- should be here {}",
                module_name, module_import_name
            );
            target_image_i.save("check.exe").unwrap();
        }
    } else {
        println!("Import found, now look for rva.");
        // new size should increment by 20 every iteration (eg new imo)
    }
}
