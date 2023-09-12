use crate::utils::context::{BinaryLayout, CrateBinary, PackageContext, SigInfo, StringTable};
use crate::utils::package::{CrateBinarySection, CrateHeader, CratePackage, CRATEVERSION, DataSection, DataSectionCollectionType, DepTableSection, FINGERPRINT_LEN, get_datasection_type, MAGIC_NUMBER, Off, PackageSection, RawArrayType, SectionIndex, SectionIndexEntry, Size};
use crate::utils::package::bin::Encode;
use crate::utils::package::gen_bincode::encode2vec_by_bincode;


impl CratePackage{
    pub fn set_section_index(&mut self){
        self.section_index.entries.arr = vec![];
        for (i, (_size, _off)) in self.data_sections.encode_size_offset().iter().enumerate(){
            let size = *_size;
            let off = *_off;
            let typ = get_datasection_type(&self.data_sections.col.arr[i]);
            self.section_index.entries.arr.push(SectionIndexEntry::new(typ, off as Off, size as Size));
        }
    }

    pub fn set_string_table(&mut self, str_table: & StringTable){
        self.string_table = RawArrayType::from_vec(str_table.to_bytes());
    }


    pub fn set_crate_header(&mut self, fake_num: usize){
        self.crate_header.c_version = CRATEVERSION;
        self.crate_header.strtable_size = self.string_table.get_size() as Size;
        self.crate_header.strtable_offset = (self.crate_header.get_size() + self.magic_number.len()) as Size;
        self.crate_header.si_not_sig_size = self.section_index.get_none_sig_size() as Size;
        self.crate_header.si_not_sig_num = self.section_index.get_none_sig_num() as Size;
        self.crate_header.si_size = self.section_index.get_size() as Size + (fake_num * SectionIndexEntry::default().get_size()) as Size;
        self.crate_header.si_num = self.section_index.get_num() as Size + fake_num as Size;
        self.crate_header.si_offset = self.crate_header.strtable_offset + self.crate_header.strtable_size;
        self.crate_header.ds_offset = self.crate_header.si_offset + self.crate_header.si_size;
    }

    pub fn set_magic_numer(&mut self){
        self.magic_number = MAGIC_NUMBER;
    }

    pub fn set_finger_print(&mut self, fp: Vec<u8>){
        self.finger_print.copy_from_slice(fp.as_slice());
    }
}


impl PackageContext{
    fn set_sigs(&self, crate_package: &mut CratePackage){
        self.write_to_data_section_collection_sig(&mut crate_package.data_sections);
    }

    fn set_pack_dep_bin(&self, crate_package: &mut CratePackage, str_table: &mut StringTable){
        self.write_to_data_section_collection_without_sig(&mut crate_package.data_sections, str_table);
    }

    //1 before sig
    fn encode_to_crate_package_before_sig(&self, str_table: &mut StringTable,  crate_package: &mut CratePackage, sig_num: usize){
        crate_package.set_magic_numer();
        crate_package.set_string_table(str_table);
        self.set_pack_dep_bin(crate_package, str_table);
        crate_package.set_section_index();
        crate_package.set_crate_header(sig_num);
    }

    //2 sig
    fn encode_sig_to_crate_package(&self, crate_package: &mut CratePackage){
        self.set_sigs(crate_package);
    }

    //3 after sig
    fn encode_to_crate_package_after_sig(&self, crate_package: &mut CratePackage){
        crate_package.set_section_index();
        crate_package.set_crate_header(0);
        //FIXME current it's not right
        crate_package.set_finger_print([0;256].to_vec());
    }


    //1 2 3
    pub fn encode_to_crate_package(&self, str_table: &mut StringTable, crate_package: &mut CratePackage){
        self.encode_to_crate_package_before_sig(str_table, crate_package, self.get_sig_num());
        self.encode_sig_to_crate_package(crate_package);
        self.encode_to_crate_package_after_sig(crate_package);
    }
}




#[test]
fn test_encode() {

}

