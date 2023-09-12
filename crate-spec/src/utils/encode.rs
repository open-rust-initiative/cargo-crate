use crate::utils::context::{BinaryLayout, CrateBinary, PackageContext, SigInfo, StringTable};
use crate::utils::package::{CrateBinarySection, CrateHeader, CratePackage, CRATEVERSION, DataSection, DataSectionCollectionType, DepTableSection, FINGERPRINT_LEN, get_datasection_type, MAGIC_NUMBER, Off, PackageSection, RawArrayType, SectionIndex, SectionIndexEntry, Size};
use crate::utils::package::bin::Encode;
use crate::utils::package::gen_bincode::encode2vec_by_bincode;


// pub fn write_pack_context_to_data_section(pack_context: &PackageContext, str_table: &mut StringTable,  crate_package: &mut CratePackage){
//     let mut si = SectionIndex::new();
//     let mut offset = 0;
//     let mut size = 0;
//     let mut ds = DataSectionCollectionType::new();
//
//     let mut package_section = PackageSection::new();
//     pack_context.write_to_package_section(&mut package_section, str_table);
//     size = package_section.get_size() as Size;
//     si.entries.arr.push(SectionIndexEntry::new(0, offset, size));
//     offset += size;
//     ds.col.arr.push(DataSection::PackageSection(package_section));
//
//
//     let mut dep_table_section = DepTableSection::new();
//     pack_context.write_to_dep_table_section(&mut dep_table_section, str_table);
//     size = dep_table_section.get_size() as Size;
//     si.entries.arr.push(SectionIndexEntry::new(1, offset, size));
//     offset += size;
//     ds.col.arr.push(DataSection::DepTableSection(dep_table_section));
//
//     let mut binary_section = CrateBinarySection::new();
//     pack_context.write_to_crate_binary_section(&mut binary_section);
//     size = binary_section.get_size() as Size;
//     si.entries.arr.push(SectionIndexEntry::new(3, offset, size));
//     offset += size;
//     ds.col.arr.push(DataSection::CrateBinarySection(binary_section));
//
//     crate_package.data_sections = ds;
//     crate_package.section_index = si;
// }


// pub fn write_sig_to_crate_package(crate_package: &mut CratePackage){
//     //SigStructureSection
// }

// pub fn write_crate_header_to_crate_package(crate_package: &mut CratePackage, sig_num:usize){
//     let mut crate_header = CrateHeader::new();
//     crate_header.c_version = CRATEVERSION;
//
//     let mut offset = (crate_package.magic_number.len() + crate_header.get_size()) as Size;
//     crate_header.strtable_offset = offset;
//     crate_header.strtable_size = crate_package.string_table.get_size() as Size;
//
//     offset += crate_header.strtable_size;
//     crate_header.si_offset = offset;
//     crate_header.si_size = crate_package.section_index.get_size() as Size;
//     crate_header.si_num = crate_package.section_index.section_num();
//     crate_header.si_not_sig_size = sig_num as Size;
// }

// pub fn write_to_crate_package_first(pack_context: &PackageContext, str_table: &mut StringTable,  crate_package: &mut CratePackage, sig_num: usize)->Vec<u8>{
//     crate_package.magic_number = MAGIC_NUMBER;
//     crate_package.string_table = RawArrayType::from_vec(str_table.to_bytes());
//     write_pack_context_to_data_section(pack_context, str_table, crate_package);
//
//     //fake sigStructure index
//     for i in 0..sig_num{
//         crate_package.section_index.entries.arr.push(SectionIndexEntry::new(0, 0, 0));
//     }
//     //write_crate_header_to_crate_package(crate_package);
//     let mut bin = encode2vec_by_bincode(crate_package);
//
//     //pop fake sigstructure index
//     for i in 0..sig_num{
//         crate_package.section_index.entries.arr.pop();
//     }
//     bin
// }



impl PackageContext{
    fn set_sigs(&self, crate_package: &mut CratePackage){
        self.write_to_data_section_collection_sig(&mut crate_package.data_sections);
    }

    fn encode_sig_to_crate_package(&self, crate_package: &mut CratePackage){
        self.set_sigs(crate_package);
    }

    fn encode_to_crate_package_before_sig(&self, str_table: &mut StringTable,  crate_package: &mut CratePackage, sig_num: usize){
        crate_package.set_magic_numer();
        crate_package.set_string_table(str_table);
        self.set_data_sections_without_sig(crate_package, str_table);
        crate_package.set_section_index();
        crate_package.set_crate_header(sig_num);
    }

    fn set_data_sections_without_sig(&self, crate_package: &mut CratePackage, str_table: &mut StringTable){
        self.write_to_data_section_collection_without_sig(&mut crate_package.data_sections, str_table);
    }

    fn encode_to_crate_package_after_sig(&self, crate_package: &mut CratePackage){
        crate_package.set_section_index();
        crate_package.set_crate_header(0);
        //FIXME current it's not right
        crate_package.set_finger_print([0;256].to_vec());
    }

    pub fn encode_to_crate_package(&self, str_table: &mut StringTable, crate_package: &mut CratePackage){
        self.encode_to_crate_package_before_sig(str_table, crate_package, self.get_sig_num());
        self.encode_sig_to_crate_package(crate_package);
        self.encode_to_crate_package_after_sig(crate_package);
    }
}

impl CratePackage{
    pub fn get_binary_before_sig(&mut self)->Vec<u8>{
        let mut buf = vec![];
        buf.extend(encode2vec_by_bincode(&self.magic_number));
        buf.extend(encode2vec_by_bincode(&self.string_table));
        buf.extend(self.section_index.encode_fake_to_vec(self.crate_header.si_not_sig_size as usize, self.crate_header.si_size as usize));
        buf.extend(self.data_sections.encode_fake_to_vec(self.section_index.fake_datasection_size(self.crate_header.si_not_sig_num)));
        buf
    }

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




#[test]
fn test() {

}

