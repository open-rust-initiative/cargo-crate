
use crate::utils::context::{NOT_SIG_NUM, PackageContext,  StringTable};
use crate::utils::package::{ CratePackage, CRATEVERSION,   FINGERPRINT_LEN, get_datasection_type, MAGIC_NUMBER, Off,  RawArrayType,  SectionIndexEntry, Size};

use crate::utils::package::gen_bincode::{encode2vec_by_bincode};
use crate::utils::pkcs::PKCS;


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
    fn set_sigs(&self, crate_package: &mut CratePackage, non_sig_num:usize){
        crate_package.data_sections.col.arr.truncate(non_sig_num);
        self.write_to_data_section_collection_sig(&mut crate_package.data_sections);
    }

    fn set_pack_dep_bin(&self, crate_package: &mut CratePackage, str_table: &mut StringTable){
        self.write_to_data_section_collection_without_sig(&mut crate_package.data_sections, str_table);
    }

    fn calc_sigs(&mut self, crate_package: &CratePackage){
        let bin_all = encode2vec_by_bincode(crate_package);
        let bin_all = self.get_binary_before_sig(crate_package, bin_all.as_slice());
        let bin_crate = crate_package.get_crate_binary_section().bin.arr.as_slice();
        self.sigs.iter_mut().for_each(|siginfo|{
            let digest;
            match siginfo.typ {
                0 => {
                    digest = siginfo.pkcs.gen_digest_256(bin_all.as_slice());
                }
                1 => {
                    digest = siginfo.pkcs.gen_digest_256(bin_crate);
                }
                _ => {panic!("sig type is not right!")}
            }
            siginfo.bin = siginfo.pkcs.encode_pkcs_bin(digest.as_slice());
            siginfo.size = siginfo.bin.len();
        });
    }

    fn calc_fingerprint(&self, crate_package: &CratePackage)->Vec<u8>{
        let bin_all = encode2vec_by_bincode(crate_package);
        PKCS::new().gen_digest_256(&bin_all[..bin_all.len() - FINGERPRINT_LEN])
    }

    //1 before sig
    fn encode_to_crate_package_before_sig(&self, str_table: &mut StringTable, crate_package: &mut CratePackage){
        crate_package.set_magic_numer();
        self.set_pack_dep_bin(crate_package, str_table);
        //this is setting fake sigsection
        self.set_sigs(crate_package, NOT_SIG_NUM);
        crate_package.set_section_index();
        crate_package.set_string_table(str_table);
        crate_package.set_crate_header(0);
    }

    //2 sig
    fn encode_sig_to_crate_package(&mut self, crate_package: &mut CratePackage){
        self.calc_sigs(crate_package);
        //this is setting true sigsection
        self.set_sigs(crate_package, NOT_SIG_NUM);
    }

    //3 after sig
    fn encode_to_crate_package_after_sig(&self, crate_package: &mut CratePackage){
        crate_package.set_section_index();
        crate_package.set_crate_header(0);
        let finger_print = self.calc_fingerprint(crate_package);
        crate_package.set_finger_print(finger_print);
    }


    //1 2 3
    pub fn encode_to_crate_package(&mut self)->(CratePackage, StringTable, Vec<u8>){
        let mut crate_package =  CratePackage::new();
        let mut str_table = StringTable::new();
        self.encode_to_crate_package_before_sig(&mut str_table, &mut crate_package, );
        self.encode_sig_to_crate_package(&mut crate_package);
        self.encode_to_crate_package_after_sig(&mut crate_package);
        let bin = encode2vec_by_bincode(&crate_package);
        (crate_package, str_table, bin)
    }
}
