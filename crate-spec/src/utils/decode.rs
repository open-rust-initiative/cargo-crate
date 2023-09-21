use crate::utils::context::{DepInfo, PackageContext, SigInfo, StringTable};
use crate::utils::package::{CrateBinarySection, CratePackage, DataSection, DepTableSection, FINGERPRINT_LEN,  PackageSection, SectionIndex, SigStructureSection};

use crate::utils::pkcs::PKCS;


impl SectionIndex{
    pub fn get_section_id_by_typ(&self, typ:usize)->usize{
        for (i, entry) in self.entries.arr.iter().enumerate(){
            if entry.sh_type as usize == typ{
                return i;
            }
        }
        panic!("section typ not found")
    }
}


impl CratePackage{
    pub fn get_data_section_by_id(&self, id:usize)->&DataSection{
        &self.data_sections.col.arr[id]
    }

    pub fn get_data_section_by_typ(&self, typ:usize)->&DataSection{
        self.get_data_section_by_id(self.section_index.get_section_id_by_typ(typ))
    }

    pub fn get_package_section(&self)->&PackageSection{
        //FIXME: 0 should be constant
        match self.get_data_section_by_typ(0){
            DataSection::PackageSection(pak)=>{pak}
            _ => {panic!("package section not found!")}
        }
    }

    pub fn get_dep_table_section(&self)->&DepTableSection{
        match self.get_data_section_by_typ(1){
            DataSection::DepTableSection(dep) => {dep},
            _ => {panic!("dep table section not found!")}
        }
    }

    pub fn get_crate_binary_section(&self)->&CrateBinarySection{
        match self.get_data_section_by_typ(3){
            DataSection::CrateBinarySection(cra) => {cra},
            _ => {panic!("crate binary section not found!")}
        }
    }

    pub fn get_sig_structure_section(&self, no: usize)-> &SigStructureSection{
        let base = self.section_index.get_section_id_by_typ(4);
        match self.get_data_section_by_id(no + base){
            DataSection::SigStructureSection(sig) => {sig},
            _ => {panic!("sig structure section not found!")}
        }
    }

}
impl PackageContext{
    pub fn get_binary_before_sig(&self, crate_package: &CratePackage, bin:&[u8]) -> Vec<u8> {
        //FIXME
        let ds_size = crate_package.section_index.get_datasection_size_without_sig();
        let total_size = crate_package.crate_header.ds_offset as usize + ds_size;
        if crate_package.section_index.get_sig_num() != self.sigs.len() && self.sigs.len() > 0{
            assert_eq!(crate_package.section_index.get_sig_num(), 0);

        }else{

        }
        let mut buf = bin[..total_size].to_vec();
        let zero_begin = crate_package.crate_header.si_offset as usize + crate_package.section_index.get_none_sig_size();
        let zero_end = crate_package.crate_header.si_offset as usize + crate_package.crate_header.si_size as usize;
        //FIXME this is not efficient
        for i in zero_begin..zero_end{
            buf[i] = 0;
        }

        buf
    }

    pub fn get_binary_before_digest(&self, bin:&[u8])-> Vec<u8>{
        bin[..bin.len() - FINGERPRINT_LEN].to_vec()
    }

    fn get_pack_info(&mut self, crate_package: &CratePackage, str_table: &StringTable){
        self.pack_info.read_from_package_section(crate_package.get_package_section(), &str_table);
    }


    fn get_deps(&mut self, crate_package: &CratePackage, str_table: &StringTable){
        for entry in crate_package.get_dep_table_section().entries.arr.iter(){
            let mut dep_info = DepInfo::default();
            dep_info.read_from_dep_table_entry(entry, str_table);
            self.dep_infos.push(dep_info);
        }
    }

    fn get_binary(&mut self, crate_package: &CratePackage){
        self.crate_binary.bytes = crate_package.get_crate_binary_section().bin.arr.clone();
    }

    fn get_sigs(&mut self, crate_package: &CratePackage){
        let sig_num = crate_package.section_index.get_sig_num();
        for no in 0.. sig_num{
            let sig = crate_package.get_sig_structure_section(no);
            let mut sig_info = SigInfo::new();
            sig_info.bin = sig.sigstruct_sig.arr.clone();
            sig_info.size = sig.sigstruct_size as usize;
            sig_info.typ = sig.sigstruct_type as u32;
            self.sigs.push(sig_info);
        }
    }

    fn check_fingerprint(&self, bin_all:&[u8])->bool{
        PKCS::new().gen_digest_256(&bin_all[..bin_all.len() - FINGERPRINT_LEN]) == bin_all[bin_all.len() - FINGERPRINT_LEN..]
    }

    fn check_sigs(&self, crate_package: &CratePackage, bin_all:&[u8])->bool{
        let bin_all = self.get_binary_before_sig(crate_package, bin_all);
        let bin_crate = crate_package.get_crate_binary_section().bin.arr.as_slice();
        for siginfo in self.sigs.iter(){
            let actual_digest ;
            //FIXME this should be encapsulated as it's used in encode as well
            match siginfo.typ {
                0 => {
                    actual_digest = siginfo.pkcs.gen_digest_256(bin_all.as_slice());
                }
                1 => {
                    actual_digest = siginfo.pkcs.gen_digest_256(bin_crate);
                }
                _ => {panic!("sig type is not right!")}
            }
            let expect_digest = PKCS::decode_pkcs_bin(siginfo.bin.as_slice(), &self.root_cas);
            if actual_digest != expect_digest {
                return false
            };
        }
        true
    }

    pub fn decode_from_crate_package(&mut self, bin:&[u8])->Result<(CratePackage, StringTable), String>{
        if self.check_fingerprint( bin) == false{
            return Err("fingerprint not right".to_string());
        }
        let crate_package = CratePackage::decode_from_slice(bin)?;
        let mut str_table = StringTable::new();
        str_table.read_bytes(crate_package.string_table.arr.as_slice());
        self.get_pack_info(&crate_package, &str_table);
        self.get_deps(&crate_package, &str_table);
        self.get_binary(&crate_package);
        self.get_sigs(&crate_package);
        if self.check_sigs(&crate_package, bin) == false{
            return Err("file sig not right".to_string());
        }
        return Ok((crate_package, str_table));
    }
}

#[test]
fn test_encode_decode() {
    use crate::utils::context::{PackageInfo, SIGTYPE, SrcTypePath};
    fn get_pack_info()->PackageInfo{
        PackageInfo{
            name: "rust-crate".to_string(),
            version: "1.0.0".to_string(),
            license: "MIT".to_string(),
            authors: vec!["shuibing".to_string(), "rust".to_string()],
        }
    }

    fn get_dep_info1()->DepInfo{
        DepInfo{
            name: "toml".to_string(),
            ver_req: "1.0.0".to_string(),
            src: SrcTypePath::CratesIo,
            src_platform: "ALL".to_string(),
            dump: true,
        }
    }


    fn get_dep_info2()->DepInfo{
        DepInfo{
            name: "crate-spec".to_string(),
            ver_req: ">=0.8.0".to_string(),
            src: SrcTypePath::Git("http://git.com".to_string()),
            src_platform: "windows".to_string(),
            dump: true,
        }
    }

    fn get_crate_binary()->Vec<u8>{
        [15;100].to_vec()
    }

    fn get_sign()->PKCS{
        let mut pkcs1 = PKCS::new();
        pkcs1.load_from_file_writer("test/cert.pem".to_string(), "test/key.pem".to_string(), ["test/root-ca.pem".to_string()].to_vec());
        pkcs1
    }

    let mut package_context = PackageContext::new();

    package_context.pack_info = get_pack_info();
    package_context.dep_infos.push(get_dep_info1());
    package_context.dep_infos.push(get_dep_info2());
    package_context.crate_binary.bytes = get_crate_binary();
    package_context.add_sig(get_sign(), SIGTYPE::CRATEBIN);
    package_context.add_sig(get_sign(), SIGTYPE::FILE);

    let (_crate_package, _str_table, bin) = package_context.encode_to_crate_package();


    let mut package_context_new = PackageContext::new();
    package_context_new.set_root_cas_bin(PKCS::get_root_ca_bins(["test/root-ca.pem".to_string()].to_vec()));
    let (_crate_package_new, _str_table) = package_context_new.decode_from_crate_package(bin.as_slice()).unwrap();

    assert_eq!(get_pack_info(), package_context_new.pack_info);
    assert_eq!(get_dep_info1(), package_context_new.dep_infos[0]);
    assert_eq!(get_dep_info2(), package_context_new.dep_infos[1]);
    assert_eq!(get_crate_binary(), package_context_new.crate_binary.bytes);
}