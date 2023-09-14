use std::ops::Index;
use bincode::Encode;
use crate::utils::context::{CrateBinary, DepInfo, PackageContext, PackageInfo, SigInfo, SrcTypePath, StringTable};
use crate::utils::package::{CrateBinarySection, CratePackage, DataSection, DepTableSection, get_datasection_type, PackageSection, SectionIndex, SigStructureSection, Size, Type};
use crate::utils::package::gen_bincode::{create_bincode_slice_decoder, encode2vec_by_bincode};


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
        let mut buf = vec![];
        let ds_size = crate_package.section_index.get_datasection_size_without_sig();
        let total_size = crate_package.crate_header.ds_offset as usize + ds_size;
        buf = bin[..total_size].to_vec();
        let zero_begin = crate_package.crate_header.si_offset as usize;
        let zero_end = crate_package.crate_header.si_offset as usize + crate_package.section_index.get_none_sig_size();
        //FIXME this is not efficient
        for i in zero_begin..zero_end{
            buf[i] = 0;
        }

        buf
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
            let sig = crate_package.get_sig_structure_section(no as usize);
            let mut sig_info = SigInfo::new();
            sig_info.bin = sig.sigstruct_sig.arr.clone();
            sig_info.size = sig.sigstruct_size as usize;
            sig_info.typ = sig.sigstruct_type as u32;
            self.sigs.push(sig_info);
        }
    }

    pub fn decode_from_crate_package(&mut self, crate_package: &CratePackage)->StringTable{
        let mut str_table = StringTable::new();
        str_table.from_bytes(crate_package.string_table.arr.as_slice());
        self.get_pack_info(crate_package, &str_table);
        self.get_deps(crate_package, &str_table);
        self.get_binary(crate_package);
        self.get_sigs(crate_package);
        return str_table;
    }
}

#[test]
fn test_decode() {
    fn get_pack_info()->PackageInfo{
        PackageInfo{
            name: "rust-crate".to_string(),
            version: "1.0.0".to_string(),
            lisense: "MIT".to_string(),
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

    fn get_sig_info1()->SigInfo{
        SigInfo{
            typ: 0,
            size: 10,
            bin: vec![10; 10],
        }
    }

    fn get_sig_info2()->SigInfo{
        SigInfo{
            typ: 1,
            size: 30,
            bin: vec![15; 30],
        }
    }


    let mut crate_package = CratePackage::new();
    let mut package_context = PackageContext::new();
    let mut str_table = StringTable::new();

    package_context.pack_info = get_pack_info();

    package_context.dep_infos.push(get_dep_info1());
    package_context.dep_infos.push(get_dep_info2());
    package_context.crate_binary.bytes = vec![5; 55];

    package_context.sigs.push(get_sig_info1());
    package_context.sigs.push(get_sig_info2());

    package_context.encode_to_crate_package(&mut str_table, &mut crate_package);

    let bin = encode2vec_by_bincode(&crate_package);

    let crate_package:CratePackage = CratePackage::decode(&mut create_bincode_slice_decoder(bin.as_slice()), bin.as_slice()).unwrap();

    let mut pac = PackageContext::new();
    pac.decode_from_crate_package(&crate_package);

    println!("{:#?}", pac);

}