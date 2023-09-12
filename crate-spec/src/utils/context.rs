use std::collections::{HashMap};
use std::io::BufReader;
use crate::utils::package::{CrateBinarySection, DataSection, DataSectionCollectionType, DepTableEntry, DepTableSection, LenArrayType, PackageSection, RawArrayType};
use crate::utils::package::gen_bincode::encode_size_by_bincode;
///package context contains package's self and dependency package info
pub struct PackageContext {
    pub pack_info: PackageInfo,
    pub dep_infos: Vec<DepInfo>,
    pub crate_binary: CrateBinary,
    // pack_section_size: Option<u32>,
    // dep_table_section_size: Option<u32>,
    // crate_binary_section_size: Option<u32>
}

impl PackageContext{
    pub fn new()->Self{
        Self{
            pack_info: PackageInfo::default(),
            crate_binary: CrateBinary::new(),
            dep_infos: vec![],
            // pack_section_size: None,
            // dep_table_section_size: None,
            // crate_binary_section_size: None
        }
    }

    pub fn write_to_data_section_collection(&self, dsc: &mut DataSectionCollectionType, str_table: &mut StringTable){
        let mut package_section = PackageSection::new();
        self.write_to_package_section(&mut package_section, str_table);
        dsc.col.arr.push(DataSection::PackageSection(package_section));


        let mut dep_table_section = DepTableSection::new();
        self.write_to_dep_table_section(&mut dep_table_section, str_table);
        dsc.col.arr.push(DataSection::DepTableSection(dep_table_section));

        let mut binary_section = CrateBinarySection::new();
        self.write_to_crate_binary_section(&mut binary_section);
        dsc.col.arr.push(DataSection::CrateBinarySection(binary_section));
    }

    pub fn write_to_package_section(&self, ps: &mut PackageSection, str_table: &mut StringTable){
        self.pack_info.write_to_package_section(ps, str_table);
        encode_size_by_bincode(ps);
    }

    pub fn read_from_package_section(&mut self, ps: &PackageSection, str_table: & StringTable){
        self.pack_info.read_from_package_section(ps, str_table);
    }

    pub fn write_to_dep_table_section(&self, dts:&mut DepTableSection, str_table: &mut StringTable){
        let mut entries = vec![];
        self.dep_infos.iter().for_each(|dep_info|{
            let mut dte = DepTableEntry::new();
            dep_info.write_to_dep_table_entry(&mut dte, str_table);
            entries.push(dte);
        });
        dts.entries = LenArrayType::from_vec(entries);
    }

    pub fn read_from_dep_table_section(&mut self, dts:& DepTableSection, str_table: &mut StringTable){
        dts.entries.arr.iter().for_each(|dte|{
            let mut dep_info = DepInfo::default();
            dep_info.read_from_dep_table_entry(dte, str_table);
            self.dep_infos.push(dep_info);
        });
    }

    pub fn write_to_crate_binary_section(&self, cbs: &mut CrateBinarySection){
        self.crate_binary.write_to_crate_binary_section(cbs);
    }

    pub fn read_from_crate_biary_section(&mut self, cbs:& CrateBinarySection){
        self.crate_binary.read_from_crate_biary_section(cbs);
    }
}
///package's info
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub lisense: String,
    pub authors: Vec<String>
}

impl PackageInfo{
    pub fn default()->Self{
        Self{
            name: "".to_string(),
            version: "".to_string(),
            lisense: "".to_string(),
            authors: vec![],
        }
    }

    pub fn new(name: String, version:String, lisense:String, authors:Vec<String>)->Self{
        Self{
            name,
            version,
            lisense,
            authors
        }
    }

    pub fn write_to_package_section(&self, ps: &mut PackageSection, str_table: &mut StringTable){
        ps.pkg_name = str_table.insert_str(self.name.clone());
        ps.pkg_version = str_table.insert_str(self.version.clone());
        ps.pkg_license = str_table.insert_str(self.lisense.clone());
        let mut authors_off = vec![];
        self.authors.iter().for_each(|author|{
            authors_off.push(str_table.insert_str(author.clone()));
        });
        ps.pkg_authors = LenArrayType::copy_from_vec(&authors_off);
    }

    pub fn read_from_package_section(&mut self, ps: &PackageSection, str_table: & StringTable){
        self.name = str_table.get_str_by_off(&ps.pkg_name);
        self.version = str_table.get_str_by_off(&ps.pkg_version);
        self.lisense = str_table.get_str_by_off(&ps.pkg_license);
        let authors_off = ps.pkg_authors.to_vec();
        authors_off.iter().for_each(|author_off|{
            self.authors.push(str_table.get_str_by_off(author_off));
        });
    }
}

///dependencies' info
pub struct DepInfo {
    pub name: String,
    pub ver_req: String,
    pub src: SrcTypePath,
    pub src_platform: String,
    ///only dump dependency that can be written to crate dependency table section
    pub dump: bool
}

impl DepInfo{
    pub fn default()->Self{
        Self{
            name: "".to_string(),
            ver_req: "".to_string(),
            src: SrcTypePath::crates_io,
            src_platform: "".to_string(),
            dump: false,
        }
    }

    pub fn new(name: String, ver_req:String, src: SrcTypePath, src_platform: String, dump:bool)->Self{
        Self{
            name,
            ver_req,
            src,
            src_platform,
            dump
        }
    }

    pub fn write_to_dep_table_entry(&self, dte: &mut DepTableEntry, str_table: &mut StringTable){
        dte.dep_name = str_table.insert_str(self.name.clone());
        dte.dep_verreq = str_table.insert_str(self.ver_req.clone());
        match &self.src{
            SrcTypePath::crates_io=>{
                dte.dep_srctype = 0;
                dte.dep_srcpath = str_table.insert_str("".to_string());
            }
            SrcTypePath::git(str)=>{
                dte.dep_srctype = 1;
                dte.dep_srcpath = str_table.insert_str(str.clone());
            }
            SrcTypePath::url(str)=>{
                dte.dep_srctype = 2;
                dte.dep_srcpath = str_table.insert_str(str.clone());
            }
            SrcTypePath::registry(str)=>{
                dte.dep_srctype = 3;
                dte.dep_srcpath = str_table.insert_str(str.clone());
            }
            SrcTypePath::p2p(str)=>{
                dte.dep_srctype = 4;
                dte.dep_srcpath = str_table.insert_str(str.clone());
            }
        }
        dte.dep_platform = str_table.insert_str(self.src_platform.to_string());
    }

    pub fn read_from_dep_table_entry(&mut self, dte: & DepTableEntry, str_table: &StringTable){
        self.dump = true;
        self.name = str_table.get_str_by_off(&dte.dep_name);
        self.ver_req = str_table.get_str_by_off(&dte.dep_verreq);
        match dte.dep_srctype{
            0 => {
                self.src = SrcTypePath::crates_io;
            }
            1 => {
                self.src = SrcTypePath::git(str_table.get_str_by_off(&dte.dep_srcpath));
            }
            2 => {
                self.src = SrcTypePath::url(str_table.get_str_by_off(&dte.dep_srcpath));
            }
            3 => {
                self.src = SrcTypePath::registry(str_table.get_str_by_off(&dte.dep_srcpath));
            }
            4 => {
                self.src = SrcTypePath::p2p(str_table.get_str_by_off(&dte.dep_srcpath));
            }
            _ => {
                panic!("dep_srctype not valid!")
            }
        }
        self.src_platform = str_table.get_str_by_off(&dte.dep_platform);
    }
}

///dependencies' src type and path
pub enum SrcTypePath{
    crates_io,
    git(String),
    url(String),
    registry(String),
    p2p(String)
}

///StringTable
pub struct StringTable{
    str2off: HashMap<String, u32>,
    off2str: HashMap<u32, String>,
    total_bytes: u32
}

impl StringTable{
    pub fn default()->Self{
        Self::new()
    }

    pub fn new()->Self{
        let mut new_str_table = Self{
            str2off: Default::default(),
            off2str: Default::default(),
            total_bytes: 0,
        };
        new_str_table.insert_str("".to_string());
        new_str_table
    }

    pub fn insert_str(&mut self, st:String)->u32{
        if self.str2off.contains_key(&st){
            return self.str2off.get(&st).unwrap().clone();
        }else{
            let st_len = st.as_bytes().len() as u32;
            let ret_val = self.total_bytes;
            self.str2off.insert(st.clone(), self.total_bytes);
            self.off2str.insert(self.total_bytes, st.clone());
            self.total_bytes += 4 + st_len;
            return ret_val;
        }
    }

    pub fn contains_str(&self, st: &String)->bool{
        self.str2off.contains_key(st)
    }

    pub fn get_off_by_str(&self, st: &String)-> u32{
        *self.str2off.get(st).unwrap()
    }

    pub fn get_str_by_off(&self, off: &u32)->String{
        self.off2str.get(off).unwrap().clone()
    }

    ///dump string table to bytes
    pub fn to_bytes(&self)->Vec<u8>{
        let mut offs:Vec<_> = self.off2str.keys().cloned().collect();
        offs.sort();
        let mut bytes = vec![];
        for off in offs{
            //FIXME we use little endian
            bytes.extend(off.to_le_bytes());
            bytes.extend(self.off2str.get(&off).unwrap().bytes());
        }
        return bytes;
    }

    ///parse string table from bytes
    pub fn from_bytes(&mut self, bytes: &[u8]){
        let mut i = 0;
        while i < bytes.len(){
            let mut len_bytes:[u8; 4]= [0;4];
            len_bytes.copy_from_slice(bytes[i..i+4].as_ref());
            let len = u32::from_le_bytes(len_bytes) as usize;
            let st = String::from_utf8(bytes[i + 4..i + 4 + len].to_vec()).unwrap();
            self.str2off.insert(st.clone(), i as u32);
            self.off2str.insert(i as u32, st);
            i += 4 + len;
            self.total_bytes = i as u32;
        }
    }
}

pub struct CrateBinary {
    //FIXME this maybe change to for fast read
    pub bytes:Vec<u8>,
}

impl CrateBinary{
    pub fn new()->Self{
        Self{
            bytes:vec![]
        }
    }

    pub fn write_to_crate_binary_section(&self, cbs: &mut CrateBinarySection){
        cbs.bin.arr = self.bytes.to_vec();
    }

    pub fn read_from_crate_biary_section(&mut self, cbs:& CrateBinarySection){
        self.bytes = cbs.bin.arr.to_vec();
    }
}

pub struct BinaryLayout{
    pub magic_number:Vec<u8>,
    pub crate_header:Vec<u8>,
    pub string_table:Vec<u8>,
    pub section_index:Vec<u8>,
    pub section_index_fake: Vec<u8>,
    pub data_sections:Vec<Vec<u8>>,
    pub finger_print:Vec<u8>,
    sig_num: u32,
}

impl BinaryLayout{
    pub fn new(sig_num: u32)->Self{
        Self{
            magic_number: vec![],
            crate_header: vec![],
            string_table: vec![],
            section_index: vec![],
            section_index_fake: vec![],
            data_sections: vec![],
            finger_print: vec![],
            sig_num
        }
    }
}