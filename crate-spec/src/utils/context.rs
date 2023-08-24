use std::collections::{HashMap, HashSet};
use crate::utils::package::DepTableEntry;

///package context contains package's self and dependency package info
pub struct PackageContext {
    pub pack_info: PackageInfo,
    pub dep_info: Vec<DepInfo>
}

///package's info
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub lisense: String,
    pub authors: Vec<String>
}

impl PackageInfo{
    pub fn new(name: String, version:String, lisense:String, authors:Vec<String>)->Self{
        Self{
            name,
            version,
            lisense,
            authors
        }
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
}