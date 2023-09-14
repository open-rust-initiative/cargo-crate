//!package definition
pub mod bin;
pub mod gen_bincode;

use bincode::{Decode, Encode};
use crate::utils::package::gen_bincode::encode_size_by_bincode;

//Types used in CratePackage

///Unsigned file offset
pub type Off = u32;

///Unsigned file size
pub type Size = u32;

///Unsigned type id
pub type Type=u8;

///Unsigned small int
pub type Uchar=u8;

///Unsigned str offset
type StrOff = u32;

//custom Encode
//custom Decode
///len + array
#[derive(Debug)]
pub struct LenArrayType<T: 'static>{
    pub len:Size,
    pub arr:Vec<T>
}

impl<T> LenArrayType<T>{
    pub fn new()->Self{
        LenArrayType{
            len: Default::default(),
            arr: vec![],
        }
    }

    pub fn from_vec(arr: Vec<T>)->Self{
        Self{
            len: arr.len() as Size,
            arr,
        }
    }
}

impl <T:Clone> LenArrayType<T> {
    pub fn copy_from_vec(v: &Vec<T>) ->Self{
        let mut len_array = Self::new();
        len_array.arr = v.to_vec();
        len_array.len = v.len() as Size;
        len_array
    }

    pub fn to_vec(&self)->Vec<T>{
        self.arr.to_vec()
    }
}
/// array
/// custom Encode
/// non-self Decode
#[derive(Debug)]
pub struct RawArrayType<T>{
    pub arr:Vec<T>
}

impl<T> RawArrayType<T>{
    pub fn new()->Self{
        Self{
            arr: vec![],
        }
    }

    pub fn from_vec(arr: Vec<T>)->Self{
        Self{
            arr
        }
    }
}

/// auto encode
/// self decode
/// collections(array whose elem is enum)
#[derive(Encode, Debug)]
pub struct DataSectionCollectionType{
    pub col:RawArrayType<DataSection>
}

impl DataSectionCollectionType{
    pub fn new()->Self{
        Self{
            col: RawArrayType::new()
        }
    }
}

// /// custom Encode
// /// non-self Decode
// pub struct PKCS7Struct{
//     pub cms: SignedData
// }
//
// impl PKCS7Struct{
//     pub fn new(sd: SignedData)->Self{
//         Self{
//             cms: sd
//         }
//     }
// }

//constant val
pub const MAGIC_NUMBER_LEN:usize=5;
pub type MagicNumberType = [Uchar; MAGIC_NUMBER_LEN];
pub const MAGIC_NUMBER:MagicNumberType=[0x43, 0x52, 0x41, 0x54, 0x45];
pub const FINGERPRINT_LEN:usize = 256;
pub type FingerPrintType = [Uchar; FINGERPRINT_LEN];
pub const CRATEVERSION:Uchar = 0;

//package structure

//auto encode
//non-self decode
///top-level package structure
#[derive(Encode, Debug)]
pub struct CratePackage{
    pub magic_number: MagicNumberType,
    pub crate_header: CrateHeader,
    pub string_table: RawArrayType<Uchar>,
    pub section_index: SectionIndex,
    pub data_sections: DataSectionCollectionType,
    pub finger_print: FingerPrintType
}

impl CratePackage {
    pub fn new()->Self{
        Self{
            magic_number: MAGIC_NUMBER,
            crate_header: CrateHeader::new(),
            string_table: RawArrayType::new(),
            section_index: SectionIndex::new(),
            data_sections: DataSectionCollectionType::new(),
            finger_print: [0; FINGERPRINT_LEN]
        }
    }


}

//auto encode
//auto decode
///crate header structure
#[derive(Encode, Decode, Debug)]
pub struct CrateHeader{
    pub c_version: Uchar,
    pub strtable_size: Size,
    pub strtable_offset: Off,
    pub si_size: Size,
    pub si_offset: Off,
    pub si_num: Size,
    // pub si_not_sig_num: Size,
    // pub si_not_sig_size: Size,
    pub ds_offset: Off,
}

impl CrateHeader{
    pub fn new()->Self{
        Self{
            c_version: Default::default(),
            strtable_size: Default::default(),
            strtable_offset: Default::default(),
            si_num: Default::default(),
            si_size: Default::default(),
            // si_not_sig_size:Default::default(),
            // si_not_sig_num: Default::default(),
            si_offset: Default::default(),
            ds_offset: Default::default(),
        }
    }
}

//auto encode
//self decode
///section index structure
#[derive(Encode, Debug)]
pub struct SectionIndex{
    pub entries: RawArrayType<SectionIndexEntry>
}

impl SectionIndex{
    pub fn new()->Self{
        Self{
            entries: RawArrayType::new(),
        }
    }

    pub fn section_num(&self)->Size{
        self.entries.arr.len() as Size
    }
}
//auto encode
//auto decode
///section index entry structure
#[derive(Encode, Decode, Debug)]
pub struct SectionIndexEntry{
    /*
FIXME In RFC0.1 there are no alignment requirements for the struct.
SectionIndexEntry's size is 9 bytes, 9 is not a multiple of 4
we may padding 3 bytes of 0 after each SectionIndexEntry,
so here, we use a user-defined encoder to implement the serialization of SectionIndex.
  */
    pub sh_type: Type,
    pub sh_offset: Off,
    pub sh_size: Size
}

impl SectionIndexEntry{
    pub fn default()->Self{
        Self{
            sh_type: 0,
            sh_offset: 0,
            sh_size: 0,
        }
    }

    pub fn new(sh_type:Type, sh_offset:Off, sh_size:Size)->Self{
        Self{
            sh_type,
            sh_offset,
            sh_size
        }
    }
}
//custom encode
//non-self decode
//data sections
#[derive(Debug)]
pub enum DataSection{
    //0
    PackageSection(PackageSection),
    //1
    DepTableSection(DepTableSection),
    //3
    CrateBinarySection(CrateBinarySection),
    //4
    SigStructureSection(SigStructureSection)
}

pub fn get_datasection_type(d:&DataSection)->Type{
    match d{
        DataSection::PackageSection(_) => {0}
        DataSection::DepTableSection(_) => {1}
        DataSection::CrateBinarySection(_) => {3}
        DataSection::SigStructureSection(_) => {4}
    }
}
//auto encode
//auto decode
///package section structure
#[derive(Encode, Decode, Debug)]
pub struct PackageSection{
    pub pkg_name: StrOff,
    pub pkg_version: StrOff,
    pub pkg_license: StrOff,
    pub pkg_authors: LenArrayType<StrOff>
}

impl PackageSection{
    pub fn new()->Self{
        Self{
            pkg_name: 0,
            pkg_version: 0,
            pkg_license: 0,
            pkg_authors: LenArrayType::new(),
        }
    }

}
//auto encode
//auto decode
///Dependency table entry structure
#[derive(Encode, Decode, Debug)]
pub struct DepTableEntry{
    pub dep_name : StrOff,
    pub dep_verreq: StrOff,
    pub dep_srctype: Type,
    pub dep_srcpath: StrOff,
    pub dep_platform: StrOff
}

impl DepTableEntry {
    pub fn new()->Self{
        Self{
            dep_name: 0,
            dep_verreq: 0,
            dep_srctype: 0,
            dep_srcpath: 0,
            dep_platform: 0,
        }
    }
}
//auto encode
//non-self decode
///Dependency table section structure
#[derive(Encode, Decode, Debug)]
pub struct  DepTableSection{
    pub entries:LenArrayType<DepTableEntry>
}


impl DepTableSection{
    pub fn new()->Self{
        Self{
            entries: LenArrayType::new()
        }
    }
}
//auto encode
//non-self decode
#[derive(Encode, Debug)]
pub struct CrateBinarySection{
    pub bin: RawArrayType<Uchar>
}

impl CrateBinarySection{
    pub fn new()->Self{
        Self{
            bin:RawArrayType::new()
        }
    }
}

//auto encode
//custom decode
///Signature  section structure
#[derive(Encode, Debug)]
pub struct SigStructureSection{
    pub sigstruct_size: Size,
    pub sigstruct_type: Type,
    pub sigstruct_sig: RawArrayType<u8>
}

impl SigStructureSection{
    pub fn new()->Self{
        Self{
            sigstruct_size: 0,
            sigstruct_type: 0,
            sigstruct_sig: RawArrayType::new(),
        }
    }
}

