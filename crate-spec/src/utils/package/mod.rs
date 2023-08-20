//!package definition
pub mod bin;
mod gen_bincode;
use bincode::{Decode, Encode};
use cms::signed_data::SignedData;
//Types used in CratePackage

///Unsigned file offset
#[derive(Encode, Decode)]
pub struct Off(pub u32);

///Unsigned file size
#[derive(Encode, Decode, Debug)]
#[derive(Default)]
pub struct Size(pub u32);

///Unsigned type id
#[derive(Encode, Decode)]
pub struct Type(pub u8);

///Unsigned small int
#[derive(Encode, Decode)]
pub struct Uchar(pub u8);

///Unsigned str offset
#[derive(Encode, Decode)]
pub struct StrOff(pub u32);

//custom Encode
//custom Decode
///len + array
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
}
/// array
/// custom Encode
/// self Decode
#[derive(Debug)]
pub struct RawArrayType<T>{
    pub arr:Vec<T>
}

impl<T> RawArrayType<T>{
    fn new()->Self{
        Self{
            arr: vec![],
        }
    }
}

/// custom Encode
/// self Decode
pub struct PKCS7Struct{
    pub cms: SignedData
}


//package structure

//auto encode
//self decode
///top-level package structure
#[derive(Encode)]
pub struct CratePackage{
    pub magic_number: RawArrayType<Uchar>,
    pub create_header: CrateHeader,
    pub string_table: RawArrayType<Uchar>,
    pub section_index: SectionIndex,
    pub data_sections: RawArrayType<DataSection>,
    pub finger_print: RawArrayType<Uchar>,
}

//auto encode
//auto decode
///crate header structure
#[derive(Encode, Decode)]
pub struct CrateHeader{
    pub c_version: Uchar,
    pub c_flsize: Size,
    pub strtable_size: Size,
    pub strtable_offset: Off,
    pub sh_size: Size,
    pub sh_offset: Off
}

//auto encode
//self decode
///section index structure
#[derive(Encode)]
pub struct SectionIndex{
    pub entries: RawArrayType<SectionIndexEntry>
}

//auto encode
//auto decode
///section index entry structure
#[derive(Encode, Decode)]
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

//custom encode
//non-self decode
//data sections
pub enum DataSection{
    PackageSection(PackageSection),
    DepTableSection(DepTableSection),
    SigStructureSection(SigStructureSection)
}

//auto encode
//auto decode
///package section structure
#[derive(Encode, Decode)]
pub struct PackageSection{
    pub pkg_name: StrOff,
    pub pkg_version: StrOff,
    pub pkg_license: StrOff,
    pub pkg_authors: LenArrayType<StrOff>
}

//auto encode
//auto decode
///Dependency table section structure
#[derive(Encode, Decode)]
pub struct DepTableSection{
    pub dep_name : StrOff,
    pub dep_verreq: StrOff,
    pub dep_srctype: Type,
    pub dep_srcpath: StrOff,
    pub dep_platform: StrOff
}

//auto encode
//self decode
#[derive(Encode)]
pub struct CrateBinarySection{
    pub bin: RawArrayType<Uchar>
}

//auto encode
//custom decode
///Signature  section structure
#[derive(Encode)]
pub struct SigStructureSection{
    sigstruct_size: Size,
    sigstruct_type: Type,
    sigstruct_sig: PKCS7Struct
}


