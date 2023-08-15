//!package definition
use cms::signed_data::SignedData;

//Types used in CratePackage

///Unsigned file offset
pub struct Off(pub usize);
///Unsigned file size
pub struct Size(pub usize);
///Unsigned type id
pub struct Type(pub u8);
///Unsigned small int
pub struct Uchar(pub u8);
///Unsigned str offset
pub struct StrOff(pub usize);

///len + array
pub struct LenArrayType<T>{
    pub len:Size,
    pub arr:Vec<T>
}

/// array
pub struct RawArrayType<T>{
    pub arr:Vec<T>
}

pub struct PKCS7Struct{
    pub cms: SignedData
}


//package structure

///top-level package structure
pub struct CratePackage{

}

///crate header structure
pub struct CrateHeader{
    pub c_version: Uchar,
    pub c_flsize: Size,
    pub strtable_size: Size,
    pub strtable_offset: Off,
    pub sh_size: Size,
    pub sh_offset: Off
}

///section index structure
pub struct SectionIndex{
    pub entries: RawArrayType<SectionIndexEntry>
}

///section index entry structure
pub struct SectionIndexEntry{
    pub sh_type: Type,
    pub sh_offset: Off,
    pub sh_size: Size
}

//data sections
///package section structure
pub struct PackageSection{
    pub pkg_name: StrOff,
    pub pkg_version: StrOff,
    pub pkg_license: StrOff,
    pub pkg_authors: LenArrayType<StrOff>
}

///package section structure
pub struct DepTableSection{
    pub dep_name : StrOff,
    pub dep_verreq: StrOff,
    pub dep_srctype: Type,
    pub dep_srcpath: StrOff,
    pub dep_platform: StrOff
}

///Signature  section
pub struct SigStructure{
    sigstruct_size: Size,
    sigstruct_type: Type,
    sigstruct_sig: PKCS7Struct
}


