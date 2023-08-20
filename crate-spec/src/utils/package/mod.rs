//!package definition
use cms::signed_data::SignedData;

//Types used in CratePackage

///Unsigned file offset
pub struct Off(pub usize);
///Unsigned file size
pub struct Size(pub u32);
///Unsigned type id
pub struct Type(pub u8);
///Unsigned small int
pub struct Uchar(pub u8);
///Unsigned str offset
pub struct StrOff(pub u32);

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
    pub magic_number: RawArrayType<Uchar>,
    pub create_header: CrateHeader,
    pub string_table: RawArrayType<Uchar>,
    pub section_index: SectionIndex,
    pub data_sections: RawArrayType<DataSection>,
    pub finger_print: RawArrayType<Uchar>,
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

//data sections
//
pub enum DataSection{
    PackageSection(PackageSection),
    DepTableSection(DepTableSection),
    SigStructureSection(SigStructureSection)
}

///package section structure
pub struct PackageSection{
    pub pkg_name: StrOff,
    pub pkg_version: StrOff,
    pub pkg_license: StrOff,
    pub pkg_authors: LenArrayType<StrOff>
}

///Dependency table section structure
pub struct DepTableSection{
    pub dep_name : StrOff,
    pub dep_verreq: StrOff,
    pub dep_srctype: Type,
    pub dep_srcpath: StrOff,
    pub dep_platform: StrOff
}

pub struct CrateBinarySection{
    pub bin: RawArrayType<Uchar>
}

///Signature  section structure
pub struct SigStructureSection{
    sigstruct_size: Size,
    sigstruct_type: Type,
    sigstruct_sig: PKCS7Struct
}


