use std::any::{Any, TypeId};
use std::clone;
use std::mem::size_of;
use bincode;
use bincode::config::{Configuration, Fixint, legacy, LittleEndian, NoLimit};
use bincode::{BorrowDecode, Decode, enc, Encode};
use bincode::de::{Decoder, DecoderImpl};
use bincode::de::read::{Reader, SliceReader};
use bincode::enc::Encoder;
use bincode::enc::write::Writer;
use bincode::error::{DecodeError, EncodeError};
use cms::cert::x509::der;
use cms::cert::x509::der::{Decode as OtherDecode, Encode as OtherEncode};
use cms::signed_data::SignedData;
use cms::cert::x509::der::SliceReader as DerSliceReader;
use crate::utils::package::{DataSection, LenArrayType, PackageSection, PKCS7Struct, RawArrayType, DataSectionCollectionType, Size, StrOff, DepTableSection, DepTableEntry, CrateBinarySection, Uchar, Type, SigStructureSection, CratePackage, SectionIndex, SectionIndexEntry};



pub const BINCODE_CONFIG: Configuration<LittleEndian, Fixint, NoLimit> = legacy();

pub(crate) fn encode_size_by_bincode<T: bincode::enc::Encode>(val: &T) -> usize{
    let mut size_encoder = bincode::enc::EncoderImpl::new(bincode::enc::write::SizeWriter::default(), BINCODE_CONFIG.clone());
    val.encode(&mut size_encoder).unwrap();
    size_encoder.into_writer().bytes_written
}

pub (crate) fn encode2vec_by_bincode<T: bincode::enc::Encode>(val: &T)-> Vec<u8>{
    let mut buffer = vec![0; encode_size_by_bincode(val)];
    let mut encoder = enc::EncoderImpl::new(bincode::enc::write::SliceWriter::new(buffer.as_mut_slice()), BINCODE_CONFIG.clone());
    val.encode(&mut encoder).unwrap();
    buffer
}

pub (crate) fn decode_slice_by_bincode<T: bincode::de::Decode>(bin: &[u8])-> T{
    let (res, _) = bincode::decode_from_slice(bin, BINCODE_CONFIG.clone()).unwrap();
    res
}

pub (crate) fn create_bincode_slice_decoder(bin: &[u8])-> DecoderImpl<SliceReader, Configuration<LittleEndian, Fixint, NoLimit>>{
    DecoderImpl::new(SliceReader::new(bin), BINCODE_CONFIG.clone())
}


//===============custom Encode, Decode===============

//LenArrayType Encode+Decode
impl<T: Encode + 'static> Encode for LenArrayType<T>{
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.len.encode(encoder)?;
        for elem in self.arr.iter(){
            elem.encode(encoder)?;
        }
        Ok(())
    }
}

impl<T: Decode + 'static> Decode for LenArrayType<T>{
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut len_array = LenArrayType::<T>::new();
        len_array.len = bincode::Decode::decode(decoder)?;
        for i in 0..len_array.len.0{
            len_array.arr.push(Decode::decode(decoder)?);
        }
        Ok(len_array)
    }
}

impl<'de, T: BorrowDecode<'de> + 'static> BorrowDecode<'de> for LenArrayType<T>{
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut len_array = LenArrayType::<T>::new();
        len_array.len = bincode::BorrowDecode::borrow_decode(decoder)?;
        for i in 0..len_array.len.0{
            len_array.arr.push(bincode::BorrowDecode::borrow_decode(decoder)?);
        }
        Ok(len_array)
    }
}

//RawArray Encode
impl<T: Encode + 'static> Encode for RawArrayType<T>{
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        if TypeId::of::<u8>() == TypeId::of::<T>() || TypeId::of::<Uchar>() == TypeId::of::<T>() || TypeId::of::<Type>() == TypeId::of::<T>(){
            let vec_u8: Vec<u8> = unsafe{Vec::from_raw_parts(self.arr.as_ptr() as *mut u8, self.arr.len() * 8, self.arr.len() * 8)};
            encoder.writer().write(vec_u8.as_slice()).unwrap();
            return Ok(())
        }
        for elem in self.arr.iter(){
            elem.encode(encoder)?
        }
        Ok(())
    }
}

///RawArray Decode
impl<T: Decode + 'static> RawArrayType<T>{
    pub fn decode<D: Decoder>(decoder: &mut D, elem_num:usize) -> Result<Self, DecodeError> {
        if TypeId::of::<u8>() == TypeId::of::<T>() || TypeId::of::<Uchar>() == TypeId::of::<T>() || TypeId::of::<Type>() == TypeId::of::<T>(){
            let mut buf = vec![0 as u8; 8 * elem_num];
            decoder.reader().read(buf.as_mut_slice()).unwrap();
            let vec_t: Vec<T> = unsafe{Vec::from_raw_parts(buf.as_ptr() as *mut T, buf.len() * 8, buf.len() * 8)};
            return Ok(RawArrayType::from_vec(vec_t));
        }
        let mut raw_array = RawArrayType::<T>::new();
        for i in 0..elem_num{
            raw_array.arr.push(Decode::decode(decoder)?);
        }
        Ok(raw_array)
    }
}

#[test]
fn test_RawArrayType(){
    let a= RawArrayType::<i8>{arr: [1,2,3].to_vec()};
    let encode_vec = encode2vec_by_bincode(&a);
    println!("{:?}", encode_vec);
    let mut decoder = create_bincode_slice_decoder(encode_vec.as_slice());
    let raw_array = RawArrayType::<i8>::decode(&mut decoder, 3).unwrap();
    // let decode = RawArrayType<T>::
    println!("{:?}", raw_array);
}


//PKCS7Struct Encode
impl Encode for PKCS7Struct{
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        let mut vec= vec![];
        let size = self.cms.encode_to_vec(&mut vec).unwrap();
        encoder.writer().write(vec.as_slice()).unwrap();
        Ok(())
    }
}


//datasection Encode
impl Encode for DataSection{
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match &self{
            DataSection::PackageSection(x) =>{x.encode(encoder)?}
            DataSection::DepTableSection(x) =>{x.encode(encoder)?}
            DataSection::CrateBinarySection(x) =>{x.encode(encoder)?}
            DataSection::SigStructureSection(x) =>{x.encode(encoder)?}
            _ => {panic!("section type error")}
        }
        Ok(())
    }
}


impl Decode for SigStructureSection{
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let sigstruct_size:Size = Decode::decode(decoder)?;
        let sigstruct_type:Type = Decode::decode(decoder)?;
        let sigstruct_sig:PKCS7Struct = PKCS7Struct::decode(decoder, sigstruct_size.0.clone() as usize)?;
        Ok(Self{
            sigstruct_size,
            sigstruct_type,
            sigstruct_sig
        })
    }
}
// non-self decode

impl CratePackage{
    pub fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError>{
        todo!()
    }
}

///SectionIndex Decode
impl SectionIndex{
    pub fn decode<D: Decoder>(decoder: &mut D, elem_num:usize) -> Result<Self, DecodeError>{
        Ok(Self{
            entries: RawArrayType::<SectionIndexEntry>::decode(decoder, elem_num)?
        })
    }
}

///RawCollection Decode
impl DataSectionCollectionType{
    pub fn decode<D: Decoder>(decoder: &mut D, enum_size_in_bytes:Vec<(i32, usize)>) -> Result<Self, DecodeError> {
        let mut raw_col = DataSectionCollectionType::new();
        for (type_id, size) in enum_size_in_bytes.into_iter(){
            match type_id{
                0 => {
                    let pack_sec:PackageSection = Decode::decode(decoder)?;
                    raw_col.col.arr.push(DataSection::PackageSection(pack_sec));
                }
                1 => {
                    let dep_table:DepTableSection = Decode::decode(decoder)?;
                    raw_col.col.arr.push(DataSection::DepTableSection(dep_table));
                }
                3 => {
                    let crate_binary:CrateBinarySection = CrateBinarySection::decode(decoder, size)?;
                    raw_col.col.arr.push(DataSection::CrateBinarySection(crate_binary));
                }
                4 => {
                    let sig_structure:SigStructureSection = Decode::decode(decoder)?;
                    raw_col.col.arr.push(DataSection::SigStructureSection(sig_structure));
                }
                _ => {panic!("unkown datasection type_id")}
            }
        }
        Ok(raw_col)
    }
}


//CrateBinarySection decode
impl CrateBinarySection{
    pub fn decode<D: Decoder>(decoder: &mut D, size_in_bytes:usize) -> Result<Self, DecodeError> {
        let mut dep_table = CrateBinarySection::new();
        dep_table.bin = RawArrayType::<Uchar>::decode(decoder, size_in_bytes)?;
        Ok(dep_table)
    }
}

//PKCS7Struct decode
impl PKCS7Struct{
    fn decode<D: Decoder>(decoder: &mut D, size_in_bytes:usize) -> Result<Self, DecodeError> {
        let mut der_reader = der::SliceReader::new(decoder.reader().peek_read(size_in_bytes).unwrap()).unwrap();
        let cms = SignedData::decode(&mut der_reader).unwrap();
        decoder.reader().consume(size_in_bytes);
        Ok(Self{
            cms
        })
    }
}
