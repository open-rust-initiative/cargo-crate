use std::clone;
use std::mem::size_of;
use bincode;
use bincode::config::{Configuration, Fixint, legacy, LittleEndian, NoLimit};
use bincode::{BorrowDecode, Decode, enc, Encode};
use bincode::de::{Decoder, DecoderImpl};
use bincode::de::read::SliceReader;
use bincode::enc::Encoder;
use bincode::enc::write::Writer;
use bincode::error::{DecodeError, EncodeError};
use cms::cert::x509::der::Encode as OtherEncode;
use crate::utils::package::{DataSection, LenArrayType, PKCS7Struct, RawArrayType, Size};

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
        for elem in self.arr.iter(){
            elem.encode(encoder)?
        }
        Ok(())
    }
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
            DataSection::SigStructureSection(x) =>{x.encode(encoder)?}
            _ => {panic!("section type error")}
        }
        Ok(())
    }
}

