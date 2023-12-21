use bincode;
use bincode::config::{legacy, Configuration, Fixint, LittleEndian, NoLimit};
use bincode::de::read::{Reader, SliceReader};
use bincode::de::{Decoder, DecoderImpl};
use bincode::enc::Encoder;
use bincode::{enc, BorrowDecode, Decode, Encode};

use bincode::error::{DecodeError, EncodeError};

use crate::utils::package::{
    CrateBinarySection, CrateHeader, CratePackage, DataSection, DataSectionCollectionType,
    DepTableSection, FingerPrintType, LenArrayType, MagicNumberType, PackageSection, RawArrayType,
    SectionIndex, SectionIndexEntry, SigStructureSection, Size, Type, Uchar, FINGERPRINT_LEN,
    MAGIC_NUMBER,
};

pub const BINCODE_CONFIG: Configuration<LittleEndian, Fixint, NoLimit> = legacy();

pub fn encode_size_by_bincode<T: enc::Encode>(val: &T) -> usize {
    let mut size_encoder = enc::EncoderImpl::new(enc::write::SizeWriter::default(), BINCODE_CONFIG);
    val.encode(&mut size_encoder).unwrap();
    size_encoder.into_writer().bytes_written
}

pub fn encode2vec_by_bincode<T: enc::Encode>(val: &T) -> Vec<u8> {
    let mut buffer = vec![0; encode_size_by_bincode(val)];
    let mut encoder = enc::EncoderImpl::new(
        enc::write::SliceWriter::new(buffer.as_mut_slice()),
        BINCODE_CONFIG,
    );
    val.encode(&mut encoder).unwrap();
    buffer
}

pub fn decode_slice_by_bincode<T: bincode::de::Decode>(bin: &[u8]) -> T {
    let (res, _) = bincode::decode_from_slice(bin, BINCODE_CONFIG).unwrap();
    res
}

pub fn create_bincode_slice_decoder(
    bin: &[u8],
) -> DecoderImpl<SliceReader, Configuration<LittleEndian, Fixint, NoLimit>> {
    DecoderImpl::new(SliceReader::new(bin), BINCODE_CONFIG)
}

//===============custom Encode, Decode===============

//LenArrayType Encode+Decode
impl<T: Encode + 'static> Encode for LenArrayType<T> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        Encode::encode(&self.len, encoder)?;
        for elem in self.arr.iter() {
            elem.encode(encoder)?;
        }
        Ok(())
    }
}

impl<T: Decode + 'static> Decode for LenArrayType<T> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut len_array = LenArrayType::<T>::new();
        len_array.len = bincode::Decode::decode(decoder)?;
        for _i in 0..len_array.len {
            len_array.arr.push(Decode::decode(decoder)?);
        }
        Ok(len_array)
    }
}

impl<'de, T: BorrowDecode<'de> + 'static> BorrowDecode<'de> for LenArrayType<T> {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let mut len_array = LenArrayType::<T>::new();
        len_array.len = bincode::BorrowDecode::borrow_decode(decoder)?;
        for _i in 0..len_array.len {
            len_array.arr.push(BorrowDecode::borrow_decode(decoder)?);
        }
        Ok(len_array)
    }
}

//RawArray Encode
impl<T: Encode + 'static> Encode for RawArrayType<T> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        //TODO FIXME!!!
        // if TypeId::of::<u8>() == TypeId::of::<T>() || TypeId::of::<Uchar>() == TypeId::of::<T>() || TypeId::of::<Type>() == TypeId::of::<T>(){
        //     let vec_u8: &[u8] = unsafe { core::mem::transmute(self.arr.as_slice())};
        //     encoder.writer().write(vec_u8).unwrap();
        //     return Ok(())
        // }
        for elem in self.arr.iter() {
            elem.encode(encoder)?
        }
        Ok(())
    }
}

///RawArray Decode
impl<T: Decode + 'static> RawArrayType<T> {
    pub fn decode<D: Decoder>(decoder: &mut D, elem_num: usize) -> Result<Self, DecodeError> {
        //TODO FIXME
        // if TypeId::of::<u8>() == TypeId::of::<T>() || TypeId::of::<Uchar>() == TypeId::of::<T>() || TypeId::of::<Type>() == TypeId::of::<T>(){
        //     let mut buf = vec![0 as u8; 8 * elem_num];
        //     decoder.reader().read(buf.as_mut_slice()).unwrap();
        //     let vec_t: Vec<T> = unsafe{Vec::from_raw_parts(buf.as_ptr() as *mut T, buf.len(), buf.len())};
        //     return Ok(RawArrayType::from_vec(vec_t));
        // }
        let mut raw_array = RawArrayType::<T>::new();
        for _i in 0..elem_num {
            raw_array.arr.push(Decode::decode(decoder)?);
        }
        Ok(raw_array)
    }
}

#[test]
fn test_raw_array_type() {
    let a = RawArrayType::<i8> {
        arr: [1, 2, 3].to_vec(),
    };
    let encode_vec = encode2vec_by_bincode(&a);
    println!("{:?}", encode_vec);
    let mut decoder = create_bincode_slice_decoder(encode_vec.as_slice());
    let raw_array = RawArrayType::<i8>::decode(&mut decoder, 3).unwrap();
    // let decode = RawArrayType<T>::
    println!("{:?}", raw_array);
}

// //PKCS7Struct Encode
// impl Encode for PKCS7Struct{
//     fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
//         let mut vec= vec![];
//         let _size = self.cms.encode_to_vec(&mut vec).unwrap();
//         encoder.writer().write(vec.as_slice()).unwrap();
//         Ok(())
//     }
// }

//datasection Encode
impl Encode for DataSection {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match &self {
            DataSection::PackageSection(x) => x.encode(encoder)?,
            DataSection::DepTableSection(x) => x.encode(encoder)?,
            DataSection::CrateBinarySection(x) => x.encode(encoder)?,
            DataSection::SigStructureSection(x) => x.encode(encoder)?, //_ => {panic!("section type error")}
        }
        Ok(())
    }
}

impl Decode for SigStructureSection {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let sigstruct_size: Size = Decode::decode(decoder)?;
        let sigstruct_type: Type = Decode::decode(decoder)?;
        let sigstruct_sig = RawArrayType::<u8>::decode(decoder, sigstruct_size as usize)?;
        //let sigstruct_sig:PKCS7Struct = PKCS7Struct::decode(decoder, sigstruct_size as usize)?;
        Ok(Self {
            sigstruct_size,
            sigstruct_type,
            sigstruct_sig,
        })
    }
}
// non-self decode

fn is_magic_number(mn: &MagicNumberType) -> bool {
    for i in 0..MAGIC_NUMBER.len() {
        if mn[i] != MAGIC_NUMBER[i] {
            return false;
        }
    }
    true
}

macro_rules! early_return {
    ($condition:expr, $value:expr) => {
        if !$condition {
            return Err(DecodeError::Other($value));
        }
    };
}

impl CratePackage {
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode2vec_by_bincode(self)
    }

    pub fn decode_from_slice(bin: &[u8]) -> Result<CratePackage, String> {
        return match Self::decode(&mut create_bincode_slice_decoder(bin), bin) {
            Ok(t) => Ok(t),
            Err(DecodeError::Other(s)) => Err(s.to_string()),
            Err(_) => Err("file format not right! - others".to_string()),
        };
    }

    pub fn decode<D: Decoder>(decoder: &mut D, bin: &[u8]) -> Result<Self, DecodeError> {
        let magic_number: MagicNumberType = Decode::decode(decoder).unwrap();
        if !is_magic_number(&magic_number) {
            return Err(DecodeError::Other("magic not right!"));
        }

        let crate_header: CrateHeader = Decode::decode(decoder)?;

        early_return!(
            bin.len() > (crate_header.strtable_size + crate_header.strtable_offset) as usize,
            "file format not right! - strtable"
        );
        let string_table_bin = &bin[crate_header.strtable_offset as usize
            ..(crate_header.strtable_size + crate_header.strtable_offset) as usize];
        let string_table: RawArrayType<Uchar> = RawArrayType::<Uchar>::decode(
            &mut create_bincode_slice_decoder(string_table_bin),
            string_table_bin.len(),
        )?;

        early_return!(
            bin.len() > (crate_header.si_offset + crate_header.si_size) as usize,
            "file format not right! - si"
        );
        let section_index_bin = &bin[crate_header.si_offset as usize
            ..(crate_header.si_offset + crate_header.si_size) as usize];
        let section_index: SectionIndex = SectionIndex::decode(
            &mut create_bincode_slice_decoder(section_index_bin),
            crate_header.si_num as usize,
        )?;

        let mut enum_size_off_in_bytes = vec![];
        section_index.entries.arr.iter().for_each(|index_entry| {
            enum_size_off_in_bytes.push((
                index_entry.sh_type as i32,
                index_entry.sh_size as usize,
                index_entry.sh_offset as usize,
            ))
        });

        early_return!(
            bin.len() > crate_header.ds_offset as usize,
            "file format not right! - ds"
        );
        let datasections_bin = &bin[crate_header.ds_offset as usize..];
        let data_sections = DataSectionCollectionType::decode(
            &mut create_bincode_slice_decoder(datasections_bin),
            enum_size_off_in_bytes,
        )?;

        early_return!(
            bin[bin.len() - FINGERPRINT_LEN..].len() == FINGERPRINT_LEN,
            "file format not right! - fingerprint"
        );
        let fingerprint_bin = &bin[bin.len() - FINGERPRINT_LEN..];
        let finger_print: FingerPrintType =
            Decode::decode(&mut create_bincode_slice_decoder(fingerprint_bin))?;

        Ok(Self {
            magic_number,
            crate_header,
            string_table,
            section_index,
            data_sections,
            finger_print,
        })
    }
}

///SectionIndex Decode
impl SectionIndex {
    pub fn decode<D: Decoder>(decoder: &mut D, elem_num: usize) -> Result<Self, DecodeError> {
        Ok(Self {
            entries: RawArrayType::<SectionIndexEntry>::decode(decoder, elem_num)?,
        })
    }
}

///RawCollection Decode
impl DataSectionCollectionType {
    pub fn decode<D: Decoder>(
        decoder: &mut D,
        enum_size_offset_in_bytes: Vec<(i32, usize, usize)>,
    ) -> Result<Self, DecodeError> {
        let mut raw_col = DataSectionCollectionType::new();
        let mut consume_size = 0;
        for (type_id, size, offset) in enum_size_offset_in_bytes.into_iter() {
            if consume_size > offset {
                return Err(DecodeError::Other("file format not right!"));
            }
            if consume_size < offset {
                decoder.reader().consume(offset - consume_size);
                consume_size = offset;
            }
            match type_id {
                0 => {
                    let pack_sec: PackageSection = Decode::decode(decoder)?;
                    raw_col.col.arr.push(DataSection::PackageSection(pack_sec));
                }
                1 => {
                    let dep_table: DepTableSection = Decode::decode(decoder)?;
                    raw_col
                        .col
                        .arr
                        .push(DataSection::DepTableSection(dep_table));
                }
                3 => {
                    let crate_binary: CrateBinarySection =
                        CrateBinarySection::decode(decoder, size)?;
                    raw_col
                        .col
                        .arr
                        .push(DataSection::CrateBinarySection(crate_binary));
                }
                4 => {
                    let sig_structure: SigStructureSection = Decode::decode(decoder)?;
                    raw_col
                        .col
                        .arr
                        .push(DataSection::SigStructureSection(sig_structure));
                }
                _ => return Err(DecodeError::Other("file format not right!")),
            }
            consume_size += size;
        }
        Ok(raw_col)
    }

    pub fn encode_size_offset(&self) -> Vec<(usize, usize)> {
        let mut v = vec![];
        let mut offset: usize = 0;
        self.col.arr.iter().for_each(|x| {
            let size = encode_size_by_bincode(x);
            v.push((size, offset));
            offset += size;
        });
        v
    }

    pub fn encode_fake_to_vec(&self, trunc_len: usize) -> Vec<u8> {
        let mut buf = encode2vec_by_bincode(self);
        buf.truncate(trunc_len);
        buf
    }
}

//CrateBinarySection decode
impl CrateBinarySection {
    pub fn decode<D: Decoder>(decoder: &mut D, size_in_bytes: usize) -> Result<Self, DecodeError> {
        let mut dep_table = CrateBinarySection::new();
        dep_table.bin = RawArrayType::<Uchar>::decode(decoder, size_in_bytes)?;
        Ok(dep_table)
    }
}

//PKCS7Struct decode
// impl PKCS7Struct{
//     fn decode<D: Decoder>(decoder: &mut D, size_in_bytes:usize) -> Result<Self, DecodeError> {
//         let mut der_reader = der::SliceReader::new(decoder.reader().peek_read(size_in_bytes).unwrap()).unwrap();
//         let cms = SignedData::decode(&mut der_reader).unwrap();
//         decoder.reader().consume(size_in_bytes);
//         Ok(Self{
//             cms
//         })
//     }
// }

//get_size
impl CrateHeader {
    pub fn size(&self) -> usize {
        encode_size_by_bincode(self)
    }
}

impl<T: Encode + 'static> RawArrayType<T> {
    pub fn size(&self) -> usize {
        encode_size_by_bincode(self)
    }
}

impl SectionIndex {
    pub fn size(&self) -> usize {
        encode_size_by_bincode(self)
    }

    pub fn num(&self) -> usize {
        self.entries.arr.len()
    }

    pub fn none_sig_size(&self) -> usize {
        let mut total_len = 0;
        self.entries.arr.iter().for_each(|x| {
            if x.sh_type != 4 {
                total_len += x.size();
            }
        });
        total_len
    }

    pub fn none_sig_num(&self) -> usize {
        let mut total_len = 0;
        self.entries.arr.iter().for_each(|x| {
            if x.sh_type != 4 {
                total_len += 1;
            }
        });
        total_len
    }

    pub fn sig_num(&self) -> usize {
        self.num() - self.none_sig_num()
    }

    pub fn sig_size(&self) -> usize {
        self.size() - self.none_sig_size()
    }

    pub fn encode_fake_to_vec(&self, no_sig_size: usize, size: usize) -> Vec<u8> {
        let mut buf = encode2vec_by_bincode(self);
        buf.truncate(no_sig_size);
        buf.extend(vec![0; size - no_sig_size]);
        buf
    }

    pub fn datasection_size_without_sig(&self) -> usize {
        (self.entries.arr[self.none_sig_num() - 1].sh_offset
            + self.entries.arr[self.none_sig_num() - 1].sh_size) as usize
    }
}

impl DataSectionCollectionType {
    pub fn size(&self) -> usize {
        encode_size_by_bincode(self)
    }
}

impl PackageSection {
    pub fn size(&self) -> usize {
        encode_size_by_bincode(self)
    }
}

impl DepTableSection {
    pub fn size(&self) -> usize {
        encode_size_by_bincode(self)
    }
}

impl CrateBinarySection {
    pub fn size(&self) -> usize {
        encode_size_by_bincode(self)
    }
}

impl SigStructureSection {
    pub fn size(&self) -> usize {
        encode_size_by_bincode(self)
    }
}

impl SectionIndexEntry {
    pub fn size(&self) -> usize {
        encode_size_by_bincode(self)
    }
}
