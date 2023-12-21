use bincode;
use bincode::enc;
use std::io::{BufRead, Write};
use std::mem::size_of;
use std::vec;

use crate::utils::package::gen_bincode::{create_bincode_slice_decoder, encode2vec_by_bincode};
use crate::utils::package::*;

pub trait Encode {
    fn encode(&self) -> Vec<u8>;
    fn encode_to_vec(&self) -> Vec<u8> {
        self.encode()
    }
    fn encode_to_writer<W: Write>(&self, writer: &mut W) -> usize {
        writer.write(&self.encode()).unwrap()
    }
}

pub trait Decode {
    type Output;
    fn decode(bin: &[u8]) -> Self::Output;
    fn decode_from_vec(bin: &Vec<u8>) -> Self::Output {
        Self::decode(bin.as_slice())
    }
    fn decode_from_slice(bin: &[u8]) -> Self::Output {
        Self::decode(bin)
    }
    fn decode_from_reader<W: BufRead>(reader: &mut W, size: usize) -> Self::Output {
        let mut buf = vec![0u8; size];
        reader.read_exact(buf.as_mut_slice()).unwrap();
        Self::decode(buf.as_mut_slice())
    }
}

impl<T: enc::Encode + 'static> Encode for RawArrayType<T> {
    fn encode(&self) -> Vec<u8> {
        encode2vec_by_bincode(self)
    }
}

impl<T: enc::Encode + 'static + bincode::de::Decode> Decode for RawArrayType<T> {
    type Output = RawArrayType<T>;
    fn decode(bin: &[u8]) -> Self::Output {
        let mut decoder = create_bincode_slice_decoder(bin);
        let mut output = RawArrayType::new();
        let len = bin.len() / size_of::<T>();
        for _i in 0..len {
            output
                .arr
                .push(bincode::Decode::decode(&mut decoder).unwrap());
        }
        output
    }
}
