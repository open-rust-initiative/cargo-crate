use std::fmt::{Debug, Formatter};
use std::fs;
use std::path::Path;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkcs7::Pkcs7;
use openssl::pkcs7::Pkcs7Flags;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;



pub struct PKCS{
    cert_bin: Vec<u8>,
    pkey_bin: Vec<u8>,
    root_ca_bins: Vec<Vec<u8>>
}

impl Debug for PKCS{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("")
    }
}

impl PKCS{
    pub fn new()->Self{
        Self{
            cert_bin: vec![],
            pkey_bin: vec![],
            root_ca_bins: vec![],
        }
    }
    pub fn get_root_ca_bins(ca_paths: Vec<String>)->Vec<Vec<u8>>{
        let mut root_ca_bins = vec![];
        for ca_path in ca_paths{
            root_ca_bins.push(fs::read(Path::new(ca_path.as_str())).unwrap());
        }
        root_ca_bins
    }

    pub fn load_from_file_writer(&mut self, cert_path: String, pkey_path: String, ca_paths: Vec<String>){
        //just for demo
        self.cert_bin = fs::read(Path::new(cert_path.as_str())).unwrap();
        self.pkey_bin = fs::read(Path::new(pkey_path.as_str())).unwrap();
        for ca_path in ca_paths{
            self.root_ca_bins.push(fs::read(Path::new(ca_path.as_str())).unwrap());
        }
    }

    pub fn load_from_file_reader(&mut self,  ca_paths: Vec<String>){
        //just for demo
        for ca_path in ca_paths{
            self.root_ca_bins.push(fs::read(Path::new(ca_path.as_str())).unwrap());
        }
    }

    pub fn encode_pkcs_bin(&self, message:&[u8])->Vec<u8>{
        //FIXME current we don't support middle certs
        let cert = X509::from_pem(self.cert_bin.as_slice()).unwrap();
        let certs = Stack::new().unwrap();
        let flags = Pkcs7Flags::STREAM;
        let pkey = PKey::private_key_from_pem(self.pkey_bin.as_slice()).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        for root_ca_bin in self.root_ca_bins.iter() {
            let root_ca = X509::from_pem(root_ca_bin.as_slice()).unwrap();
            store_builder.add_cert(root_ca).expect("should succeed");
        }

        let store = store_builder.build();

        let pkcs7 =
            Pkcs7::sign(&cert, &pkey, &certs, message, flags).expect("should succeed");

        let signed = pkcs7
            .to_smime(message, flags)
            .expect("should succeed");
        signed
    }

    pub fn decode_pkcs_bin(signed_bin:&[u8], root_ca_bins: &Vec<Vec<u8>>)->Vec<u8>{
        //FIXME maybe all pkcs section should share same root cas
        let certs = Stack::new().unwrap();
        let flags = Pkcs7Flags::STREAM;
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        for root_ca_bin in root_ca_bins.iter() {
            let root_ca = X509::from_pem(root_ca_bin.as_slice()).unwrap();
            store_builder.add_cert(root_ca).expect("should succeed");
        }

        let store = store_builder.build();

        let (pkcs7_decoded, content) =
            Pkcs7::from_smime(signed_bin).expect("should succeed");

        let mut output = Vec::new();
        pkcs7_decoded
            .verify(&certs, &store, None, Some(&mut output), flags)
            .expect("should succeed");
        output
    }

    pub fn gen_digest_256(&self, bin:&[u8])->Vec<u8>{
        let res = hash(MessageDigest::sha256(), bin).unwrap();
        res.to_vec()
    }
}

#[test]
fn test_PKCS(){
    let mut pkcs = PKCS::new();
    pkcs.load_from_file_writer("test/cert.pem".to_string(), "test/key.pem".to_string(), ["test/root-ca.pem".to_string()].to_vec());
    let bin = "Hello rust!".to_string();
    let digest = pkcs.gen_digest_256(bin.as_bytes());
    let signedData = pkcs.encode_pkcs_bin(digest.as_slice());
    // let digest_de = pkcs.decode_pkcs_bin(signedData.as_slice());
    // assert_eq!(digest, digest_de);
}

#[test]
fn test_pkcs7(){
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let mut certs = Stack::new().unwrap();
    certs.push(X509::from_pem(include_bytes!("../../test/cert1.pem")).unwrap()).unwrap();

    let message = "foo";
    let flags = Pkcs7Flags::STREAM;
    let pkey = include_bytes!("../../test/key.pem");
    let pkey = PKey::private_key_from_pem(pkey).unwrap();
    let mut store_builder = X509StoreBuilder::new().expect("should succeed");

    let root_ca = include_bytes!("../../test/root-ca.pem");
    let root_ca = X509::from_pem(root_ca).unwrap();
    store_builder.add_cert(root_ca).expect("should succeed");

    let store = store_builder.build();

    let pkcs7 =
        Pkcs7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

    let signed = pkcs7
        .to_smime(message.as_bytes(), flags)
        .expect("should succeed");

    let (pkcs7_decoded, content) =
        Pkcs7::from_smime(signed.as_slice()).expect("should succeed");

    let mut output = Vec::new();
    let certs = Stack::new().unwrap();

    let mut store_builder = X509StoreBuilder::new().expect("should succeed");
    let root_ca = include_bytes!("../../test/cert1.pem");
    let root_ca = X509::from_pem(root_ca).unwrap();
    let root_ca = include_bytes!("../../test/root-ca.pem");
    let root_ca = X509::from_pem(root_ca).unwrap();
    store_builder.add_cert(root_ca).expect("should succeed");
    let store = store_builder.build();

    pkcs7_decoded
        .verify(&certs, &store, None, Some(&mut output), flags)
        .expect("should succeed");

    assert_eq!(output, message.as_bytes());
    assert!(content.is_none());
}

#[test]
fn test_hash() -> Result<(), Box<dyn std::error::Error>> {
    use openssl::hash::{hash, MessageDigest};

    let data = b"\x42\xF4\x97\xE0";
    //let spec = b"\x7c\x43\x0f\x17\x8a\xef\xdf\x14\x87\xfe\xe7\x14\x4e\x96\x41\xe2";
    let res = hash(MessageDigest::sha256(), data)?;
    println!("{:?}", &*res);
    //assert_eq!(&*res, spec);
    Ok(())
}