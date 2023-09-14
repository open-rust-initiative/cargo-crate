use openssl::pkcs7::Pkcs7;
use openssl::pkcs7::Pkcs7Flags;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;
#[test]
fn test_pkcs(){
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let certs = Stack::new().unwrap();
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
    pkcs7_decoded
        .verify(&certs, &store, None, Some(&mut output), flags)
        .expect("should succeed");

    assert_eq!(output, message.as_bytes());
    assert!(content.is_none());
}