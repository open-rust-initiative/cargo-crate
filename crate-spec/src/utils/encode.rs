use openssl::asn1::{Asn1Object, Asn1Time};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::stack::Stack;
use openssl::cms::CmsContentInfo;
use openssl::x509::{X509, X509Builder, X509Name};
use crate::utils::context::{BinaryLayout, CrateBinary, PackageContext, StringTable};
use crate::utils::package::{CrateBinarySection, CrateHeader, CratePackage, CRATEVERSION, DataSection, DataSectionCollectionType, DepTableSection, FINGERPRINT_LEN, get_datasection_type, MAGIC_NUMBER, Off, PackageSection, RawArrayType, SectionIndex, SectionIndexEntry, Size};
use crate::utils::package::bin::Encode;
use crate::utils::package::gen_bincode::encode2vec_by_bincode;


pub fn write_pack_context_to_data_section(pack_context: &PackageContext, str_table: &mut StringTable,  crate_package: &mut CratePackage){
    let mut si = SectionIndex::new();
    let mut offset = 0;
    let mut size = 0;
    let mut ds = DataSectionCollectionType::new();

    let mut package_section = PackageSection::new();
    pack_context.write_to_package_section(&mut package_section, str_table);
    size = package_section.get_size() as Size;
    si.entries.arr.push(SectionIndexEntry::new(0, offset, size));
    offset += size;
    ds.col.arr.push(DataSection::PackageSection(package_section));


    let mut dep_table_section = DepTableSection::new();
    pack_context.write_to_dep_table_section(&mut dep_table_section, str_table);
    size = dep_table_section.get_size() as Size;
    si.entries.arr.push(SectionIndexEntry::new(1, offset, size));
    offset += size;
    ds.col.arr.push(DataSection::DepTableSection(dep_table_section));

    let mut binary_section = CrateBinarySection::new();
    pack_context.write_to_crate_binary_section(&mut binary_section);
    size = binary_section.get_size() as Size;
    si.entries.arr.push(SectionIndexEntry::new(3, offset, size));
    offset += size;
    ds.col.arr.push(DataSection::CrateBinarySection(binary_section));

    crate_package.data_sections = ds;
    crate_package.section_index = si;
}


pub fn write_sig_to_crate_package(crate_package: &mut CratePackage){
    //SigStructureSection
}

pub fn write_crate_header_to_crate_package(crate_package: &mut CratePackage, sig_num:usize){
    let mut crate_header = CrateHeader::new();
    crate_header.c_version = CRATEVERSION;

    let mut offset = (crate_package.magic_number.len() + crate_header.get_size()) as Size;
    crate_header.strtable_offset = offset;
    crate_header.strtable_size = crate_package.string_table.get_size() as Size;

    offset += crate_header.strtable_size;
    crate_header.si_offset = offset;
    crate_header.si_size = crate_package.section_index.get_size() as Size;
    crate_header.si_num = crate_package.section_index.section_num();
    crate_header.si_not_sig_size = sig_num as Size;
}

pub fn write_to_crate_package_first(pack_context: &PackageContext, str_table: &mut StringTable,  crate_package: &mut CratePackage, sig_num: usize)->Vec<u8>{
    crate_package.magic_number = MAGIC_NUMBER;
    crate_package.string_table = RawArrayType::from_vec(str_table.to_bytes());
    write_pack_context_to_data_section(pack_context, str_table, crate_package);

    //fake sigStructure index
    for i in 0..sig_num{
        crate_package.section_index.entries.arr.push(SectionIndexEntry::new(0, 0, 0));
    }
    //write_crate_header_to_crate_package(crate_package);
    let mut bin = encode2vec_by_bincode(crate_package);

    //pop fake sigstructure index
    for i in 0..sig_num{
        crate_package.section_index.entries.arr.pop();
    }
    bin
}

// pub fn write_to_crate_package_second(pack_context: &PackageContext, str_table: &mut StringTable,  crate_package: &mut CratePackage, sig_num: usize)->Vec<u8>{
// }


pub fn set_section_index(crate_package: &mut CratePackage){
    for (i, (_size, _off)) in crate_package.data_sections.encode_size_offset().iter().enumerate(){
        let size = *_size;
        let off = *_off;
        let typ = get_datasection_type(&crate_package.data_sections.col.arr[i]);
        crate_package.section_index.entries.arr.push(SectionIndexEntry::new(typ, off as Off, size as Size));
    }
}

pub fn set_string_table(crate_package: &mut CratePackage, str_table: & StringTable){
    crate_package.string_table = RawArrayType::from_vec(str_table.to_bytes());
}

pub fn set_data_sections_without_sig(pack_context: &PackageContext, crate_package: &mut CratePackage, str_table: &mut StringTable){
    pack_context.write_to_data_section_collection(&mut crate_package.data_sections, str_table);
}

pub fn set_crate_header(crate_package:&mut CratePackage, fake_num: usize){
    crate_package.crate_header.c_version = CRATEVERSION;
    crate_package.crate_header.strtable_size = crate_package.string_table.get_size() as Size;
    crate_package.crate_header.strtable_offset = (crate_package.crate_header.get_size() + crate_package.magic_number.len()) as Size;
    crate_package.crate_header.si_not_sig_size = crate_package.section_index.get_none_sig_size() as Size;
    crate_package.crate_header.si_not_sig_num = crate_package.section_index.get_none_sig_num() as Size;
    crate_package.crate_header.si_size = crate_package.section_index.get_size() as Size + (fake_num * SectionIndexEntry::default().get_size()) as Size;
    crate_package.crate_header.si_num = crate_package.section_index.get_num() as Size + fake_num as Size;
    crate_package.crate_header.si_offset = crate_package.crate_header.strtable_offset + crate_package.crate_header.strtable_size;
    crate_package.crate_header.ds_offset = crate_package.crate_header.si_offset + crate_package.crate_header.si_size;
}

pub fn set_magic_numer(crate_package:&mut CratePackage){
    crate_package.magic_number = MAGIC_NUMBER;
}

pub fn set_finger_print(crate_package: &mut CratePackage, fp: Vec<u8>){
    crate_package.finger_print.copy_from_slice(fp.as_slice());
}

pub fn get_binary_before_sig(crate_packge: &mut CratePackage)->Vec<u8>{
    let mut buf = vec![];
    buf.extend(encode2vec_by_bincode(&crate_packge.magic_number));
    buf.extend(encode2vec_by_bincode(&crate_packge.string_table));
    buf.extend(crate_packge.section_index.encode_fake_to_vec(crate_packge.crate_header.si_not_sig_size as usize, crate_packge.crate_header.si_size as usize));
    buf.extend(crate_packge.data_sections.encode_fake_to_vec(crate_packge.section_index.fake_datasection_size(crate_packge.crate_header.si_not_sig_num)));
    buf
}

pub fn encode_to_crate_package_before_sig(pack_context: &PackageContext, str_table: &mut StringTable,  crate_package: &mut CratePackage, binary_layout: &mut BinaryLayout, sig_num: usize){
    set_magic_numer(crate_package);
    set_string_table(crate_package, str_table);
    set_data_sections_without_sig(pack_context, crate_package, str_table);
    set_crate_header(crate_package, sig_num);
}

pub fn encode_sig_to_crate_package(crate_package:& mut CratePackage){

}

pub fn encode_to_crate_package_after_sig(crate_package: &mut CratePackage){
    set_crate_header(crate_package, 0);
}


#[test]
fn test() {
    // 你的原始数据
    let data: Vec<u8> = b"Hello, world!".to_vec();

    // 创建一个 RSA 密钥对用于签名
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = PKey::from_rsa(rsa.clone()).unwrap();

    // 创建一个自签名的 X.509 证书
    let mut x509_name = X509Name::builder().unwrap();
    x509_name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "Self-Signed Cert").unwrap();
    let x509_name = x509_name.build();

    let mut x509_builder = X509::builder().unwrap();
    x509_builder.set_version(2).unwrap();
    x509_builder.set_subject_name(&x509_name).unwrap();
    x509_builder.set_issuer_name(&x509_name).unwrap();
    x509_builder.set_pubkey(&private_key).unwrap();
    x509_builder.sign(&private_key, openssl::hash::MessageDigest::sha256()).unwrap();
    let certificate = x509_builder.build();

    // 对数据进行签名
    let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &private_key).unwrap();
    let signature = signer.sign_oneshot_to_vec(&data).unwrap();

    // 创建 CMS SignedData 结构
    let mut signed_data = CmsSignedData::new().unwrap();

    // 设置原始数据
    signed_data.set_content_type(CmsContentType::Data).unwrap();
    signed_data.set_content(&data).unwrap();

    // 添加签名者信息
    let mut signer_info = Vec::new();
    // 这里你需要手动构建签名者信息结构，请根据 ASN.1 格式创建签名者信息
    // 这里只是一个示例，实际上需要更复杂的构建
    signer_info.push(Asn1Object::null().to_der().unwrap());

    signed_data.set_signer_infos(&signer_info).unwrap();

    // 添加证书
    let mut certificates = Stack::new().unwrap();
    certificates.push(certificate.clone()).unwrap();
    signed_data.set_certificates(&certificates).unwrap();

    // 添加签名值
    let mut signature_value = Vec::new();
    signature_value.push(Asn1Object::null().to_der().unwrap());
    signed_data.set_signature_value(&signature_value).unwrap();

    // 输出 SignedData 对象
    println!("SignedData: {:?}", signed_data);
}

