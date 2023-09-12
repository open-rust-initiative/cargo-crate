use crate::utils::context::PackageContext;
use crate::utils::package::CratePackage;
use crate::utils::package::gen_bincode::encode2vec_by_bincode;

impl PackageContext{
    pub fn get_binary_before_sig(&self, crate_package: &CratePackage) -> Vec<u8> {
        //FIXME
        let mut buf = vec![];
        buf.extend(encode2vec_by_bincode(&crate_package.magic_number));
        buf.extend(encode2vec_by_bincode(&crate_package.string_table));
        buf.extend(crate_package.section_index.encode_fake_to_vec(crate_package.crate_header.si_not_sig_size as usize, crate_package.crate_header.si_size as usize));
        buf.extend(crate_package.data_sections.encode_fake_to_vec(crate_package.section_index.fake_datasection_size(crate_package.crate_header.si_not_sig_num)));
        buf
    }
}