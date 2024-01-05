use crate::utils::context::PackageContext;
use crate::utils::pkcs::PKCS;
use std::path::PathBuf;
use std::str::FromStr;
use std::fs;

struct Unpacking {
    file_path: PathBuf,
    cas_path: Vec<String>,
}

impl Unpacking {
    pub fn new(path: &str) -> Unpacking {
        Unpacking {
            file_path: PathBuf::from_str(path).unwrap(),
            cas_path: Vec::new(),
        }
    }

    pub fn add_ca_from_file(&mut self, path: &str) {
        let file_path = fs::canonicalize(PathBuf::from_str(path).unwrap()).unwrap();
        self.cas_path.push(file_path.to_str().unwrap().to_string());
    }

    pub fn unpack_context(self) -> Result<PackageContext, String> {
        let mut package_context_new = PackageContext::new();
        package_context_new.set_root_cas_bin(PKCS::root_ca_bins(self.cas_path));
        let bin = fs::read(self.file_path).unwrap();
        let (_crate_package_new, _str_table) =
            package_context_new.decode_from_crate_package(bin.as_slice())?;
        Ok(package_context_new)
    }
}

pub fn unpack_context(file_path: &str, cas_path: Vec<String>) -> Result<PackageContext, String> {
    let mut unpack = Unpacking::new(file_path);
    cas_path
        .iter()
        .for_each(|ca_path| unpack.add_ca_from_file(ca_path.as_str()));
    unpack.unpack_context()
}

#[test]
fn test_unpack() {
    use std::env;
    
    use crate::utils::context::SIGTYPE;
    use crate::pack::pack_context;


    let mut pack_context = pack_context(env::current_dir().unwrap().to_str().unwrap());
    fn sign() -> PKCS {
        let mut pkcs1 = PKCS::new();
        pkcs1.load_from_file_writer(
            "test/cert.pem".to_string(),
            "test/key.pem".to_string(),
            ["test/root-ca.pem".to_string()].to_vec(),
        );
        pkcs1
    }
    pack_context.add_sig(sign(), SIGTYPE::CRATEBIN);

    let (_, _, bin) = pack_context.encode_to_crate_package();
    fs::write(PathBuf::from_str("test/crate-spec.cra").unwrap(), bin).unwrap();

    let pack_context_decode =
        unpack_context("test/crate-spec.cra", vec!["test/root-ca.pem".to_string()]);

    assert_eq!(
        pack_context_decode.as_ref().unwrap().pack_info,
        pack_context.pack_info
    );
    assert_eq!(
        pack_context_decode.as_ref().unwrap().dep_infos,
        pack_context.dep_infos
    );
    assert_eq!(
        pack_context_decode.unwrap().crate_binary,
        pack_context.crate_binary
    );

    fs::remove_file("test/crate-spec.cra").unwrap()
}
