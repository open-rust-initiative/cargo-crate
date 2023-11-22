use crate_spec::utils::context::PackageContext;
use crate_spec::utils::from_toml::CrateToml;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

fn run_cmd(cmd: &str, args: Vec<&str>, cur_dir: Option<&PathBuf>) -> Result<String, String> {
    let mut output = Command::new(cmd);
    if !args.is_empty() {
        output.args(args);
    }
    if let Some(cd) = cur_dir {
        output.current_dir(cd);
    }
    let output = output
        .output()
        .unwrap_or_else(|_| panic!("error run cmd {}", cmd));
    return if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(stderr.to_string())
    };
}

struct Packing {
    pack_context: PackageContext,
    crate_path: PathBuf,
}

impl Packing {
    fn new(crate_path: &str) -> Self {
        Packing {
            pack_context: PackageContext::new(),
            crate_path: PathBuf::from_str(crate_path).unwrap(),
        }
    }

    fn cmd_cargo_package(&self) {
        let res = run_cmd(
            "cargo",
            ["package", "--allow-dirty"].to_vec(),
            Some(&self.crate_path),
        );
        if res.is_err() {
            panic!("{}", res.unwrap_err());
        } else {
            println!("{}", res.unwrap());
        }
    }

    fn read_crate(&mut self) {
        //parse crate toml file
        let mut toml_path = self.crate_path.clone();
        toml_path.push("Cargo.toml");
        let toml_path = fs::canonicalize(toml_path).unwrap();
        let toml = CrateToml::from_file(toml_path.to_str().unwrap().to_string());
        toml.write_info_to_package_context(&mut self.pack_context);

        //read crate binary
        let crate_bin_file = format!(
            "{}-{}.crate",
            self.pack_context.pack_info.name, self.pack_context.pack_info.version
        );
        let mut crate_bin_path = self.crate_path.clone();
        crate_bin_path.push(format!("target/package/{}", crate_bin_file));
        let crate_bin_path = fs::canonicalize(crate_bin_path).unwrap();
        assert!(crate_bin_path.exists());
        let bin = fs::read(crate_bin_path).unwrap();

        //write to pack_context
        self.pack_context.add_crate_bin(bin);
    }

    fn get_pack_context(mut self) -> PackageContext {
        self.cmd_cargo_package();
        self.read_crate();
        self.pack_context
    }
}

pub fn get_pack_context(path: &str) -> PackageContext {
    Packing::new(path).get_pack_context()
}

pub fn get_pack_name(pack: &PackageContext) -> String {
    format!("{}-{}.scrate", pack.pack_info.name, pack.pack_info.version)
}

#[test]
fn test_cmd_cargo_package() {
    let pac = get_pack_context("../crate-spec");
    println!("{:#?}", pac);
}
