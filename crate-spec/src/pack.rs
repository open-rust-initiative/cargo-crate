use std::path::{PathBuf};
use std::process::Command;
use std::{fs};
use std::str::FromStr;
use crate_spec::utils::context::PackageContext;
use crate_spec::utils::from_toml::CrateToml;

fn run_cmd(cmd:&str, args:Vec<&str>, cur_dir:Option<&PathBuf>)->Result<String, String>{
    let mut output = Command::new(cmd);
    if !args.is_empty(){
        output.args(args);
    }
    if cur_dir.is_some(){
        output.current_dir(cur_dir.unwrap());
    }
    let output = output.output().expect(format!("error run cmd {}", cmd).as_str());
    return if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(stderr.to_string())
    }
}




struct Packing {
    pack_context:PackageContext,
    crate_path: PathBuf,
}

impl Packing {
    fn new(crate_path:&str)->Self{
        Packing {
            pack_context: PackageContext::new(),
            crate_path:  PathBuf::from_str(crate_path).unwrap()
        }
    }

    fn cmd_cargo_package(&self){
        let res = run_cmd("cargo",["package", "--allow-dirty"].to_vec(), Some(&self.crate_path));
        if res.is_err(){
            panic!("{}", res.unwrap_err());
        }else{
            println!("{}", res.unwrap());
        }
    }

    fn read_crate(&mut self){
        let mut toml_path = self.crate_path.clone();
        toml_path.push("Cargo.toml");
        let toml_path = fs::canonicalize(toml_path).unwrap();
        let toml = CrateToml::from_file(toml_path.to_str().unwrap().to_string());
        toml.write_info_to_package_context(&mut self.pack_context);
        let crate_bin_file = format!("{}-{}.crate", self.pack_context.pack_info.name, self.pack_context.pack_info.version);
        let mut crate_bin_path = self.crate_path.clone();
        crate_bin_path.push("target");
        crate_bin_path.push("package");
        crate_bin_path.push(crate_bin_file);
        let crate_bin_path = fs::canonicalize(crate_bin_path).unwrap();
        assert!(crate_bin_path.exists());
        let bin = fs::read(crate_bin_path).unwrap();
        self.pack_context.add_crate_bin(bin);
    }

    fn get_pack_context(mut self)->PackageContext{
        self.cmd_cargo_package();
        self.read_crate();
        self.pack_context
    }
}

pub fn get_pack_context(path:&str)->PackageContext{
    Packing::new(path).get_pack_context()
}


#[test]
fn test_cmd_cargo_package(){
    let pac = get_pack_context("../crate-spec");
    println!("{:#?}", pac);
}
