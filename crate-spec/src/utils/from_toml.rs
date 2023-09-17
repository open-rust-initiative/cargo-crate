use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use toml::Table;
use crate::utils::context::{DepInfo, PackageContext, SrcTypePath};


struct CrateToml{
    t:Table
}

impl CrateToml{
    pub fn default()->Self{
        CrateToml{
            t: Default::default(),
        }
    }
    pub fn from_file(path:String)->CrateToml{
        let f = fs::read(Path::new(path.as_str())).unwrap();
        CrateToml::from_str(String::from_utf8(f).unwrap().as_str())
    }
    pub fn from_str(st: &str)->CrateToml{
        CrateToml{
            t:Table::from_str(st).unwrap()
        }
    }
}

impl CrateToml{
    fn write_package_info_to_package_context(&self, package_context: &mut PackageContext, package: &Table){
        let name = package["name"].as_str().unwrap().to_string();
        let version = package["version"].as_str().unwrap().to_string();
        let mut license="".to_string();
        let mut authors = Vec::<String>::new();
        if package["license"].as_str().is_some(){
            license = package["license"].as_str().unwrap().to_string();
        }
        if package["authors"].as_array().is_some(){
            authors = package["authors"].as_array().unwrap().iter().map(|x|x.as_str().unwrap().to_string()).collect();
        }
        package_context.set_package_info(name, version, license, authors);
    }

    fn write_dep_info_to_package_context(&self, package_context: &mut PackageContext, deps: &Table, platform:String)->Vec<String>{
        let mut irresolve_depinfos = vec![];
        for dep in deps.iter(){
            let name =  dep.0.to_string();
            let val = dep.1;
            let mut dep_info = DepInfo::default();
            dep_info.src_platform = platform.to_string();
            let mut req_ver = "default".to_string();
            let mut dump = true;
            let mut src = SrcTypePath::CratesIo;
            if val.is_str(){
                dep_info.ver_req = val.to_string();
            }else{
                let attri_map = val.as_table().unwrap();
                let allow_keys = HashSet::from(["version".to_string(), "git".to_string(), "registry".to_string()]);
                for attri in attri_map.keys(){
                    if !allow_keys.contains(attri){
                        dep_info.dump = false;
                    }
                }
                if attri_map.contains_key("version") {
                    dep_info.ver_req = attri_map["version"].as_str().unwrap().to_string();
                }
                if attri_map.contains_key("git"){
                    dep_info.src = SrcTypePath::Git(attri_map["git"].as_str().unwrap().to_string());
                }
                if attri_map.contains_key("registry"){
                    dep_info.src = SrcTypePath::Registry(attri_map["registry"].as_str().unwrap().to_string());
                }
            }
            if dep_info.dump{
                package_context.add_dep_info(dep_info.name, dep_info.ver_req, dep_info.src, dep_info.src_platform);
            }else{
                irresolve_depinfos.push(dep_info.name);
            }
        }
        return irresolve_depinfos;
    }

    pub fn write_info_to_package_context(&self, package_context: &mut PackageContext)->Vec<String>{
        assert!(self.t.contains_key("package"));
        unimplemented!()
    }
}

#[test]
fn test_toml(){
    use toml::Table;
    let f = fs::read("Cargo.toml".to_string()).unwrap();
    let mut t = Table::from_str(String::from_utf8(f).unwrap().as_str()).unwrap();
    println!("{:#?}", t["dependencies"].as_table().unwrap());
}