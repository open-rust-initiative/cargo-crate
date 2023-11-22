use crate::pack::{get_pack_context, get_pack_name};
use crate::unpack::get_unpack_context;
use clap::Parser;
use crate_spec::utils::context::SIGTYPE;
use crate_spec::utils::pkcs::PKCS;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

pub mod pack;
pub mod unpack;
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    ///encode crate
    #[clap(short, long, required = false)]
    encode: bool,
    ///decode crate
    #[clap(short, long, required = false)]
    decode: bool,
    ///root-ca file paths
    #[clap(short, long, required = false)]
    root_ca_paths: Vec<String>,
    ///certification file path
    #[clap(short, long, required = false)]
    cert_path: Option<String>,
    ///private key path
    #[clap(short, long, required = false)]
    pkey_path: Option<String>,
    ///output file path
    #[clap(short, long)]
    output: String,
    #[clap()]
    input: String,
}

fn main() {
    let args = Args::parse();
    if args.encode && !args.decode {
        //check args
        if args.cert_path.is_none() {
            eprintln!("certificate not provided!");
            return;
        }
        if args.pkey_path.is_none() {
            eprintln!("pkey not provided!");
            return;
        }
        if args.root_ca_paths.is_empty() {
            eprintln!("root-ca not provided!");
            return;
        }

        //check input file
        let p = PathBuf::from_str(&args.input).unwrap();
        if !p.exists() {
            eprintln!("input files not found!");
            return;
        }

        //pack package
        let mut pack_context = get_pack_context(&args.input);

        //sign package
        let mut pkcs = PKCS::new();
        pkcs.load_from_file_writer(
            args.cert_path.unwrap(),
            args.pkey_path.unwrap(),
            args.root_ca_paths,
        );
        pack_context.add_sig(pkcs, SIGTYPE::CRATEBIN);

        //encode package to binary
        let (_, _, bin) = pack_context.encode_to_crate_package();

        //dump binary path/<name>.scrate
        let mut bin_path = PathBuf::from_str(args.output.as_str()).unwrap();
        bin_path.push(get_pack_name(&pack_context));
        fs::write(bin_path, bin).unwrap();
    } else if !args.encode && args.decode {
        //check args
        if args.root_ca_paths.is_empty() {
            eprintln!("root-ca not provided!");
            return;
        }

        //check input file
        let p = PathBuf::from_str(&args.input).unwrap();
        if !p.exists() {
            eprintln!("input files not found!");
            return;
        }

        //decode package from binary
        let pack_context = get_unpack_context(args.input.as_str(), args.root_ca_paths);
        if pack_context.is_err() {
            eprintln!("{}", pack_context.unwrap_err());
            return;
        }
        let pack_context = pack_context.unwrap();
        //extract crate bin file
        let mut bin_path = PathBuf::from_str(args.output.as_str()).unwrap();
        bin_path.push(format!(
            "{}-{}.crate",
            pack_context.pack_info.name, pack_context.pack_info.version
        ));
        fs::write(bin_path, pack_context.crate_binary.bytes).unwrap();

        //dump scrate metadata
        let mut metadata_path = PathBuf::from_str(args.output.as_str()).unwrap();
        metadata_path.push(format!(
            "{}-{}-metadata.txt",
            pack_context.pack_info.name, pack_context.pack_info.version
        ));
        fs::write(
            metadata_path,
            format!(
                "{:#?}\n{:#?}",
                pack_context.pack_info, pack_context.dep_infos
            ),
        )
        .unwrap();
    } else {
        eprintln!("-e or -d not found!");
        return;
    }
}
