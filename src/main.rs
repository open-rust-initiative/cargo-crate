use crate::pack::{pack_context, pack_name};
use crate::unpack::unpack_context;
use crate::utils::context::SIGTYPE;
use crate::utils::pkcs::PKCS;
use clap::{Args,  Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;



pub mod pack;
pub mod unpack;
pub mod utils;

/// A fictional versioning CLI
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "cargo")]
#[command(bin_name = "cargo")]
#[command(about = "A fictional versioning CLI", long_about = None)]
enum CargoCli {
    Crate(CrateArgs),
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
struct CrateArgs {
    #[command(subcommand)]
    command: Option<CrateCommands>,
}


#[derive(Debug, Subcommand)]
enum CrateCommands {
    Encode(CrateEncodeArgs),
    Decode(CrateDecodeArgs)
}

#[derive(Debug, Args)]
struct CrateEncodeArgs {
    #[arg(short, long, required = false)]
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

#[derive(Debug, Args)]
struct CrateDecodeArgs {
    #[arg(short, long, required = false)]
    root_ca_paths: Vec<String>,
    ///output file path
    #[clap(short, long)]
    output: String,
    #[clap()]
    input: String,
}




fn main() {
    let CargoCli::Crate(args) = CargoCli::parse();
    if let  Some(subcommand)=args.command {
        match subcommand {
        CrateCommands::Encode(en_args)=>{
            //pack package
            let mut pack_context = pack_context(&en_args.input);

            //sign package
            let mut pkcs = PKCS::new();
            pkcs.load_from_file_writer(
                en_args.cert_path.unwrap(),
                en_args.pkey_path.unwrap(),
                en_args.root_ca_paths,
            );
            pack_context.add_sig(pkcs, SIGTYPE::CRATEBIN);

            //encode package to binary
            let (_, _, bin) = pack_context.encode_to_crate_package();

            //dump binary path/<name>.scrate
            let mut bin_path = PathBuf::from_str(en_args.output.as_str()).unwrap();
            bin_path.push(pack_name(&pack_context));
            fs::write(bin_path, bin).unwrap();
        }
        CrateCommands::Decode(de_args)=>{
            //decode package from binary
            let pack_context = unpack_context(de_args.input.as_str(), de_args.root_ca_paths);
            if pack_context.is_err() {
                eprintln!("{}", pack_context.unwrap_err());
                return;
            }
            let pack_context = pack_context.unwrap();
            //extract crate bin file
            let mut bin_path = PathBuf::from_str(de_args.output.as_str()).unwrap();
            bin_path.push(format!(
                "{}-{}.crate",
                pack_context.pack_info.name, pack_context.pack_info.version
            ));
            fs::write(bin_path, pack_context.crate_binary.bytes).unwrap();

            //dump scrate metadata
            let mut metadata_path = PathBuf::from_str(de_args.output.as_str()).unwrap();
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
            ).unwrap();
        }
    }
    }else {
        println!("Cargo subcommands: {:?}", args.command);
    }


}