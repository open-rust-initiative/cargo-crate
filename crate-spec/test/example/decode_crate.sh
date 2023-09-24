script_dir=$(cd "$(dirname "$0")" && pwd)
test_dir=$(dirname "$script_dir")
cd "$script_dir" || exit
cargo build || exit
cargo run -- -d -r "$test_dir"/root-ca.pem -o "$test_dir"/output/ "$test_dir"/output/crate-spec-0.1.0.scrate || exit
