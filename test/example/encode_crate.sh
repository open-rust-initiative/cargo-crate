script_dir=$(cd "$(dirname "$0")" && pwd)
test_dir=$(dirname "$script_dir")
crate_dir=$(dirname "$test_dir")
mkdir -p "$test_dir"/output
cd "$script_dir" || exit
cargo build || exit
cargo run -- -e -c "$test_dir"/cert.pem -r "$test_dir"/root-ca.pem -p "$test_dir"/key.pem -o "$test_dir"/output/ "$crate_dir" || exit
