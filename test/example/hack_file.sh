script_dir=$(cd "$(dirname "$0")" && pwd)
test_dir=$(dirname "$script_dir")

python3 "$script_dir"/hack.py "$1"