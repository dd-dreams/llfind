mod find;
use std::env::args as args_fn;

const HELP: &str = "llfinder {} - find dynamically linked libraries in binaries

Usage:
    llfinder <path1> <path2> ...

Positional arguments:
    path1, path2, ...

Optional arguments:
    --help,    -h      Prints help
    --version, -v      Prints the version
";

fn main() {
    let args = args_fn();
    let version = env!("CARGO_PKG_VERSION");
    if args.len() == 1 {
        print!("{}", HELP.replace("{}", version));
        return;
    }

    for path in args.skip(1) {
        let mut file = std::fs::File::open(&path).expect(&format!("Invalid path {}", path));
        match find::fileos(&mut file).unwrap() {
            (find::OS::Macho, bits) => {
                let libs = find::find_macho(&mut file, bits).expect("IO Error");
                if libs.is_empty() {
                    println!("No dynamic libraries in {}", path);
                    return;
                }
                for lib in libs {
                    println!("{}, compatibility version: {}, current version: {}, load: {}",
                        lib.path,
                        lib.compat_ver,
                        lib.curr_ver,
                        if lib.cmd == 1 {"full path"} else if lib.cmd == 0 {"current directory load"} else {"not required"});
                }
            }
            (find::OS::ELF, _) => {
                let libs = find::find_elf(&mut file).unwrap();
                for lib in libs {
                    println!("{}", lib.name);
                }
            }
            (find::OS::PE, _) => {
                let libs = find::find_pe(&mut file).unwrap();
                for lib in libs {
                    println!("{}", lib.name);
                }
            }
            _ => {
                println!("Unknown platform for {}", path);
            }
        }
    }
}
