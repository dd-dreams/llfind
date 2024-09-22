# <p align="center" style="font-family: sans-monospace"> llfind

llfind (Linked Library Finder) is a fast and a very minimal tool/library to find dynamically linked libraries
in executables. The program supports the following formats: Mach-O (including multi-architectures), ELF and PE (Portable Executable).

## Installation

## Cargo

You can install the tool using `cargo` by just running: `cargo install llfind`.

## GitHub releases

Navigate to the [releases](https://github.com/dd-dreams/aft/releases) page and choose your platform.
For Windows you can export the archive contents by double clicking.
For Linux and macOS you can use `gzip` for extracting the contents. `gzip` should be included by default.
Run: `gzip -dN <archive>`. You can export the program anywhere you like, but make sure you add it to PATH so you can easily access it.

## Building

Normal `cargo build` instructions.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
