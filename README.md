# Crusty

Educational rust code for creating a position independant, implantable tcp connection. Also commonly known as reverse shell.

The resulting implant.bin file should be between 1200 and 1300 bytes.

## Prerequisite

- [cargo make](https://crates.io/crates/cargo-make)
- On Windows: x86_64-w64-mingw32 tools

## Build Instructions

```bash
cargo make
```


## Usage

the `init` function accepts a pointer to byte array (4 bytes) and a 16 bit port number.
