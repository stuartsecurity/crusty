fn main() {
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-nostartfiles");
    println!("cargo:rustc-link-arg=-static");
    println!("cargo:rustc-link-arg=-fno-ident");
    println!("cargo:rustc-link-arg=-Wl,--gc-sections,--build-id=none");
    println!("cargo:rustc-link-arg=-falign-labels=1");
    println!("cargo:rustc-link-arg=-Wall");
    println!("cargo:rustc-link-arg=-fno-asynchronous-unwind-tables");
    println!("cargo:rustc-link-arg=-Wl,-e_start");

    println!("cargo:rustc-link-arg=-Wl,-Map=implant.map");
}
