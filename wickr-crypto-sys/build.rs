use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Initialize and update git submodules
    let output = Command::new("git")
        .args(&["submodule", "update", "--init", "--recursive"])
        .current_dir("../")
        .output()
        .expect("Failed to execute git submodule command");

    if !output.status.success() {
        panic!("Git submodule initialization failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let dst = cmake::Config::new("../")
        .define("SYSTEM_OPENSSL", "ON")
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=wickrcrypto");

    let bindings = bindgen::Builder::default()
        .header("../src/wickrcrypto/include/wickrcrypto/wickr_ctx.h")
        .header("../src/wickrcrypto/include/wickrcrypto/protocol.h")
        .header("../src/wickrcrypto/include/wickrcrypto/crypto_engine.h")
        .header("../src/wickrcrypto/include/wickrcrypto/stream_ctx.h")
        .clang_arg(format!("-I{}/include", dst.display()))
        .clang_arg("-I../src/wickrcrypto/include")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
