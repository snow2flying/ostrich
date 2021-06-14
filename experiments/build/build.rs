use std::{env, path::{Path, PathBuf}, process::Command, io};
static N2N_STATIC_LIB: &str = "n2n";
// fn compile_n2n() {
//     cc::Build::new()
//         .file("src/n2n/src/n2n.c")
//         .file("src/n2n/src/edge_utils.c")
//         .file("src/n2n/src/sn_utils.c")
//         .file("src/n2n/src/wire.c")
//         .file("src/n2n/src/minilzo.c")
//         .file("src/n2n/src/tf.c")
//         .file("src/n2n/src/cc20.c")
//         .file("src/n2n/src/transform_null.c")
//         .file("src/n2n/src/transform_tf.c")
//         .file("src/n2n/src/transform_aes.c")
//         .file("src/n2n/src/transform_cc20.c")
//         .file("src/n2n/src/transform_speck.c")
//         .file("src/n2n/src/aes.c")
//         .file("src/n2n/src/speck.c")
//         .file("src/n2n/src/random_numbers.c")
//         .file("src/n2n/src/pearson.c")
//         .file("src/n2n/src/header_encryption.c")
//         .file("src/n2n/src/tuntap_freebsd.c")
//         .file("src/n2n/src/tuntap_netbsd.c")
//         .file("src/n2n/src/tuntap_linux.c")
//         .file("src/n2n/src/tuntap_osx.c")
//         .file("src/n2n/src/n2n_regex.c")
//         .file("src/n2n/src/network_traffic_filter.c")
//         .file("src/n2n/src/sn_selection.c")
//         .include("src/n2n/include")
//         .warnings(false)
//         .flag_if_supported("-Wno-everything")
//         .compile("libn2n.a");
// }

fn compile_n2n(n2n_dir: &PathBuf) -> PathBuf{
    let mut config = cmake::Config::new(n2n_dir);
    config
        .profile("Release")
        // CMake options
        .define("CMAKE_INSTALL_LIBDIR", "lib")
        .define("CMAKE_POSITION_INDEPENDENT_CODE", "ON");
    // Glslang options
    // .define("ENABLE_SPVREMAPPER", "OFF")
    // .define("ENABLE_GLSLANG_BINARIES", "OFF")
    // Shaderc options
    // .define("SHADERC_SKIP_TESTS", "ON")
    // SPIRV-Tools options
    // .define("SPIRV_SKIP_EXECUTABLES", "ON")
    // .define("SPIRV_WERROR", "OFF");
    // if use_ninja {
    //     config.generator("Ninja");
    // }



    config.build()
}


fn generate_n2n_bindings() {
    println!("cargo:rustc-link-lib=n2n");
    // println!("cargo:rerun-if-changed=src/proxy/tun/netstack/wrapper.h");
    println!("cargo:include=src/n2n/include");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let bindings = bindgen::Builder::default()
        .header("src/wrapper.h")
        .clang_arg("-I./src/n2n/include")
        .clang_arg("-Wno-everything")
        .layout_tests(false)
        .clang_arg(if arch == "aarch64" && os == "ios" {
            // https://github.com/rust-lang/rust-bindgen/issues/1211
            "--target=arm64-apple-ios"
        } else {
            ""
        })
        .clang_arg(if arch == "aarch64" && os == "ios" {
            // sdk path find by `xcrun --sdk iphoneos --show-sdk-path`
            let output = Command::new("xcrun")
                .arg("--sdk")
                .arg("iphoneos")
                .arg("--show-sdk-path")
                .output()
                .expect("failed to execute xcrun");
            let inc_path =
                Path::new(String::from_utf8_lossy(&output.stdout).trim()).join("usr/include");
            format!("-I{}", inc_path.to_str().expect("invalid include path"))
        } else {
            "".to_string()
        })
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let mut out_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    out_path = out_path.join("src/network");
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() -> io::Result<()>{
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_dir = Path::new(&manifest_dir).join("build");
    let proto_path = build_dir.join("proto");
    let output_path = proto_path.join("output");
    println!(
        "cargo:warning=shaderc: searching native shaderc libraries in '{}'",
        proto_path.display()
    );
    if !output_path.exists() {
        std::fs::create_dir(&output_path).unwrap();
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .out_dir(&output_path)
        .compile(&[proto_path.join("api/api.proto")], &[proto_path])?;


    // compile_n2n(&n2n_dir);

    let mut lib_path = compile_n2n(&build_dir);


    lib_path.push("build/n2n");
    println!(
        "cargo:warning=shaderc: searching native shaderc libraries in '{}'",
        lib_path.display()
    );
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=static={}", N2N_STATIC_LIB);
    Ok(())


    // generate_n2n_bindings();
    // let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    // if os == "ios" || os == "android" || os == "linux" || os == "macos" {
    //     compile_n2n();
    // }
    //
    // if env::var("BINDINGS_GEN").is_ok()
    //     && (os == "ios" || os == "android" || os == "linux" || os == "macos")
    // {
    //     generate_n2n_bindings();
    // }
}
