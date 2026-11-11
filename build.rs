//! Produces the `heel-shim` executable the library embeds.
//!
//! The `shim` feature gates everything here: without it the script does
//! nothing. With it, one file is written to `OUT_DIR`, the shim executable for
//! `TARGET`, which `src/ipc/shim.rs` includes with `include_bytes!`. It comes,
//! in this order, from
//!
//! 1. the shim's source, when this package is a checkout that contains
//!    `shim/` (a prebuilt executable would not match that source);
//! 2. the prebuilt executable of exactly the shim version this package depends
//!    on, published as an asset of the shim's GitHub release;
//! 3. `cargo install` of that version, when the target has no prebuilt or the
//!    download failed.
//!
//! The download is a `curl` subprocess rather than an HTTP client: this
//! package's dependency tree has no TLS stack, and adding one would compile it
//! in every consumer's build.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the shim's release assets are published.
const RELEASE_DOWNLOAD_URL: &str = "https://github.com/May-Agent/heel/releases/download";

/// The longest `curl` may spend on the whole transfer, in seconds: the
/// executable is a few megabytes, so this allows a slow link while still
/// failing a stalled connection.
const FETCH_TIME_LIMIT_SECONDS: &str = "120";

/// Name of the file written to `OUT_DIR`.
const OUTPUT_NAME: &str = "heel-shim";

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=DOCS_RS");
    if std::env::var_os("CARGO_FEATURE_SHIM").is_none() {
        return;
    }

    let out_dir = PathBuf::from(required_env("OUT_DIR"));
    let output = out_dir.join(OUTPUT_NAME);
    if std::env::var_os("DOCS_RS").is_some() {
        // Nothing runs on docs.rs and its sandbox has no network.
        std::fs::write(&output, []).expect("writes the placeholder shim");
        return;
    }

    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let target = required_env("TARGET");
    let windows = required_env("CARGO_CFG_TARGET_OS") == "windows";
    let executable = if windows {
        format!("{OUTPUT_NAME}.exe")
    } else {
        OUTPUT_NAME.to_owned()
    };

    let built = if manifest_dir.join("shim/Cargo.toml").is_file() {
        build_checkout(&manifest_dir, &out_dir, &target, &executable)
            .unwrap_or_else(|error| panic!("building the shim from this checkout failed: {error}"))
    } else {
        fetch_or_install(&out_dir, &target, &executable)
    };
    std::fs::copy(&built, &output)
        .unwrap_or_else(|error| panic!("copying {} failed: {error}", built.display()));
}

/// Build the shim from the source beside this package.
fn build_checkout(
    manifest_dir: &Path,
    out_dir: &Path,
    target: &str,
    executable: &str,
) -> Result<PathBuf, String> {
    let shim_dir = manifest_dir.join("shim");
    println!(
        "cargo::rerun-if-changed={}",
        shim_dir.join("Cargo.toml").display()
    );
    println!("cargo::rerun-if-changed={}", shim_dir.join("src").display());
    println!(
        "cargo::rerun-if-changed={}",
        manifest_dir.join("Cargo.lock").display()
    );

    let target_dir = out_dir.join("shim-build");
    let release = required_env("PROFILE") == "release";
    let mut cargo = cargo();
    cargo
        .arg("build")
        .arg("--manifest-path")
        .arg(shim_dir.join("Cargo.toml"))
        .args(["--bin", OUTPUT_NAME, "--locked", "--target", target])
        .arg("--target-dir")
        .arg(&target_dir);
    if release {
        cargo.arg("--release");
    }
    run(cargo)?;
    Ok(target_dir
        .join(target)
        .join(if release { "release" } else { "debug" })
        .join(executable))
}

/// Download the prebuilt executable, or build the published crate when there
/// is none for `target` or the download fails.
fn fetch_or_install(out_dir: &Path, target: &str, executable: &str) -> PathBuf {
    let fetch_error = match fetch(out_dir, target, executable) {
        Ok(path) => return path,
        Err(error) => error,
    };
    println!(
        "cargo::warning=no prebuilt heel-shim {version} for {target} ({fetch_error}); \
         building it with cargo install",
        version = heel_shim::VERSION,
    );
    match install(out_dir, target, executable) {
        Ok(path) => path,
        Err(install_error) => panic!(
            "no heel-shim {version} executable for {target}\n\
             fetching the prebuilt executable failed: {fetch_error}\n\
             building it with cargo install failed: {install_error}",
            version = heel_shim::VERSION,
        ),
    }
}

/// The release asset target a prebuilt executable exists for, if any.
///
/// Linux prebuilts are static musl builds, so they serve the gnu and musl
/// targets of their architecture alike.
fn prebuilt_target(target: &str) -> Option<&'static str> {
    match target {
        "x86_64-unknown-linux-gnu" | "x86_64-unknown-linux-musl" => {
            Some("x86_64-unknown-linux-musl")
        }
        "aarch64-unknown-linux-gnu" | "aarch64-unknown-linux-musl" => {
            Some("aarch64-unknown-linux-musl")
        }
        "aarch64-apple-darwin" => Some("aarch64-apple-darwin"),
        "x86_64-pc-windows-msvc" => Some("x86_64-pc-windows-msvc"),
        "aarch64-pc-windows-msvc" => Some("aarch64-pc-windows-msvc"),
        _ => None,
    }
}

/// Download the prebuilt executable of this shim version.
fn fetch(out_dir: &Path, target: &str, executable: &str) -> Result<PathBuf, String> {
    let asset_target = prebuilt_target(target)
        .ok_or_else(|| format!("the release publishes no executable for {target}"))?;
    let suffix = executable.strip_prefix(OUTPUT_NAME).unwrap_or_default();
    let url = format!(
        "{RELEASE_DOWNLOAD_URL}/shim/v{version}/{OUTPUT_NAME}-{asset_target}{suffix}",
        version = heel_shim::VERSION,
    );
    let downloaded = out_dir.join("shim-download").join(executable);
    std::fs::create_dir_all(downloaded.parent().expect("a file has a parent"))
        .map_err(|error| error.to_string())?;
    let mut curl = Command::new("curl");
    curl.args([
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-time",
        FETCH_TIME_LIMIT_SECONDS,
        "--output",
    ])
    .arg(&downloaded)
    .arg(&url);
    run(curl).map_err(|error| format!("fetching {url}: {error}"))?;
    let size = std::fs::metadata(&downloaded)
        .map_err(|error| error.to_string())?
        .len();
    if size == 0 {
        return Err(format!("{url} is empty"));
    }
    Ok(downloaded)
}

/// Build the published crate of this shim version.
fn install(out_dir: &Path, target: &str, executable: &str) -> Result<PathBuf, String> {
    let root = out_dir.join("shim-install");
    let mut cargo = cargo();
    cargo
        .arg("install")
        .arg(OUTPUT_NAME)
        .arg("--version")
        .arg(format!("={}", heel_shim::VERSION))
        .args(["--locked", "--bin", OUTPUT_NAME, "--target", target])
        .arg("--root")
        .arg(&root)
        .arg("--target-dir")
        .arg(out_dir.join("shim-install-build"));
    run(cargo)?;
    Ok(root.join("bin").join(executable))
}

/// The cargo that runs this build, for a build of its own.
fn cargo() -> Command {
    let mut cargo = Command::new(required_env("CARGO"));
    // A lint wrapper the outer build runs over this package's crates must not
    // run over the executable that is embedded into them.
    cargo.env_remove("RUSTC_WORKSPACE_WRAPPER");
    cargo
}

/// Run `command`, naming its standard error when it fails.
fn run(mut command: Command) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|error| format!("cannot run {:?}: {error}", command.get_program()))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{:?} exited with {}: {}",
        command.get_program(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// A variable cargo always sets for a build script.
fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("cargo did not set {name}"))
}
