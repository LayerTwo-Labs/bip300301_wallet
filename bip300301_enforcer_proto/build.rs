//! Locate `cusf_sidechain_proto` (git submodule or sibling checkout) and compile mainchain protos.

use std::env;
use std::path::{Path, PathBuf};

fn proto_root_from_manifest(manifest_dir: &Path) -> PathBuf {
    let repo_root = manifest_dir
        .parent()
        .expect("bip300301_enforcer_proto must live directly under the repository root");
    // Only paths inside this repository so CI and clones do not pick up an unrelated sibling tree.
    let candidates = [repo_root.join("cusf_sidechain_proto/proto")];
    for c in candidates {
        if c.join("cusf/mainchain/v1/validator.proto").is_file() {
            return c;
        }
    }
    panic!(
        "cusf_sidechain_proto/proto not found. From repo root run:\n  git submodule update --init --recursive\n\
         or place cusf_sidechain_proto next to this repository."
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = proto_root_from_manifest(&manifest_dir);
    let common = proto_root.join("cusf/common/v1/common.proto");
    let validator = proto_root.join("cusf/mainchain/v1/validator.proto");
    for p in [&common, &validator] {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed={}", proto_root.display());

    tonic_build::configure()
        .build_server(false)
        .compile(
            &[common.as_path(), validator.as_path()],
            &[proto_root.as_path()],
        )?;
    Ok(())
}
