Bitcoin Core in regtest mode alongside with electrs must be running for this
wallet to work.

Also the Bitcoin `-datadir` parameter must be set to `../../data/bitcoin/`
relative to the working directory from which the wallet is being called.

Bitcoin core must be run with the `-txindex` flag in order for sidechain
deposits to work.

WARNING

This wallet MUST NOT be used in production in its current state, it is only
intended for testing. Currently the 12 words are hard coded as
```
betray annual dog current tomorrow media ghost dynamic mule length sure salad
```
for ease of testing.

## Building from a fresh clone

The `bip300301_enforcer_proto` directory is an in-tree Tonic shim. It compiles protos from
[cusf_sidechain_proto](https://github.com/LayerTwo-Labs/cusf_sidechain_proto) at **`cusf_sidechain_proto/proto/`**
inside this repository (initialize the submodule after clone):

```bash
git submodule update --init --recursive
cargo build
```

## Follow-ups (maintainers)

- **Publish:** After cloning, push commits with a GitHub account that has write access to **LayerTwo-Labs** (a
  misconfigured remote user will get `403` on `git push`).
- **Lockfile vs proto repo:** `Cargo.lock` may still pin the **`cusf_sidechain_proto`** *crate* from crates.io/git at
  an older revision. When you intentionally move to newer protos, run  
  `cargo update -p cusf_sidechain_proto`  
  and re-run tests.
