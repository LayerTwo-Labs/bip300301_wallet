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

The `bip300301_enforcer_proto` directory is an in-tree Tonic shim. It needs the proto files from
[cusf_sidechain_proto](https://github.com/LayerTwo-Labs/cusf_sidechain_proto) at `cusf_sidechain_proto/proto/`
(e.g. `git submodule add` that repo as `cusf_sidechain_proto`, or clone it beside this repo and use the
`../cusf_sidechain_proto/proto` fallback path).
