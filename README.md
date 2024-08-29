Bitcoin Core in regtest mode alongside with electrs must be running for this
wallet to work.

Also the Bitcoin `-datadir` parameter must be set to `../../data/bitcoin/`
relative to the working directory from which the wallet is being called.

WARNING

This wallet MUST NOT be used in production in its current state, it is only
intended for testing. Currently the 12 words are hard coded as
```
betray annual dog current tomorrow media ghost dynamic mule length sure salad
```
for ease of testing.
