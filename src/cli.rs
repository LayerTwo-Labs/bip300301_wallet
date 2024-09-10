use bdk::bitcoin::Amount;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Mine a new block in regtest mode.
    Mine {
        count: Option<u32>,
    },
    /// Submit a transaction on a sidechain.
    Send {
        sidechain_number: u8,
        address: String,
        value: Amount,
        fee: Amount,
    },
    /// Show all transactions in the "mempool".
    Mempool,
    /// Get balances available in the wallet.
    GetBalance,
    /// Get a list of all UTXOs in the mainchain wallet.
    GetUtxos,
    /// Crete a new sidechain proposal for miners to vote on.
    ProposeSidechain {
        sidechain_number: u8,
        data: String,
    },
    /// Get all sidechain proposals.
    GetSidechainProposals,
    /// Get all active sidechains.
    GetSidechains,
    /// Get number of blocks.
    GetBlockCount,
    /// Get current CTIP for a particular sidechain.
    GetCtip {
        sidechain_number: u8,
    },
    /// Vote for activating a sidechain.
    AckSidechain {
        sidechain_number: u8,
        data_hash: String,
    },
    /// Don't vote for activating a sidechain.
    NackSidechain {
        sidechain_number: u8,
        data_hash: String,
    },
    /// Propose a withdrawal bundle.
    ProposeBundle {
        sidechain_number: u8,
        bundle_hash: String,
    },
    /// Vote for including withdrawal bundles.
    AckBundles {
        bundles: Vec<String>,
    },
    /// Deposit funds to a sidechain address.
    Deposit {
        sidechain_number: u8,
        amount: Amount,
        address: Option<String>,
    },
    /// Get all deposits.
    GetDeposits {
        sidechain_number: u8,
    },
    /// Encode sidechain address in the proper format.
    EncodeSidechainAddress {
        data: String,
    },
    /// Get new sidechain address
    GetNewSidechainAddress {
        sidechain_number: u8,
    },
    /// Mine a block for a sidechain.
    MineSideBlock {
        sidechain_number: u8,
    },
    /// Get a list of all UTXOs in the sidechain wallet.
    GetSideUtxos {
        sidechain_number: u8,
    },
    /// Spend a sidechain utxo.
    Spend {
        utxo_id: u64,
    },
    /// Clear inputs and outputs for pending sidechain transaction.
    ClearPendingTransaction,
    /// Submit pending sidechain transaction.
    SubmitPendingTransaction,
    /// Get pending sidechain transaction.
    GetPendingTransaction,
    AddOutput {
        value: Amount,
        address: Option<String>,
        main_address: Option<String>,
        main_fee: Option<Amount>,
    },
    SyncSideUtxos {
        sidechain_number: u8,
    },
}
