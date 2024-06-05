use bdk::bitcoin::{Address, Amount};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Mine {
        count: Option<u32>,
    },
    GetBalance,
    GetUtxos,
    ProposeSidechain {
        sidechain_number: u8,
        data: String,
    },
    ListSidechainProposals,
    ListSidechains,
    AckSidechain {
        sidechain_number: u8,
        data_hash: String,
    },
    NackSidechain {
        sidechain_number: u8,
        data_hash: String,
    },
    ProposeBundle {
        sidechain_number: u8,
        bundle_hash: String,
    },
    AckBundles {
        bundles: Vec<String>,
    },
    Deposit {
        sidechain_number: u8,
        address: String,
        amount: Amount,
    },
}
