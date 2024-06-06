use std::{future::pending, path::Path};

use bip300_messages::{
    bitcoin::{
        opcodes::{all::OP_PUSHBYTES_1, OP_TRUE},
        ScriptBuf,
    },
    sha256d, CoinbaseBuilder, M4AckBundles, OP_DRIVECHAIN,
};
use miette::{miette, IntoDiagnostic, Result};

use clap::Parser;
use wallet::Wallet;

use crate::{cli::Command, wallet::create_client};

mod cli;
mod wallet;

#[tokio::main]
async fn main() -> Result<()> {
    let message = [
        OP_DRIVECHAIN.to_u8(),
        OP_PUSHBYTES_1.to_u8(),
        0,
        OP_TRUE.to_u8(),
    ];
    let op_drivechain = ScriptBuf::from_bytes(message.into());

    let witness_version = op_drivechain.witness_version();
    dbg!(witness_version);
    dbg!(op_drivechain.is_witness_program());

    let tx_hex = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402670100ffffffff04807c814a00000000160014b7f21a1f88a270063cdd28f4fc19bbb57d012542000000000000000004b40103510000000000000000266ad6e1c5df032a57d5dbaefb9d7e46c6a4e0515d08d16a4ff7eeb30dde9ede22c5dd99ddd4f00000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";

    let cli = cli::Cli::parse();

    let mut wallet = Wallet::new("./db").await?;

    match cli.command {
        Command::Mine { count } => {
            for _ in 0..count.unwrap_or(1) {
                let sidechain_proposals = wallet.get_sidechain_proposals()?;
                let mut coinbase_builder = CoinbaseBuilder::new();
                for sidechain_proposal in sidechain_proposals {
                    coinbase_builder = coinbase_builder.propose_sidechain(
                        sidechain_proposal.sidechain_number,
                        sidechain_proposal.data.as_slice(),
                    );
                }
                let sidechain_acks = wallet.get_sidechain_acks()?;
                let pending_sidechain_proposals = wallet.get_pending_sidechain_proposals().await?;
                for sidechain_ack in sidechain_acks {
                    if let Some(sidechain_proposal) =
                        pending_sidechain_proposals.get(&sidechain_ack.sidechain_number)
                    {
                        if sidechain_proposal.data_hash == sidechain_ack.data_hash {
                            dbg!(sidechain_proposal);
                            if sidechain_proposal.vote_count == 19 {
                                coinbase_builder =
                                    coinbase_builder.op_drivechain(sidechain_ack.sidechain_number);
                            }
                            coinbase_builder = coinbase_builder.ack_sidechain(
                                sidechain_ack.sidechain_number,
                                &sidechain_ack.data_hash,
                            );
                        } else {
                            wallet.delete_sidechain_ack(&sidechain_ack)?;
                        }
                    } else {
                        wallet.delete_sidechain_ack(&sidechain_ack)?;
                    }
                }
                let coinbase_outputs = coinbase_builder.build();

                let deposits = wallet.get_deposits(None)?;
                let deposit_transactions = deposits
                    .into_iter()
                    .map(|deposit| deposit.transaction)
                    .collect();
                // let deposit_transactions = vec![];

                wallet.mine(&coinbase_outputs, deposit_transactions).await?;
                wallet.delete_sidechain_proposals()?;
                wallet.delete_deposits()?;
            }
        }
        Command::GetBalance => {
            wallet.get_balance()?;
        }
        Command::GetUtxos => {
            wallet.get_utxos()?;
        }
        Command::ProposeSidechain {
            sidechain_number,
            data,
        } => {
            wallet.propose_sidechain(sidechain_number, data.as_bytes())?;
        }
        Command::ListSidechainProposals => {
            let sidechain_proposals = wallet.get_sidechain_proposals()?;
            let pending_sidechain_proposals = wallet.get_pending_sidechain_proposals().await?;

            println!("Proposals waiting to be included:");
            for proposal in &sidechain_proposals {
                let data_hash = sha256d(&proposal.data);
                let data_hash = hex::encode(&data_hash);
                println!(
                    "sidechain number: {} data hash: {} data: {}",
                    proposal.sidechain_number,
                    data_hash,
                    String::from_utf8(proposal.data.clone()).into_diagnostic()?,
                );
            }
            println!();

            println!("Proposals being voted on:");
            for (_, proposal) in &pending_sidechain_proposals {
                let data = String::from_utf8(proposal.data.clone()).into_diagnostic()?;
                let data_hash = hex::encode(&proposal.data_hash);

                let main_datadir = Path::new("../../data/bitcoin/");
                let main_client = create_client(main_datadir)?;
                let block_height: u32 = main_client
                    .send_request("getblockcount", &[])
                    .into_diagnostic()?
                    .ok_or(miette!("failed to get block count"))?;
                println!(
                    "sidechain number: {} data hash: {} data: {} votes: {} age: {}",
                    proposal.sidechain_number,
                    data_hash,
                    data,
                    proposal.vote_count,
                    block_height - proposal.proposal_height
                );
            }
        }
        Command::ListSidechains => {
            let sidechains = wallet.get_sidechains().await?;
            for sidechain in &sidechains {
                println!(
                    "sidechain number: {} data: {}",
                    sidechain.sidechain_number,
                    String::from_utf8(sidechain.data.clone()).into_diagnostic()?
                );
            }
        }
        Command::GetBlockCount => {
            let main_datadir = Path::new("../../data/bitcoin/");
            let main_client = create_client(main_datadir)?;
            let block_height: u32 = main_client
                .send_request("getblockcount", &[])
                .into_diagnostic()?
                .ok_or(miette!("failed to get block count"))?;
            println!("{block_height}");
        }
        Command::GetCtip { sidechain_number } => {
            let (outpoint, value) = wallet.get_ctip(sidechain_number).await?;
            println!("outpoint: {} value: {}", outpoint, value,);
        }
        Command::NackSidechain {
            sidechain_number,
            data_hash,
        } => {
            let data_hash: [u8; 32] = hex::decode(data_hash)
                .into_diagnostic()?
                .try_into()
                .unwrap();
            wallet.nack_sidechain(sidechain_number, &data_hash)?;
        }
        Command::AckSidechain {
            sidechain_number,
            data_hash,
        } => {
            let data_hash: [u8; 32] = hex::decode(data_hash)
                .into_diagnostic()?
                .try_into()
                .unwrap();
            wallet.ack_sidechain(sidechain_number, &data_hash)?;
        }
        Command::ProposeBundle {
            sidechain_number,
            bundle_hash,
        } => {
            let bundle_hash: [u8; 32] = hex::decode(bundle_hash)
                .into_diagnostic()?
                .try_into()
                .unwrap();
            let coinbase = CoinbaseBuilder::new()
                .propose_bundle(sidechain_number, &bundle_hash)
                .build();
            dbg!(coinbase);
        }
        Command::AckBundles { bundles } => {
            let bundle_hashes: Vec<[u8; 32]> = bundles
                .iter()
                .map(|bundle_hash| hex::decode(&bundle_hash).unwrap().try_into().unwrap())
                .collect();
            let m4_ack_bundles = M4AckBundles::OneByte {
                upvotes: vec![0, 1, 2],
            };
            let coinbase = CoinbaseBuilder::new().ack_bundles(m4_ack_bundles).build();
            dbg!(coinbase);
        }
        Command::Deposit {
            sidechain_number,
            address,
            amount,
        } => {
            println!("deposit sidechain number: {sidechain_number}, address: {address}, amount: {amount}");
            wallet
                .deposit(sidechain_number, &address, amount.to_sat())
                .await?;
        }
        Command::GetDeposits { sidechain_number } => {
            let deposits = wallet.get_deposits(sidechain_number)?;
            for deposit in &deposits {
                let address = bs58::encode(&deposit.address).with_check().into_string();
                println!(
                    "sidechain number: {} address: {} amount: {} txid: {}",
                    deposit.sidechain_number,
                    address,
                    deposit.amount,
                    deposit
                        .transaction
                        .txid()
                        .to_string()
                        .chars()
                        .take(8)
                        .collect::<String>()
                );
            }
        }
        Command::EncodeSidechainAddress { data } => {
            let address = bs58::encode(data).with_check().into_string();
            println!("{address}");
        }
    }

    Ok(())
}
