// May the Barbarous Words inscribed upon this Black Mirror echo in All Eternity.

use bip300301_messages::{sha256d, CoinbaseBuilder, M4AckBundles};
use miette::{IntoDiagnostic, Result};

use clap::Parser;
use wallet::Wallet;

use crate::cli::Command;

mod cli;
mod wallet;

#[tokio::main]
async fn main() -> Result<()> {
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
                dbg!(&sidechain_acks);
                for sidechain_ack in sidechain_acks {
                    if let Some(sidechain_proposal) =
                        pending_sidechain_proposals.get(&sidechain_ack.sidechain_number)
                    {
                        if sidechain_proposal.data_hash == sidechain_ack.data_hash {
                            dbg!(sidechain_proposal);
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

                let deposits = wallet.get_pending_deposits(None)?;
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
        Command::Mempool => {
            todo!();
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
        Command::GetSidechainProposals => {
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
                let block_height = wallet.get_block_height()?;
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
        Command::GetSidechains => {
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
            let block_height = wallet.get_block_height()?;
            println!("{block_height}");
        }
        Command::GetCtip { sidechain_number } => {
            if let Some((outpoint, value)) = wallet.get_ctip(sidechain_number).await? {
                println!("outpoint: {} value: {}", outpoint, value,);
            } else {
                println!("no ctip");
            }
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
            amount,
            address,
        } => {
            println!(
                "deposit sidechain number: {sidechain_number}, amount: {amount}{}",
                match &address {
                    Some(address) => {
                        format!(", address: {address}")
                    }
                    None => "".to_string(),
                }
            );
            wallet
                .deposit(sidechain_number, amount.to_sat(), &address)
                .await?;
        }
        Command::GetDeposits { sidechain_number } => {
            println!("Pending deposits:");
            let deposits = wallet.get_pending_deposits(Some(sidechain_number))?;
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
            println!("Deposits:");
            wallet.get_deposits(sidechain_number).await?;
        }
        Command::EncodeSidechainAddress { data } => {
            if data.len() == 20 {
                let address = bs58::encode(data).with_check().into_string();
                println!("{address}");
            } else {
                println!(
                    "invalid address length, is is {} bytes, when it must be 20 bytes",
                    data.len()
                );
            }
        }
    }

    Ok(())
}
