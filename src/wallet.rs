use bdk::bitcoin::opcodes::all::OP_RETURN;
use bdk::bitcoin::{Amount, Network, Txid};
use bdk::blockchain::ElectrumBlockchain;
use bdk::template::Bip84;
use bdk::wallet::AddressIndex;
use bdk::{
    database::SqliteDatabase,
    keys::{DerivableKey, ExtendedKey},
};
use bdk::{KeychainKind, SignOptions, SyncOptions};
use bip300301_enforcer_proto::validator::validator_client::ValidatorClient;
use bip300301_enforcer_proto::validator::{
    GetCtipRequest, GetDepositsRequest, GetSidechainProposalsRequest, GetSidechainsRequest,
};
use bip300301_messages::bitcoin::opcodes::all::{OP_PUSHBYTES_1, OP_PUSHBYTES_36};
use bip300301_messages::bitcoin::opcodes::OP_TRUE;
use bip300301_messages::bitcoin::{Script, Witness};
use bip300301_messages::{CoinbaseBuilder, OP_DRIVECHAIN};
use bip39::{Language, Mnemonic};
use miette::{miette, IntoDiagnostic, Result};
use rusqlite::{Connection, Row};
use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;
use tonic::transport::Channel;
use tonic::IntoRequest;

use rand::prelude::*;

pub struct Wallet {
    main_client: Client,
    enforcer_client: ValidatorClient<Channel>,
    bitcoin_wallet: bdk::Wallet<SqliteDatabase>,
    db_connection: Connection,
    bitcoin_blockchain: ElectrumBlockchain,
}

impl Wallet {
    pub async fn new<P: AsRef<Path>>(datadir: P) -> Result<Self> {
        let network = Network::Regtest; // Or this can be Network::Bitcoin, Network::Signet or Network::Regtest
                                        // Generate fresh mnemonic

        /*
        let mnemonic: GeneratedKey<_, miniscript::Segwitv0> =
                                        Mnemonic::generate((WordCount::Words12, Language::English)).unwrap();
        // Convert mnemonic to string
        let mnemonic_words = mnemonic.to_string();
        // Parse a mnemonic
        let mnemonic = Mnemonic::parse(&mnemonic_words).unwrap();
        */

        let mnemonic = Mnemonic::parse_in_normalized(
            Language::English,
            "betray annual dog current tomorrow media ghost dynamic mule length sure salad",
        )
        .into_diagnostic()?;
        let mnemonic_words = mnemonic.to_string();
        // Generate the extended key
        let xkey: ExtendedKey = mnemonic.into_extended_key().into_diagnostic()?;
        // Get xprv from the extended key
        let xprv = xkey
            .into_xprv(network)
            .ok_or(miette!("couldn't get xprv"))?;

        std::fs::create_dir_all(&datadir).into_diagnostic()?;

        // Create a BDK wallet structure using BIP 84 descriptor ("m/84h/1h/0h/0" and "m/84h/1h/0h/1")
        let bitcoin_wallet = bdk::Wallet::new(
            Bip84(xprv, KeychainKind::External),
            Some(Bip84(xprv, KeychainKind::Internal)),
            network,
            SqliteDatabase::new(datadir.as_ref().join("wallet.sqlite")),
        )
        .into_diagnostic()?;

        let bitcoin_wallet_client =
            bdk::electrum_client::Client::new("127.0.0.1:60401").into_diagnostic()?;
        let bitcoin_blockchain = ElectrumBlockchain::from(bitcoin_wallet_client);

        use rusqlite_migration::{Migrations, M};

        // 1️⃣ Define migrations
        let migrations = Migrations::new(vec![
            M::up(
                "CREATE TABLE sidechain_proposals
                   (number INTEGER NOT NULL,
                    data BLOB NOT NULL,
                    UNIQUE(number, data));",
            ),
            M::up(
                "CREATE TABLE sidechain_acks\
                   (number INTEGER NOT NULl,
                    data_hash BLOB NOT NULL,
                    UNIQUE(number, data_hash));",
            ),
            M::up(
                "CREATE TABLE bundle_proposals
                   (sidechain_number INTEGER NOT NULL,
                    bundle_hash BLOB NOT NULL,
                    UNIQUE(sidechain_number, bundle_hash));",
            ),
            M::up(
                "CREATE TABLE bundle_acks
                   (sidechain_number INTEGER NOT NULL,
                    bundle_hash BLOB NOT NULL,
                    UNIQUE(sidechain_number, bundle_hash));",
            ),
            M::up(
                "CREATE TABLE deposits
                   (sidechain_number INTEGER NOT NULL,
                    address BLOB NOT NULl,
                    amount INTEGER NOT NULL,
                    txid BLOB NOT NULL);",
            ),
            M::up(
                "CREATE TABLE mempool
                   (txid BLOB UNIQUE NOT NULL,
                    tx_data BLOB NOT NULL);",
            ),
        ]);

        let mut db_connection =
            Connection::open(datadir.as_ref().join("db.sqlite")).into_diagnostic()?;

        migrations.to_latest(&mut db_connection).into_diagnostic()?;

        let enforcer_client = ValidatorClient::connect("http://[::1]:50051")
            .await
            .into_diagnostic()?;

        let main_datadir = Path::new("../../data/bitcoin/");
        let main_client = create_client(main_datadir)?;
        Ok(Self {
            main_client,
            enforcer_client,
            bitcoin_wallet,
            db_connection,
            bitcoin_blockchain,
        })
    }

    pub fn get_block_height(&self) -> Result<u32> {
        let block_height: u32 = self
            .main_client
            .send_request("getblockcount", &[])
            .into_diagnostic()?
            .ok_or(miette!("failed to get block count"))?;
        Ok(block_height)
    }

    pub async fn generate_block(
        &self,
        coinbase_outputs: &[TxOut],
        transactions: Vec<Transaction>,
    ) -> Result<Block> {
        let addr = self
            .bitcoin_wallet
            .get_address(AddressIndex::New)
            .into_diagnostic()?;
        let script_pubkey = addr.script_pubkey();
        let block_height = self.get_block_height()?;
        println!("Block height: {block_height}");
        let block_hash: String = self
            .main_client
            .send_request("getblockhash", &[json!(block_height)])
            .into_diagnostic()?
            .ok_or(miette!("failed to get block hash"))?;
        let prev_blockhash = BlockHash::from_str(&block_hash).into_diagnostic()?;

        let start = SystemTime::now();
        let time = start
            .duration_since(UNIX_EPOCH)
            .into_diagnostic()?
            .as_secs() as u32;

        let script_sig = bitcoin::blockdata::script::Builder::new()
            .push_int((block_height + 1) as i64)
            .push_opcode(OP_0)
            .into_script();
        let value = get_block_value(block_height + 1, 0, Network::Regtest);

        let output = if value > 0 {
            vec![TxOut {
                script_pubkey,
                value,
            }]
        } else {
            vec![TxOut {
                script_pubkey: ScriptBuf::builder().push_opcode(OP_RETURN).into_script(),
                value: 0,
            }]
        };

        const WITNESS_RESERVED_VALUE: [u8; 32] = [0; 32];

        let txdata = [
            vec![Transaction {
                version: 2,
                lock_time: LockTime::Blocks(Height::ZERO),
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::all_zeros(),
                        vout: 0xFFFF_FFFF,
                    },
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[WITNESS_RESERVED_VALUE]),
                    script_sig,
                }],
                output: [&output, coinbase_outputs].concat(),
            }],
            transactions,
        ]
        .concat();

        let genesis_block = genesis_block(bitcoin::Network::Regtest);
        let bits = genesis_block.header.bits;
        let header = bitcoin::block::Header {
            version: Version::NO_SOFT_FORK_SIGNALLING,
            prev_blockhash,
            // merkle root is computed after the witness commitment is added to coinbase
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits,
            nonce: 0,
        };
        let mut block = Block { header, txdata };
        let witness_root = block.witness_root().unwrap();
        let witness_commitment =
            Block::compute_witness_commitment(&witness_root, &WITNESS_RESERVED_VALUE);

        let script_pubkey_bytes = [
            vec![OP_RETURN.to_u8(), OP_PUSHBYTES_36.to_u8()],
            vec![0xaa, 0x21, 0xa9, 0xed],
            witness_commitment.as_byte_array().into(),
        ]
        .concat();
        let script_pubkey = ScriptBuf::from_bytes(script_pubkey_bytes);
        dbg!(&script_pubkey);
        block.txdata[0].output.push(TxOut {
            script_pubkey,
            value: 0,
        });
        let mut tx_hashes: Vec<_> = block.txdata.iter().map(Transaction::txid).collect();
        block.header.merkle_root = merkle_tree::calculate_root_inline(&mut tx_hashes)
            .unwrap()
            .to_raw_hash()
            .into();
        Ok(block)
    }

    pub async fn mine(
        &self,
        coinbase_outputs: &[TxOut],
        transactions: Vec<Transaction>,
    ) -> Result<()> {
        let mut block = self.generate_block(coinbase_outputs, transactions).await?;
        loop {
            block.header.nonce += 1;
            if block.header.validate_pow(block.header.target()).is_ok() {
                break;
            }
        }
        dbg!(&block);
        let mut block_bytes = vec![];
        block.consensus_encode(&mut block_bytes).into_diagnostic()?;
        let block_hex = hex::encode(block_bytes);

        let _: Option<()> = self
            .main_client
            .send_request("submitblock", &[json!(block_hex)])
            .into_diagnostic()?;
        std::thread::sleep(Duration::from_millis(500));
        Ok(())
    }

    pub fn get_balance(&self) -> Result<()> {
        self.bitcoin_wallet
            .sync(&self.bitcoin_blockchain, SyncOptions::default())
            .into_diagnostic()?;
        let balance = self.bitcoin_wallet.get_balance().into_diagnostic()?;
        let immature = Amount::from_sat(balance.immature);
        let untrusted_pending = Amount::from_sat(balance.untrusted_pending);
        let trusted_pending = Amount::from_sat(balance.trusted_pending);
        let confirmed = Amount::from_sat(balance.confirmed);
        println!("Confirmed: {confirmed}");
        println!("Immature: {immature}");
        println!("Untrusted pending: {untrusted_pending}");
        println!("Trusted pending: {trusted_pending}");
        Ok(())
    }

    pub fn get_utxos(&self) -> Result<()> {
        self.bitcoin_wallet
            .sync(&self.bitcoin_blockchain, SyncOptions::default())
            .into_diagnostic()?;
        let utxos = self.bitcoin_wallet.list_unspent().into_diagnostic()?;
        for utxo in &utxos {
            println!(
                "address: {}, value: {}",
                utxo.txout.script_pubkey, utxo.txout.value
            );
        }
        Ok(())
    }

    pub fn propose_sidechain(&self, sidechain_number: u8, data: &[u8]) -> Result<()> {
        self.db_connection
            .execute(
                "INSERT INTO sidechain_proposals (number, data) VALUES (?1, ?2)",
                (sidechain_number, data),
            )
            .into_diagnostic()?;
        let coinbase = CoinbaseBuilder::new()
            .propose_sidechain(sidechain_number, data)
            .build();

        dbg!(coinbase);

        let data_hash = bip300301_messages::sha256d(data);
        let data_hash = hex::encode(data_hash);

        dbg!(data_hash);
        Ok(())
    }

    pub fn ack_sidechain(&self, sidechain_number: u8, data_hash: &[u8; 32]) -> Result<()> {
        self.db_connection
            .execute(
                "INSERT INTO sidechain_acks (number, data_hash) VALUES (?1, ?2)",
                (sidechain_number, data_hash),
            )
            .into_diagnostic()?;
        Ok(())
    }

    pub fn nack_sidechain(&self, sidechain_number: u8, data_hash: &[u8; 32]) -> Result<()> {
        self.db_connection
            .execute(
                "DELETE FROM sidechain_acks WHERE number = ?1 AND data_hash = ?2",
                (sidechain_number, data_hash),
            )
            .into_diagnostic()?;
        Ok(())
    }

    pub fn get_sidechain_acks(&self) -> Result<Vec<SidechainAck>> {
        let mut statement = self
            .db_connection
            .prepare("SELECT number, data_hash FROM sidechain_acks")
            .into_diagnostic()?;
        let rows = statement
            .query_map([], |row| {
                let data_hash: [u8; 32] = row.get(1)?;
                Ok(SidechainAck {
                    sidechain_number: row.get(0)?,
                    data_hash,
                })
            })
            .into_diagnostic()?;
        let mut acks = vec![];
        for ack in rows {
            let ack = ack.into_diagnostic()?;
            acks.push(ack);
        }
        Ok(acks)
    }

    pub fn delete_sidechain_ack(&self, ack: &SidechainAck) -> Result<()> {
        self.db_connection
            .execute(
                "DELETE FROM sidechain_acks WHERE number = ?1 AND data_hash = ?2",
                (ack.sidechain_number, ack.data_hash),
            )
            .into_diagnostic()?;
        Ok(())
    }

    pub async fn get_pending_sidechain_proposals(
        &mut self,
    ) -> Result<HashMap<u8, bip300301_enforcer_proto::validator::SidechainProposal>> {
        let pending_proposals = self
            .enforcer_client
            .get_sidechain_proposals(GetSidechainProposalsRequest {})
            .await
            .into_diagnostic()?
            .into_inner()
            .sidechain_proposals
            .into_iter()
            .map(|sidechain_proposal| {
                (
                    sidechain_proposal.sidechain_number as u8,
                    sidechain_proposal,
                )
            })
            .collect();
        Ok(pending_proposals)
    }

    pub fn get_sidechain_proposals(&mut self) -> Result<Vec<Sidechain>> {
        let mut statement = self
            .db_connection
            .prepare("SELECT number, data FROM sidechain_proposals")
            .into_diagnostic()?;
        let rows = statement
            .query_map([], |row| {
                let data: Vec<u8> = row.get(1)?;
                Ok(Sidechain {
                    sidechain_number: row.get(0)?,
                    data,
                })
            })
            .into_diagnostic()?;
        let mut proposals = vec![];
        for proposal in rows {
            let proposal = proposal.into_diagnostic()?;
            proposals.push(proposal);
        }

        Ok(proposals)
    }

    pub async fn get_sidechains(&mut self) -> Result<Vec<Sidechain>> {
        let sidechains = self
            .enforcer_client
            .get_sidechains(GetSidechainsRequest {})
            .await
            .into_diagnostic()?
            .into_inner()
            .sidechains
            .into_iter()
            .map(|sidechain| Sidechain {
                sidechain_number: sidechain.sidechain_number as u8,
                data: sidechain.data,
            })
            .collect();
        Ok(sidechains)
    }

    pub async fn get_ctip(&mut self, sidechain_number: u8) -> Result<Option<(OutPoint, u64)>> {
        let request = GetCtipRequest {
            sidechain_number: sidechain_number as u32,
        };
        let ctip = self
            .enforcer_client
            .get_ctip(request)
            .await
            .into_diagnostic()?
            .into_inner()
            .ctip;
        if let Some(ctip) = ctip {
            let txid = bitcoin::Txid::from_slice(&ctip.txid).into_diagnostic()?;
            let vout = ctip.vout;
            let outpoint = OutPoint { txid, vout };
            let value = ctip.value;
            Ok(Some((outpoint, value)))
        } else {
            Ok(None)
        }
    }

    pub fn delete_sidechain_proposals(&self) -> Result<()> {
        self.db_connection
            .execute("DELETE FROM sidechain_proposals;", ())
            .into_diagnostic()?;
        Ok(())
    }

    pub async fn is_sidechain_active(&mut self, sidechain_number: u8) -> Result<bool> {
        let sidechains = self.get_sidechains().await?;
        for sidechain in sidechains {
            if sidechain.sidechain_number == sidechain_number {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn deposit(
        &mut self,
        sidechain_number: u8,
        amount: u64,
        address: &Option<String>,
    ) -> Result<()> {
        if !self.is_sidechain_active(sidechain_number).await? {
            return Err(miette!("sidechain slot {sidechain_number} is not active"));
        }
        let message = [
            OP_DRIVECHAIN.to_u8(),
            OP_PUSHBYTES_1.to_u8(),
            sidechain_number,
            OP_TRUE.to_u8(),
        ];
        let op_drivechain = ScriptBuf::from_bytes(message.into());
        dbg!(&op_drivechain);

        let address = match address {
            Some(address) => bs58::decode(address)
                .with_check(None)
                .into_vec()
                .into_diagnostic()?,
            None => rand::random::<[u8; 20]>().into(),
        };
        if address.len() != 20 {
            return Err(miette!(
                "invalid address length, is is {} bytes, when it must be 20 bytes",
                address.len()
            ));
        }
        let message = [vec![OP_RETURN.to_u8()], address.clone()].concat();
        let address_op_return = ScriptBuf::from_bytes(message);

        let ctip = self.get_ctip(sidechain_number).await?;

        // FIXME: Make this easier to read.
        let ctip_amount = ctip.map(|ctip| ctip.1).unwrap_or(0);

        let mut builder = self.bitcoin_wallet.build_tx();
        builder
            .ordering(bdk::wallet::tx_builder::TxOrdering::Untouched)
            .add_recipient(op_drivechain.clone(), ctip_amount + amount)
            .add_recipient(address_op_return, 0);

        if let Some((ctip_outpoint, _)) = ctip {
            dbg!(ctip_outpoint);

            let transaction_hex: String = self
                .main_client
                .send_request("getrawtransaction", &[json!(ctip_outpoint.txid)])
                .into_diagnostic()?
                .unwrap();
            let transaction_bytes = hex::decode(&transaction_hex).unwrap();
            let mut cursor = Cursor::new(transaction_bytes);
            let transaction = Transaction::consensus_decode(&mut cursor).into_diagnostic()?;
            /*
            let transaction = self
                .bitcoin_wallet
                .get_tx(&ctip_outpoint.txid, true)
                .into_diagnostic()?
                .unwrap();
            */

            builder
                .add_foreign_utxo(
                    ctip_outpoint,
                    bitcoin::psbt::Input {
                        non_witness_utxo: Some(transaction),
                        ..bitcoin::psbt::Input::default()
                    },
                    0,
                )
                .into_diagnostic()?;
        }

        let (mut psbt, _details) = builder.finish().into_diagnostic()?;
        self.bitcoin_wallet
            .sign(&mut psbt, SignOptions::default())
            .into_diagnostic()?;
        let transaction = psbt.extract_tx();
        /*
        transaction.input.push(TxIn {
            previous_output: ctip_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        */

        let mut tx_data = vec![];
        let mut cursor = Cursor::new(&mut tx_data);
        transaction
            .consensus_encode(&mut cursor)
            .into_diagnostic()?;
        self.db_connection
            .execute(
                "INSERT INTO deposits (sidechain_number, address, amount, txid) VALUES (?1, ?2, ?3, ?4)",
                (sidechain_number, address, amount, transaction.txid().as_byte_array()),
            )
            .into_diagnostic()?;
        self.db_connection
            .execute(
                "INSERT INTO mempool (txid, tx_data) VALUES (?1, ?2)",
                (transaction.txid().as_byte_array(), &tx_data),
            )
            .into_diagnostic()?;
        Ok(())
    }

    pub fn delete_deposits(&self) -> Result<()> {
        self.db_connection
            .execute("DELETE FROM deposits;", ())
            .into_diagnostic()?;
        Ok(())
    }

    pub async fn get_deposits(&mut self, sidechain_number: u8) -> Result<()> {
        let deposits = self
            .enforcer_client
            .get_deposits(GetDepositsRequest {
                sidechain_number: sidechain_number as u32,
            })
            .await
            .into_diagnostic()?
            .into_inner()
            .deposits;
        dbg!(deposits);
        Ok(())
    }

    pub fn get_pending_deposits(&self, sidechain_number: Option<u8>) -> Result<Vec<Deposit>> {
        let mut statement = match sidechain_number {
            Some(sidechain_number) => {
                let mut statement = self
                    .db_connection
                    .prepare(
                        "SELECT sidechain_number, address, amount, tx_data
                         FROM deposits INNER JOIN mempool ON deposits.txid = mempool.txid
                         WHERE sidechain_number = ?1;",
                    )
                    .into_diagnostic()?;
                statement
            }
            None => self
                .db_connection
                .prepare(
                    "SELECT sidechain_number, address, amount, tx_data
                     FROM deposits INNER JOIN mempool ON deposits.txid = mempool.txid;",
                )
                .into_diagnostic()?,
        };
        // FIXME: Make this code more sane.
        let func = |row: &Row| {
            let sidechain_number: u8 = row.get(0)?;
            let address: Vec<u8> = row.get(1)?;
            let amount: u64 = row.get(2)?;
            let tx_data: Vec<u8> = row.get(3)?;
            let transaction =
                Transaction::consensus_decode_from_finite_reader(&mut tx_data.as_slice()).unwrap();
            let deposit = Deposit {
                sidechain_number,
                address,
                amount,
                transaction,
            };
            Ok(deposit)
        };
        let rows = match sidechain_number {
            Some(sidechain_number) => statement
                .query_map([sidechain_number], func)
                .into_diagnostic()?,
            None => statement.query_map([], func).into_diagnostic()?,
        };
        let mut deposits = vec![];
        for deposit in rows {
            let deposit = deposit.into_diagnostic()?;
            deposits.push(deposit);
        }
        Ok(deposits)
    }
}

#[derive(Debug)]
pub struct Deposit {
    pub sidechain_number: u8,
    pub address: Vec<u8>,
    pub amount: u64,
    pub transaction: Transaction,
}

#[derive(Debug)]
pub struct Sidechain {
    pub sidechain_number: u8,
    pub data: Vec<u8>,
}

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ureq_jsonrpc::{json, Client};

pub fn create_client(main_datadir: &Path) -> Result<Client> {
    let auth = std::fs::read_to_string(main_datadir.join("regtest/.cookie")).into_diagnostic()?;
    let mut auth = auth.split(":");
    let user = auth
        .next()
        .ok_or(miette!("failed to get rpcuser"))?
        .to_string();
    let password = auth
        .next()
        .ok_or(miette!("failed to get rpcpassword"))?
        .to_string();
    Ok(Client {
        host: "localhost".into(),
        port: 18443,
        user,
        password,
        id: "mainchain".into(),
    })
}

use bdk::bitcoin;
use bdk::bitcoin::constants::SUBSIDY_HALVING_INTERVAL;
use bitcoin::absolute::{Height, LockTime};
use bitcoin::block::Version;
use bitcoin::consensus::Encodable;
use bitcoin::constants::genesis_block;
use bitcoin::hash_types::TxMerkleNode;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::OP_0;
use bitcoin::{consensus::Decodable, Block};
use bitcoin::{merkle_tree, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use std::str::FromStr;

fn get_block_value(height: u32, fees: u64, network: Network) -> u64 {
    let mut subsidy = 50 * Amount::ONE_BTC.to_sat();
    let subsidy_halving_interval = match network {
        Network::Regtest => 150,
        _ => SUBSIDY_HALVING_INTERVAL,
    };
    let halvings = height / subsidy_halving_interval;
    if halvings >= 64 {
        fees
    } else {
        subsidy >>= halvings;
        subsidy + fees
    }
}

#[derive(Debug)]
pub struct SidechainAck {
    pub sidechain_number: u8,
    pub data_hash: [u8; 32],
}
