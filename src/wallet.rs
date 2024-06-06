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
    GetCtipRequest, GetSidechainProposalsRequest, GetSidechainsRequest,
};
use bip300301_messages::bitcoin::opcodes::all::{OP_PUSHBYTES_1, OP_PUSHBYTES_36};
use bip300301_messages::bitcoin::opcodes::OP_TRUE;
use bip300301_messages::bitcoin::{Script, Witness};
use bip300301_messages::{CoinbaseBuilder, OP_DRIVECHAIN};
use bip39::{Language, Mnemonic};
use miette::{miette, IntoDiagnostic, Result};
use rusqlite::Connection;
use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;
use tonic::transport::Channel;
use tonic::IntoRequest;

pub struct Wallet {
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

        let db_connection =
            Connection::open(datadir.as_ref().join("db.sqlite")).into_diagnostic()?;

        // Use migrations library for this.
        // Use rusqlite_serde.
        {
            let number_of_tables = db_connection.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| {let number: usize = row.get(0)?; Ok(number)}).into_diagnostic()?;
            if number_of_tables == 0 {
                db_connection.execute(
                    "CREATE TABLE sidechain_proposals (number INTEGER NOT NULL, data BLOB NOT NULL, UNIQUE(number, data));",())
                    .into_diagnostic()?;
                db_connection.execute(
                    "CREATE TABLE sidechain_acks (number INTEGER NOT NULl, data_hash BLOB NOT NULL, UNIQUE(number, data_hash));",())
                    .into_diagnostic()?;
                db_connection.execute(
                    "CREATE TABLE bundle_proposals (sidechain_number INTEGER NOT NULL, bundle_hash BLOB NOT NULL, UNIQUE(sidechain_number, bundle_hash));", ())
                    .into_diagnostic()?;
                db_connection.execute(
                    "CREATE TABLE bundle_acks (sidechain_number INTEGER NOT NULL, bundle_hash BLOB NOT NULL, UNIQUE(sidechain_number, bundle_hash));", ())
                    .into_diagnostic()?;
                db_connection
                    .execute(
                        "CREATE TABLE deposits (sidechain_number INTEGER NOT NULL, address BLOB NOT NULl, amount INTEGER NOT NULL, txid BLOB UNIQUE NOT NULL, transaction_bytes BLOB NOT NULL);",
                        (),
                    )
                    .into_diagnostic()?;
            }
        }

        let enforcer_client = ValidatorClient::connect("http://[::1]:50051")
            .await
            .into_diagnostic()?;

        Ok(Self {
            enforcer_client,
            bitcoin_wallet,
            db_connection,
            bitcoin_blockchain,
        })
    }

    pub async fn mine(
        &self,
        coinbase_outputs: &[TxOut],
        transactions: Vec<Transaction>,
    ) -> Result<()> {
        let main_datadir = Path::new("../../data/bitcoin/");
        let client = create_client(main_datadir)?;
        let addr = self
            .bitcoin_wallet
            .get_address(AddressIndex::New)
            .into_diagnostic()?;
        submit_block(
            &client,
            addr.script_pubkey(),
            coinbase_outputs,
            transactions,
        )
        .await?;
        std::thread::sleep(Duration::from_millis(500));

        /*
        let addr1 = wallet.get_address(AddressIndex::New).into_diagnostic()?;
        let addr2 = wallet.get_address(AddressIndex::New).into_diagnostic()?;
        let (mut psbt1, details) = {
            let mut builder = wallet.build_tx();
            builder
                .ordering(TxOrdering::Untouched)
                .add_recipient(addr1.script_pubkey(), 50_000)
                .add_recipient(addr2.script_pubkey(), 50_000);
            builder.finish().into_diagnostic()?
        };
        // dbg!(psbt1);
        // dbg!(details);
        // dbg!(psbt1.clone().extract_tx());

        let finalized = wallet
            .sign(&mut psbt1, SignOptions::default())
            .into_diagnostic()?;

        assert!(finalized, "we should have signed all the inputs");
        */

        // dbg!(psbt1.extract_tx());

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

    pub async fn get_ctip(&mut self, sidechain_number: u8) -> Result<(OutPoint, u64)> {
        let request = GetCtipRequest {
            sidechain_number: sidechain_number as u32,
        };
        let ctip = self
            .enforcer_client
            .get_ctip(request)
            .await
            .into_diagnostic()?
            .into_inner();
        let txid = bitcoin::Txid::from_slice(&ctip.txid).into_diagnostic()?;
        let vout = ctip.vout;
        let outpoint = OutPoint { txid, vout };
        let value = ctip.value;
        Ok((outpoint, value))
    }

    pub fn delete_sidechain_proposals(&self) -> Result<()> {
        self.db_connection
            .execute("DELETE FROM sidechain_proposals;", ())
            .into_diagnostic()?;
        Ok(())
    }

    pub async fn deposit(
        &mut self,
        sidechain_number: u8,
        address: &str,
        amount: u64,
    ) -> Result<()> {
        let (ctip_outpoint, ctip_amount) = self.get_ctip(sidechain_number).await?;
        let message = [
            OP_DRIVECHAIN.to_u8(),
            OP_PUSHBYTES_1.to_u8(),
            sidechain_number,
            OP_TRUE.to_u8(),
        ];
        let op_drivechain = ScriptBuf::from_bytes(message.into());
        dbg!(&op_drivechain);

        let address = bs58::decode(address)
            .with_check(None)
            .into_vec()
            .into_diagnostic()?;
        let message = [vec![OP_RETURN.to_u8()], address.clone()].concat();
        let address_op_return = ScriptBuf::from_bytes(message);

        let transaction = self
            .bitcoin_wallet
            .get_tx(&ctip_outpoint.txid, true)
            .into_diagnostic()?
            .unwrap();

        let mut builder = self.bitcoin_wallet.build_tx();
        builder
            .ordering(bdk::wallet::tx_builder::TxOrdering::Untouched)
            .add_recipient(op_drivechain.clone(), ctip_amount + amount)
            .add_recipient(address_op_return, 0)
            .add_foreign_utxo(
                ctip_outpoint,
                bitcoin::psbt::Input {
                    non_witness_utxo: Some(transaction.transaction.unwrap()),
                    ..bitcoin::psbt::Input::default()
                },
                0,
            )
            .into_diagnostic()?;

        let (mut psbt, details) = builder.finish().into_diagnostic()?;
        self.bitcoin_wallet
            .sign(&mut psbt, SignOptions::default())
            .into_diagnostic()?;
        let mut transaction = psbt.extract_tx();
        /*
        transaction.input.push(TxIn {
            previous_output: ctip_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        */

        let mut transaction_bytes = vec![];
        let mut cursor = Cursor::new(&mut transaction_bytes);
        transaction
            .consensus_encode(&mut cursor)
            .into_diagnostic()?;
        self.db_connection
            .execute(
                "INSERT INTO deposits (sidechain_number, address, amount, txid, transaction_bytes) VALUES (?1, ?2, ?3, ?4, ?5)",
                (sidechain_number, address, amount, transaction.txid().as_byte_array(), &transaction_bytes),
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

    pub fn get_deposits(&self, sidechain_number: Option<u8>) -> Result<Vec<Deposit>> {
        let mut statement = match sidechain_number {
            Some(sidechain_number) => {
                let mut statement = self
            .db_connection
            .prepare("SELECT sidechain_number, address, amount, transaction_bytes FROM deposits WHERE sidechain_number = ?1;").into_diagnostic()?;
                statement.execute([sidechain_number]);
                statement
            }
            None => self
                .db_connection
                .prepare(
                    "SELECT sidechain_number, address, amount, transaction_bytes FROM deposits;",
                )
                .into_diagnostic()?,
        };
        let rows = statement
            .query_map([], |row| {
                let sidechain_number: u8 = row.get(0)?;
                let address: Vec<u8> = row.get(1)?;
                let amount: u64 = row.get(2)?;
                let transaction_bytes: Vec<u8> = row.get(3)?;
                let transaction = Transaction::consensus_decode_from_finite_reader(
                    &mut transaction_bytes.as_slice(),
                )
                .unwrap();
                let deposit = Deposit {
                    sidechain_number,
                    address,
                    amount,
                    transaction,
                };
                Ok(deposit)
            })
            .into_diagnostic()?;
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
use bitcoin::absolute::{Height, LockTime};
use bitcoin::block::Version;
use bitcoin::consensus::Encodable;
use bitcoin::constants::genesis_block;
use bitcoin::hash_types::TxMerkleNode;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::OP_0;
use bitcoin::{consensus::Decodable, Block};
use bitcoin::{
    merkle_tree, Address, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Target,
    Transaction, TxIn, TxOut,
};
use std::str::FromStr;

async fn submit_block(
    main_client: &Client,
    script_pubkey: ScriptBuf,
    coinbase_outputs: &[TxOut],
    transactions: Vec<Transaction>,
) -> Result<()> {
    let block_height: u32 = main_client
        .send_request("getblockcount", &[])
        .into_diagnostic()?
        .ok_or(miette!("failed to get block count"))?;
    println!("Block height: {block_height}");
    let block_hash: String = main_client
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
    loop {
        block.header.nonce += 1;
        if block.header.validate_pow(header.target()).is_ok() {
            break;
        }
    }
    dbg!(&block);
    let mut block_bytes = vec![];
    block.consensus_encode(&mut block_bytes).into_diagnostic()?;
    let block_hex = hex::encode(block_bytes);

    let _: Option<()> = main_client
        .send_request("submitblock", &[json!(block_hex)])
        .into_diagnostic()?;
    Ok(())
}

use bdk::bitcoin::constants::SUBSIDY_HALVING_INTERVAL;

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

pub struct SidechainAck {
    pub sidechain_number: u8,
    pub data_hash: [u8; 32],
}
