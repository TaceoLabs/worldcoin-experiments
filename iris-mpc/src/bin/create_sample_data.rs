use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::{Report, Result};
use iris_mpc::prelude::{Aby3, Aby3Network, MpcTrait, Swift3, Swift3Network};
use plain_reference::IrisCode;
use rand::{rngs::SmallRng, SeedableRng};
use rusqlite::Connection;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// path to the database file to store stuff in
    #[arg(short, long, value_name = "FILE", required = true)]
    database: PathBuf,

    /// MPC protocol for which the database is generated
    #[arg(short, long, value_name = "MPC", required = true)]
    mpc: String,

    /// number of items to generate
    #[arg(short, long, value_name = "NUM", required = true)]
    items: u32,
}

fn open_database(database_file: &PathBuf) -> Result<Connection> {
    let conn = Connection::open(database_file)?;
    // Additional setup or configuration for the database connection can be done here
    Ok(conn)
}

fn create_aby3_db(opts: Opts) -> Result<()> {
    let database_file = opts.database;
    let num_items = opts.items;

    let mut conn = open_database(&database_file)?;

    // Create the table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS iris_codes (
            id INTEGER PRIMARY KEY,
            code BLOB NOT NULL,
            mask BLOB NOT NULL,
            share_a BLOB NOT NULL,
            share_b BLOB NOT NULL,
            share_c BLOB NOT NULL
        )",
        rusqlite::params![],
    )?;

    let mut rng = SmallRng::from_entropy();

    let mut codes = Vec::with_capacity(num_items as usize);
    for _ in 0..num_items {
        let code = IrisCode::random_rng(&mut rng);
        codes.push(code);
    }

    // Insert the codes into the database
    let transaction = conn.transaction()?;
    let mut stmt = transaction.prepare("INSERT INTO iris_codes (code, mask, share_a, share_b, share_c) VALUES (?1, ?2, ?3, ?4, ?5)")?;

    for code in codes {
        let mut shared_code_a = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        let mut shared_code_b = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        let mut shared_code_c = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        for i in 0..IrisCode::IRIS_CODE_SIZE {
            // We simulate the parties already knowing the shares of the code.
            let shares = Aby3::<Aby3Network>::share(u16::from(code.code.get_bit(i)), &mut rng);
            shared_code_a.push(shares[0].to_owned().get_a());
            shared_code_b.push(shares[1].to_owned().get_a());
            shared_code_c.push(shares[2].to_owned().get_a());
        }

        let data_a = bincode::serialize(&shared_code_a)?;
        let data_b = bincode::serialize(&shared_code_b)?;
        let data_c = bincode::serialize(&shared_code_c)?;

        stmt.execute([
            code.code.as_raw_slice(),
            code.mask.as_raw_slice(),
            &data_a,
            &data_b,
            &data_c,
        ])?;
    }
    drop(stmt);
    transaction.commit()?;

    Ok(())
}

fn create_swift3_db(opts: Opts) -> Result<()> {
    let database_file = opts.database;
    let num_items = opts.items;

    let mut conn = open_database(&database_file)?;

    // Create the table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS iris_codes (
            id INTEGER PRIMARY KEY,
            code BLOB NOT NULL,
            mask BLOB NOT NULL,
            share_a BLOB NOT NULL,
            share_b BLOB NOT NULL,
            share_c BLOB NOT NULL,
            share_d BLOB NOT NULL
        )",
        rusqlite::params![],
    )?;

    let mut rng = SmallRng::from_entropy();

    let mut codes = Vec::with_capacity(num_items as usize);
    for _ in 0..num_items {
        let code = IrisCode::random_rng(&mut rng);
        codes.push(code);
    }

    // Insert the codes into the database
    let transaction = conn.transaction()?;
    let mut stmt = transaction.prepare("INSERT INTO iris_codes (code, mask, share_a, share_b, share_c, share_d) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?;

    for code in codes {
        let mut shared_code_a = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        let mut shared_code_b = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        let mut shared_code_c = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        let mut shared_code_d = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        for i in 0..IrisCode::IRIS_CODE_SIZE {
            // We simulate the parties already knowing the shares of the code.
            let shares = Swift3::<Swift3Network>::share(u16::from(code.code.get_bit(i)), &mut rng);
            let (a, d) = shares[0].to_owned().get_ac();
            shared_code_a.push(a);
            shared_code_b.push(shares[1].to_owned().get_a());
            shared_code_c.push(shares[2].to_owned().get_a());
            shared_code_d.push(d);
        }

        let data_a = bincode::serialize(&shared_code_a)?;
        let data_b = bincode::serialize(&shared_code_b)?;
        let data_c = bincode::serialize(&shared_code_c)?;
        let data_d = bincode::serialize(&shared_code_d)?;

        stmt.execute([
            code.code.as_raw_slice(),
            code.mask.as_raw_slice(),
            &data_a,
            &data_b,
            &data_c,
            &data_d,
        ])?;
    }
    drop(stmt);
    transaction.commit()?;

    Ok(())
}

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    let prot = opts.mpc.to_lowercase();

    if prot == "aby3" {
        create_aby3_db(opts)
    } else if prot == "swift3" {
        create_swift3_db(opts)
    } else {
        Err(Report::msg("Invalid MPC protocol specified"))
    }
}
