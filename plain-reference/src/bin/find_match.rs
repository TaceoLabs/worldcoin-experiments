use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::Result;
use plain_reference::IrisCode;
use rand::distributions::{Bernoulli, Distribution};
use rusqlite::Connection;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// path to the database file to store stuff in
    #[arg(short, long, value_name = "FILE", required = true)]
    database: PathBuf,

    /// Set to true if a image should be generated that matches an element in the database
    #[arg(short, long, default_value = "false")]
    should_match: bool,
}

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();

    let database_file = opts.database;

    fn open_database(database_file: &PathBuf) -> Result<Connection> {
        let conn = Connection::open(database_file)?;
        // Additional setup or configuration for the database connection can be done here
        Ok(conn)
    }

    let conn = open_database(&database_file)?;

    let code_to_compare_to = if opts.should_match {
        // read the codes from the database using rusqlite and iterate over them
        conn.query_row("SELECT code, mask from iris_codes LIMIT 1;", [], |row| {
            let mut res = IrisCode::default();
            res.code
                .as_raw_mut_slice()
                .copy_from_slice(&row.get::<_, Vec<u8>>(0)?);
            res.mask
                .as_raw_mut_slice()
                .copy_from_slice(&row.get::<_, Vec<u8>>(1)?);
            // flip a few bits in mask and code (like 5%)
            let dist = Bernoulli::new(0.05).unwrap();
            for i in 0..IrisCode::IRIS_CODE_SIZE {
                if dist.sample(&mut rand::thread_rng()) {
                    res.code.flip_bit(i);
                }
                if dist.sample(&mut rand::thread_rng()) {
                    res.mask.flip_bit(i);
                }
            }

            Ok(res)
        })?
    } else {
        IrisCode::random()
    };

    // read the codes from the database using rusqlite and iterate over them
    let mut stmt = conn.prepare("SELECT code, mask from iris_codes;")?;

    let codes = stmt.query_map([], |row| {
        let mut res = IrisCode::default();
        res.code
            .as_raw_mut_slice()
            .copy_from_slice(&row.get::<_, Vec<u8>>(0)?);
        res.mask
            .as_raw_mut_slice()
            .copy_from_slice(&row.get::<_, Vec<u8>>(1)?);
        Ok(res)
    })?;

    let mut result = false;

    for code in codes {
        result |= code?.is_close(&code_to_compare_to);
    }

    if result {
        println!("Found a match!");
    } else {
        println!("No match found");
    }

    Ok(())
}
