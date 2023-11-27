use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::Result;
use plain_reference::IrisCode;
use rusqlite::Connection;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// path to the database file to store stuff in
    #[arg(short, long, value_name = "FILE", required = true)]
    database: PathBuf,

    /// number of items to generate
    #[arg(short, long, value_name = "NUM", required = true)]
    items: u32,
}

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();

    let database_file = opts.database;
    let num_items = opts.items;

    fn open_database(database_file: &PathBuf) -> Result<Connection> {
        let conn = Connection::open(database_file)?;
        // Additional setup or configuration for the database connection can be done here
        Ok(conn)
    }

    let mut conn = open_database(&database_file)?;

    // Create the table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS iris_codes (
            id INTEGER PRIMARY KEY,
            code BLOB NOT NULL,
            mask BLOB NOT NULL
        )",
        rusqlite::params![],
    )?;

    let mut codes = Vec::with_capacity(num_items as usize);
    for _ in 0..num_items {
        let code = IrisCode::random();
        codes.push(code);
    }

    // Insert the codes into the database
    let transaction = conn.transaction()?;
    let mut stmt = transaction.prepare("INSERT INTO iris_codes (code, mask) VALUES (?1, ?2)")?;
    for code in codes {
        stmt.execute([code.code.as_raw_slice(), code.mask.as_raw_slice()])?;
    }
    drop(stmt);
    transaction.commit()?;

    Ok(())
}
