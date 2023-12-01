use clap::Parser;
use color_eyre::{eyre::Context, Result};
use iris_aby3::prelude::{Aby3, Aby3Network, BitArr, Error, IrisMpc, Sharable, Share};
use mpc_net::config::{NetworkConfig, NetworkParty};
use plain_reference::IRIS_CODE_SIZE;
use rand::distributions::{Distribution, Standard};
use rusqlite::Connection;
use std::{fs::File, ops::Mul, path::PathBuf};

macro_rules! println0  {
    ($id:expr) => {
        if $id == 0 {
            println!();
        }
    };
    ($id:expr, $($arg:tt)*) => {{
        if $id == 0 {
            println!($($arg)*);
        }
    }};

}

#[derive(Parser, Clone)]
struct Args {
    /// The config file path
    #[clap(short, long, value_name = "FILE")]
    config_file: PathBuf,

    /// The path to the .der key file for our certificate
    #[clap(short, long, value_name = "FILE")]
    key_file: PathBuf,

    /// The If of our party in the config
    #[clap(short, long, value_name = "ID")]
    party: usize,

    /// path to the database file to store stuff in
    #[arg(short, long, value_name = "FILE", required = true)]
    database: PathBuf,

    /// Set to true if a image should be generated that matches an element in the database
    #[arg(short, long, default_value = "false")]
    should_match: bool,
}

fn print_stats<T: Sharable>(iris: &IrisMpc<T, Aby3<Aby3Network>>) -> Result<()>
where
    Share<T>: Mul<T::Share, Output = Share<T>>,
    <T as std::convert::TryFrom<usize>>::Error: std::fmt::Debug,
    Standard: Distribution<T::Share>,
{
    let id = iris.get_id();
    if id == 0 {
        println!("Stats: party {}", id);
        iris.print_connection_stats(&mut std::io::stdout())?;
    }
    Ok(())
}

async fn setup_network(args: Args) -> Result<Aby3Network> {
    let parties: Vec<NetworkParty> =
        serde_yaml::from_reader(File::open(args.config_file).context("opening config file")?)
            .context("parsing config file")?;

    let config = NetworkConfig {
        parties,
        my_id: args.party,
        key_path: args.key_file,
    };

    let network = Aby3Network::new(config).await?;

    Ok(network)
}

struct SharedDB<T: Sharable> {
    shares: Vec<Vec<Share<T>>>,
    masks: Vec<BitArr>,
}

fn read_db<T: Sharable>(args: Args) -> Result<SharedDB<T>> {
    let database_file = args.database;

    fn open_database(database_file: &PathBuf) -> Result<Connection> {
        let conn = Connection::open(database_file)?;
        // Additional setup or configuration for the database connection can be done here
        Ok(conn)
    }

    let conn = open_database(&database_file)?;

    // read the codes from the database using rusqlite and iterate over them
    let mut stmt = match args.party {
        0 => conn.prepare("SELECT share_a, share_c, mask from iris_codes;")?,
        1 => conn.prepare("SELECT share_b, share_a, mask from iris_codes;")?,
        2 => conn.prepare("SELECT share_c, share_b, mask from iris_codes;")?,
        i => Err(Error::IdError(i))?,
    };

    let mut res = SharedDB::<T> {
        shares: Vec::new(),
        masks: Vec::new(),
    };

    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        let mut mask = BitArr::default();
        mask.as_raw_mut_slice()
            .copy_from_slice(&row.get::<_, Vec<u8>>(2)?);
        let share_a: Vec<T::Share> = bincode::deserialize(&row.get::<_, Vec<u8>>(0)?)?;
        let share_b: Vec<T::Share> = bincode::deserialize(&row.get::<_, Vec<u8>>(1)?)?;

        if share_a.len() != IRIS_CODE_SIZE
            || share_b.len() != IRIS_CODE_SIZE
            || mask.len() != IRIS_CODE_SIZE
        {
            Err(Error::InvlidCodeSizeError)?;
        }
        let mut share = Vec::with_capacity(IRIS_CODE_SIZE);
        for (a, b) in share_a.into_iter().zip(share_b) {
            share.push(Share::new(a, b));
        }

        res.shares.push(share);
        res.masks.push(mask);
    }

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let id = args.party;

    println0!(id, "Reading database:");
    let db = read_db::<u16>(args.to_owned())?;
    println0!(id, "...done\n");

    println0!(id, "Setting up network:");
    let network = setup_network(args).await?;
    println0!(id, "...done\n");

    println0!(id, "\nInitialize protocol:");
    let protocol = Aby3::new(network);
    let mut iris = IrisMpc::<u16, _>::new(protocol)?;
    println0!(id, "...done\n");
    print_stats(&iris)?;

    println0!(id, "\nPreprocessing:");
    iris.preprocessing().await?;
    println0!(id, "...done\n");
    print_stats(&iris)?;

    println0!(id, "\nFinishing:\n");
    print_stats(&iris)?;
    iris.finish().await?;

    Ok(())
}
