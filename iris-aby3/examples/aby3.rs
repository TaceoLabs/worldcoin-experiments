use clap::Parser;
use color_eyre::{eyre::Context, Result};
use iris_aby3::prelude::{Aby3, Aby3Network, Error, IrisMpc, MpcTrait, Sharable, Share};
use mpc_net::config::{NetworkConfig, NetworkParty};
use plain_reference::{IrisCode, IrisCodeArray};
use rand::{
    distributions::{Distribution, Standard},
    rngs::SmallRng,
    SeedableRng,
};
use rusqlite::Connection;
use std::{fs::File, ops::Mul, path::PathBuf};
use tokio::time::Instant;

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

    /// seed to generate the iris code to match
    #[arg(short, long, value_name = "seed", required = true)]
    iris_seed: u64,

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

#[derive(Default)]
struct SharedDB<T: Sharable> {
    shares: Vec<Vec<Share<T>>>,
    masks: Vec<IrisCodeArray>,
}

#[derive(Default)]
struct SharedIris<T: Sharable> {
    shares: Vec<Share<T>>,
    mask: IrisCodeArray,
}

fn open_database(database_file: &PathBuf) -> Result<Connection> {
    let conn = Connection::open(database_file)?;
    // Additional setup or configuration for the database connection can be done here
    Ok(conn)
}

fn read_db<T: Sharable>(args: Args) -> Result<SharedDB<T>> {
    let conn = open_database(&args.database)?;

    // read the codes from the database using rusqlite and iterate over them
    let mut stmt = match args.party {
        0 => conn.prepare("SELECT share_a, share_c, mask from iris_codes;")?,
        1 => conn.prepare("SELECT share_b, share_a, mask from iris_codes;")?,
        2 => conn.prepare("SELECT share_c, share_b, mask from iris_codes;")?,
        i => Err(Error::IdError(i))?,
    };

    let mut res = SharedDB::<T>::default();
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        let mut mask = IrisCodeArray::default();
        mask.as_raw_mut_slice()
            .copy_from_slice(&row.get::<_, Vec<u8>>(2)?);
        let share_a: Vec<T::Share> = bincode::deserialize(&row.get::<_, Vec<u8>>(0)?)?;
        let share_b: Vec<T::Share> = bincode::deserialize(&row.get::<_, Vec<u8>>(1)?)?;

        if share_a.len() != IrisCode::IRIS_CODE_SIZE || share_b.len() != IrisCode::IRIS_CODE_SIZE {
            Err(Error::InvlidCodeSizeError)?;
        }
        let mut share = Vec::with_capacity(IrisCode::IRIS_CODE_SIZE);
        for (a, b) in share_a.into_iter().zip(share_b) {
            share.push(Share::new(a, b));
        }

        res.shares.push(share);
        res.masks.push(mask);
    }

    Ok(res)
}

fn get_iris_share<T: Sharable>(args: Args) -> Result<SharedIris<T>>
where
    Share<T>: Mul<T::Share, Output = Share<T>>,
    Standard: Distribution<T::Share>,
{
    let mut rng = SmallRng::seed_from_u64(args.iris_seed);
    let iris = if args.should_match {
        let conn = open_database(&args.database)?;
        // read the codes from the database using rusqlite and iterate over them
        conn.query_row(
            "SELECT code, mask from iris_codes WHERE id = 1;",
            [],
            |row| {
                let mut res = IrisCode::default();
                res.code
                    .as_raw_mut_slice()
                    .copy_from_slice(&row.get::<_, Vec<u8>>(0)?);
                res.mask
                    .as_raw_mut_slice()
                    .copy_from_slice(&row.get::<_, Vec<u8>>(1)?);

                res = res.get_similar_iris(&mut rng);

                Ok(res)
            },
        )?
    } else {
        IrisCode::random_rng(&mut rng)
    };

    let mut res = SharedIris::<T>::default();
    res.mask
        .as_raw_mut_slice()
        .copy_from_slice(iris.mask.as_raw_slice());

    for i in 0..IrisCode::IRIS_CODE_SIZE {
        // We simulate the parties already knowing the shares of the code.
        let shares = Aby3::<Aby3Network>::share(T::from(iris.code.get_bit(i)), &mut rng);
        if args.party > 2 {
            Err(Error::IdError(args.party))?;
        }
        res.shares.push(shares[args.party].to_owned());
    }

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let id = args.party;

    println0!(id, "Reading database:");
    let start = Instant::now();
    let db = read_db::<u16>(args.to_owned())?;
    let duration = start.elapsed();
    println0!(id, "...done, took {} ms\n", duration.as_millis());

    println0!(id, "Get shares:");
    let start = Instant::now();
    let shares = get_iris_share::<u16>(args.to_owned())?;
    let duration = start.elapsed();
    println0!(id, "...done, took {} ms\n", duration.as_millis());

    println0!(id, "Setting up network:");
    let start = Instant::now();
    let network = setup_network(args.to_owned()).await?;
    let duration = start.elapsed();
    println0!(id, "...done, took {} ms\n", duration.as_millis());

    println0!(id, "\nInitialize protocol:");
    let start = Instant::now();
    let protocol = Aby3::new(network);
    let mut iris = IrisMpc::<u16, _>::new(protocol)?;
    let duration = start.elapsed();
    println0!(id, "...done, took {} ms\n", duration.as_millis());
    print_stats(&iris)?;

    println0!(id, "\nPreprocessing:");
    let start = Instant::now();
    iris.preprocessing().await?;
    let duration = start.elapsed();
    println0!(id, "...done, took {} ms\n", duration.as_millis());
    print_stats(&iris)?;

    println0!(id, "\nMPC matching:");
    let start = Instant::now();
    let res = iris
        .iris_in_db(shares.shares, &db.shares, &shares.mask, &db.masks)
        .await?;
    let duration = start.elapsed();
    println0!(id, "...done, took {} ms", duration.as_millis());
    println0!(id, "Result is {res}\n");
    print_stats(&iris)?;

    if args.should_match && !res {
        println0!(id, "ERROR: should match but doesn't");
    }

    iris.finish().await?;

    Ok(())
}