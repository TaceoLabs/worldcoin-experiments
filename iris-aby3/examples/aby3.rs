use clap::Parser;
use color_eyre::{eyre::Context, Result};
use iris_aby3::prelude::{Aby3, Aby3Network, IrisMpc, Sharable, Share};
use mpc_net::config::{NetworkConfig, NetworkParty};
use rand::distributions::{Distribution, Standard};
use std::{fs::File, ops::Mul, path::PathBuf};

#[derive(Parser)]
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println0!(args.party, "Setting up network...");

    let parties: Vec<NetworkParty> =
        serde_yaml::from_reader(File::open(args.config_file).context("opening config file")?)
            .context("parsing config file")?;

    let config = NetworkConfig {
        parties,
        my_id: args.party,
        key_path: args.key_file,
    };

    let network = Aby3Network::new(config).await?;

    println0!(args.party, "\t..done\n");

    let protocol = Aby3::new(network);
    let mut iris = IrisMpc::<u16, _>::new(protocol)?;
    print_stats(&iris)?;

    println0!(args.party, "\nPreprocessing...");
    iris.preprocessing().await?;
    println0!(args.party, "\t..done\n");
    print_stats(&iris)?;

    println0!(args.party, "\nFinishing");
    print_stats(&iris)?;
    iris.finish().await?;

    Ok(())
}
