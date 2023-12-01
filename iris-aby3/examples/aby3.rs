use clap::Parser;
use color_eyre::{eyre::Context, Result};
use iris_aby3::prelude::{Aby3, Aby3Network, IrisMpc};
use mpc_net::config::{NetworkConfig, NetworkParty};
use std::{fs::File, path::PathBuf};

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let parties: Vec<NetworkParty> =
        serde_yaml::from_reader(File::open(args.config_file).context("opening config file")?)
            .context("parsing config file")?;

    let config = NetworkConfig {
        parties,
        my_id: args.party,
        key_path: args.key_file,
    };

    let network = Aby3Network::new(config).await?;
    let protocol = Aby3::new(network);
    let mut iris = IrisMpc::<u16, _>::new(protocol)?;
    iris.preprocessing().await?;

    if args.party == 0 {
        println!("Stats: party 0");
        iris.print_connection_stats(&mut std::io::stdout())?;
    }
    iris.finish().await?;

    Ok(())
}
