use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use channel::Channel;
use color_eyre::eyre::{self, Context, Report};
use config::NetworkConfig;
use quinn::{ClientConfig, Connection, RecvStream, SendStream};
use rustls::{Certificate, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod channel;
pub mod config;

#[derive(Debug)]
pub struct MpcNetworkHandler {
    connections: HashMap<usize, Connection>,
    my_id: usize,
}

impl MpcNetworkHandler {
    pub async fn establish(config: NetworkConfig) -> Result<Self, Report> {
        config.check_config()?;
        // a client socket, let the OS pick the port
        let local_client_socket = SocketAddr::from(([0, 0, 0, 0], 0));
        let certs: HashMap<usize, Certificate> = config
            .parties
            .iter()
            .map(|p| {
                let cert = std::fs::read(&p.cert_path)
                    .with_context(|| format!("reading certificate of party {}", p.id))?;
                Ok((p.id, Certificate(cert)))
            })
            .collect::<Result<_, Report>>()?;

        let mut root_store = rustls::RootCertStore::empty();
        for (id, cert) in &certs {
            root_store
                .add(cert)
                .with_context(|| format!("adding certificate for party {} to root store", id))?;
        }
        let crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let client_config = ClientConfig::new(Arc::new(crypto));

        let key = PrivateKey(std::fs::read(config.key_path).context("reading own key file")?);
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![certs[&config.my_id].clone()], key)
                .context("creating our server config")?;
        let our_socket_addr = config
            .parties
            .iter()
            .find(|p| p.id == config.my_id)
            .map(|p| p.socket_addr)
            .expect("we are in the list of parties, so we should have a socket address");

        let server_endpoint = quinn::Endpoint::server(server_config.clone(), our_socket_addr)?;

        let mut connections = HashMap::with_capacity(config.parties.len());

        for party in config.parties {
            if party.id == config.my_id {
                // skip self
                continue;
            }
            if party.id < config.my_id {
                // connect to party, we are client
                let endpoint = quinn::Endpoint::client(local_client_socket)
                    .with_context(|| format!("creating client endpoint to party {}", party.id))?;
                let conn = endpoint
                    .connect_with(client_config.clone(), party.socket_addr, &party.dns_name)
                    .with_context(|| {
                        format!("setting up client connection with party {}", party.id)
                    })?
                    .await
                    .with_context(|| format!("connecting as a client to party {}", party.id))?;
                let mut uni = conn.open_uni().await?;
                uni.write_u32(u32::try_from(config.my_id).expect("party id fits into u32"))
                    .await?;
                uni.finish().await?;
                assert!(connections.insert(party.id, conn).is_none());
            } else {
                // we are the server, accept a connection
                if let Some(maybe_conn) = server_endpoint.accept().await {
                    let conn = maybe_conn.await?;
                    let mut uni = conn.accept_uni().await?;
                    let other_party_id = uni.read_u32().await?;
                    assert!(connections
                        .insert(
                            usize::try_from(other_party_id).expect("u32 fits into usize"),
                            conn
                        )
                        .is_none());
                } else {
                    return Err(eyre::eyre!(
                        "server endpoint did not accept a connection from party {}",
                        party.id
                    ));
                }
            }
        }

        Ok(MpcNetworkHandler {
            connections,
            my_id: config.my_id,
        })
    }

    pub fn print_connection_stats(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        for (i, conn) in &self.connections {
            let stats = conn.stats();
            writeln!(
                out,
                "Connection {} stats:\n\tSENT: {} bytes\n\tRECV: {} bytes",
                i, stats.udp_tx.bytes, stats.udp_rx.bytes
            )?;
        }
        Ok(())
    }
    pub async fn get_byte_channels(
        &mut self,
    ) -> Result<HashMap<usize, Channel<RecvStream, SendStream>>, Report> {
        let mut channels = HashMap::with_capacity(self.connections.len() - 1);
        for (&id, conn) in &mut self.connections {
            if id < self.my_id {
                // we are the client, so we are the receiver
                let (send_stream, recv_stream) = conn.open_bi().await?;
                let conn = Channel::new(recv_stream, send_stream);
                assert!(channels.insert(id, conn).is_none());
            } else {
                // we are the server, so we are the receiver
                let (send_stream, recv_stream) = conn.accept_bi().await?;
                let conn = Channel::new(recv_stream, send_stream);
                assert!(channels.insert(id, conn).is_none());
            }
        }
        Ok(channels)
    }
}