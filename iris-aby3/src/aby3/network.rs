use super::id::PartyID;
use crate::error::Error;
use crate::traits::network_trait::NetworkTrait;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use mpc_net::channel::Channel;
use mpc_net::config::NetworkConfig;
use mpc_net::MpcNetworkHandler;
use quinn::{RecvStream, SendStream};
use std::io::Error as IOError;

struct Aby3Network {
    id: PartyID,
    channel_send: Channel<RecvStream, SendStream>,
    channel_recv: Channel<RecvStream, SendStream>,
}

impl Aby3Network {
    pub async fn new(config: NetworkConfig) -> Result<Self, Error> {
        let id = PartyID::try_from(config.my_id)?;
        if config.parties.len() != 3 {
            return Err(Error::NumPartyError(config.parties.len()));
        }

        let mut network = MpcNetworkHandler::establish(config).await?;
        let mut channels = network.get_byte_channels().await?;

        let next_id: usize = id.next_id().into();
        let prev_id: usize = id.prev_id().into();

        let channel_send = channels.remove(&next_id).ok_or(Error::ConfigError)?;
        let channel_recv = channels.remove(&prev_id).ok_or(Error::ConfigError)?;

        Ok(Self {
            id,
            channel_send,
            channel_recv,
        })
    }
}

impl NetworkTrait for Aby3Network {
    fn get_id(&self) -> usize {
        self.id.into()
    }

    fn get_num_parties(&self) -> usize {
        3
    }

    async fn send(&mut self, id: usize, data: Bytes) -> Result<(), IOError> {
        todo!()
    }

    async fn sent_next_id(&mut self, data: Bytes) -> Result<(), IOError> {
        self.channel_send.send(data).await
    }

    async fn receive(&mut self, id: usize) -> Result<bytes::Bytes, IOError> {
        todo!()
        // self.channel_recv.next().await
    }

    async fn receive_prev_id(&mut self) -> Result<bytes::Bytes, IOError> {
        todo!()
    }

    async fn broadcast(&mut self, data: bytes::Bytes) -> Vec<Result<bytes::Bytes, IOError>> {
        todo!()
    }
}
