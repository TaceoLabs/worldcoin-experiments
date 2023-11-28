use super::id::PartyID;
use crate::error::Error;
use crate::traits::network_trait::NetworkTrait;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use mpc_net::channel::Channel;
use mpc_net::config::NetworkConfig;
use mpc_net::MpcNetworkHandler;
use quinn::{RecvStream, SendStream};
use std::io::{Error as IOError, ErrorKind};

pub(crate) struct Aby3Network {
    handler: MpcNetworkHandler,
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

        let mut handler = MpcNetworkHandler::establish(config).await?;
        let mut channels = handler.get_byte_channels().await?;

        let next_id: usize = id.next_id().into();
        let prev_id: usize = id.prev_id().into();

        let channel_send = channels.remove(&next_id).ok_or(Error::ConfigError)?;
        let channel_recv = channels.remove(&prev_id).ok_or(Error::ConfigError)?;

        Ok(Self {
            handler,
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
        if id == self.id.next_id().into() {
            self.channel_send.send(data).await
        } else if id == self.id.prev_id().into() {
            self.channel_recv.send(data).await
        } else {
            Err(IOError::new(ErrorKind::Other, "Invalid ID"))
        }
    }

    async fn send_next_id(&mut self, data: Bytes) -> Result<(), IOError> {
        self.channel_send.send(data).await
    }

    async fn receive(&mut self, id: usize) -> Result<BytesMut, IOError> {
        todo!()
    }

    async fn receive_prev_id(&mut self) -> Result<BytesMut, IOError> {
        let buf = self.channel_recv.next().await;
        if let Some(Ok(b)) = buf {
            Ok(b)
        } else {
            Err(IOError::new(
                ErrorKind::ConnectionAborted,
                "Receive on closed Channel",
            ))
        }
    }

    async fn broadcast(&mut self, data: bytes::Bytes) -> Vec<Result<bytes::Bytes, IOError>> {
        todo!()
    }

    async fn shutdown(&mut self) -> Result<(), IOError> {
        self.channel_send.close().await?;
        self.channel_recv.finish().await?;
        Ok(())
    }
}
