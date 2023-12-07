use std::io;

use super::id::PartyID;
use crate::error::Error;
use crate::traits::network_trait::NetworkTrait;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use mpc_net::channel::BytesChannel;
use mpc_net::config::NetworkConfig;
use mpc_net::MpcNetworkHandler;
use quinn::{RecvStream, SendStream};

pub struct Aby3Network {
    handler: MpcNetworkHandler,
    id: PartyID,
    channel_send: BytesChannel<RecvStream, SendStream>,
    channel_recv: BytesChannel<RecvStream, SendStream>,
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

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        self.handler.print_connection_stats(out)
    }

    async fn send(&mut self, id: usize, data: Bytes) -> io::Result<()> {
        tracing::trace!("send_id {}->{}: {:?}", self.id, id, data);
        let res = if id == usize::from(self.id.next_id()) {
            self.channel_send.send(data).await
        } else if id == usize::from(self.id.prev_id()) {
            self.channel_recv.send(data).await
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Invalid ID"))
        };
        tracing::trace!("send_id {}->{}: done", self.id, id);
        res
    }

    async fn send_next_id(&mut self, data: Bytes) -> io::Result<()> {
        tracing::trace!("send {}->{}: {:?}", self.id, self.id.next_id(), data);
        let res = self.channel_send.send(data).await;
        tracing::trace!("send {}->{}: done", self.id, self.id.next_id());
        res
    }

    async fn receive(&mut self, id: usize) -> Result<BytesMut, io::Error> {
        tracing::trace!("recv_id {}<-{}: ", self.id, id);
        let buf = if id == usize::from(self.id.prev_id()) {
            self.channel_recv.next().await
        } else if id == usize::from(self.id.next_id()) {
            self.channel_send.next().await
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid ID"));
        };
        tracing::trace!("recv_id {}<-{}: done", self.id, id);

        if let Some(maybe_packet) = buf {
            maybe_packet
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Receive on closed Channel",
            ))
        }
    }

    async fn receive_prev_id(&mut self) -> io::Result<BytesMut> {
        tracing::trace!("recv {}<-{}: ", self.id, self.id.prev_id());
        let buf = self.channel_recv.next().await;
        tracing::trace!("recv {}<-{}: done", self.id, self.id.prev_id());
        if let Some(maybe_packet) = buf {
            maybe_packet
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Receive on closed Channel",
            ))
        }
    }

    async fn broadcast(&mut self, data: Bytes) -> Result<Vec<BytesMut>, io::Error> {
        let mut result = Vec::with_capacity(3);
        for id in 0..3 {
            if id != usize::from(self.id) {
                self.send(id, data.clone()).await?;
            }
        }
        for id in 0..3 {
            if id == usize::from(self.id) {
                result.push(BytesMut::from(data.as_ref()));
            } else {
                result.push(self.receive(id).await?);
            }
        }
        Ok(result)
    }

    async fn shutdown(self) -> io::Result<()> {
        let (mut send1, mut recv1) = self.channel_send.split();
        let (mut send2, mut recv2) = self.channel_recv.split();
        send1.flush().await?;
        send1.close().await?;
        send2.flush().await?;
        send2.close().await?;
        drop(send1);
        drop(send2);
        if let Some(x) = recv1.next().await {
            match x {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Unexpected data on read channel when closing connections",
                    ));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        if let Some(x) = recv2.next().await {
            match x {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Unexpected data on read channel when closing connections",
                    ));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}
