use super::network_trait::NetworkTrait;
use crate::aby3::id::PartyID;
use bytes::Bytes;
use bytes::BytesMut;
use std::io;
use std::io::Error as IOError;
use std::io::ErrorKind as IOErrorKind;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

pub struct TestNetwork3p {
    p1_p2_sender: UnboundedSender<Bytes>,
    p1_p3_sender: UnboundedSender<Bytes>,
    p2_p3_sender: UnboundedSender<Bytes>,
    p2_p1_sender: UnboundedSender<Bytes>,
    p3_p1_sender: UnboundedSender<Bytes>,
    p3_p2_sender: UnboundedSender<Bytes>,
    p1_p2_receiver: UnboundedReceiver<Bytes>,
    p1_p3_receiver: UnboundedReceiver<Bytes>,
    p2_p3_receiver: UnboundedReceiver<Bytes>,
    p2_p1_receiver: UnboundedReceiver<Bytes>,
    p3_p1_receiver: UnboundedReceiver<Bytes>,
    p3_p2_receiver: UnboundedReceiver<Bytes>,
}

impl Default for TestNetwork3p {
    fn default() -> Self {
        Self::new()
    }
}

impl TestNetwork3p {
    pub fn new() -> Self {
        // AT Most 1 message is buffered before they are read so this should be fine
        let p1_p2 = mpsc::unbounded_channel();
        let p1_p3 = mpsc::unbounded_channel();
        let p2_p3 = mpsc::unbounded_channel();
        let p2_p1 = mpsc::unbounded_channel();
        let p3_p1 = mpsc::unbounded_channel();
        let p3_p2 = mpsc::unbounded_channel();

        Self {
            p1_p2_sender: p1_p2.0,
            p1_p3_sender: p1_p3.0,
            p2_p1_sender: p2_p1.0,
            p2_p3_sender: p2_p3.0,
            p3_p1_sender: p3_p1.0,
            p3_p2_sender: p3_p2.0,
            p1_p2_receiver: p1_p2.1,
            p1_p3_receiver: p1_p3.1,
            p2_p1_receiver: p2_p1.1,
            p2_p3_receiver: p2_p3.1,
            p3_p1_receiver: p3_p1.1,
            p3_p2_receiver: p3_p2.1,
        }
    }

    pub fn get_party_networks(self) -> [PartyTestNetwork; 3] {
        let party1 = PartyTestNetwork {
            id: PartyID::ID0,
            send_prev: self.p1_p3_sender,
            recv_prev: self.p3_p1_receiver,
            send_next: self.p1_p2_sender,
            recv_next: self.p2_p1_receiver,
            stats: [0; 4],
        };

        let party2 = PartyTestNetwork {
            id: PartyID::ID1,
            send_prev: self.p2_p1_sender,
            recv_prev: self.p1_p2_receiver,
            send_next: self.p2_p3_sender,
            recv_next: self.p3_p2_receiver,
            stats: [0; 4],
        };

        let party3 = PartyTestNetwork {
            id: PartyID::ID2,
            send_prev: self.p3_p2_sender,
            recv_prev: self.p2_p3_receiver,
            send_next: self.p3_p1_sender,
            recv_next: self.p1_p3_receiver,
            stats: [0; 4],
        };

        [party1, party2, party3]
    }
}

pub struct PartyTestNetwork {
    id: PartyID,
    send_prev: UnboundedSender<Bytes>,
    send_next: UnboundedSender<Bytes>,
    recv_prev: UnboundedReceiver<Bytes>,
    recv_next: UnboundedReceiver<Bytes>,
    stats: [usize; 4], // [sent_prev, sent_next, recv_prev, recv_next]
}

impl PartyTestNetwork {
    pub const NUM_PARTIES: usize = 3;
}

impl NetworkTrait for PartyTestNetwork {
    async fn shutdown(self) -> Result<(), IOError> {
        Ok(())
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        writeln!(
            out,
            "Connection \"prev\" stats:\n\tSENT: {} bytes\n\tRECV: {} bytes",
            self.stats[0], self.stats[2]
        )?;
        writeln!(
            out,
            "Connection \"next\" stats:\n\tSENT: {} bytes\n\tRECV: {} bytes",
            self.stats[1], self.stats[3]
        )?;
        Ok(())
    }

    async fn send(&mut self, id: usize, data: Bytes) -> std::io::Result<()> {
        tracing::trace!("send_id {}->{}: {:?}", self.id, id, data);
        let res = if id == usize::from(self.id.next_id()) {
            self.stats[1] += data.len();
            self.send_next
                .send(data)
                .map_err(|_| IOError::new(IOErrorKind::Other, "Send failed"))
        } else if id == usize::from(self.id.prev_id()) {
            self.stats[0] += data.len();
            self.send_prev
                .send(data)
                .map_err(|_| IOError::new(IOErrorKind::Other, "Send failed"))
        } else {
            Err(IOError::new(io::ErrorKind::Other, "Invalid ID"))
        };

        tracing::trace!("send_id {}->{}: done", self.id, id);
        res
    }

    async fn receive(&mut self, id: usize) -> std::io::Result<BytesMut> {
        tracing::trace!("recv_id {}<-{}: ", self.id, id);
        let buf = if id == usize::from(self.id.prev_id()) {
            let data = self
                .recv_prev
                .recv()
                .await
                .ok_or_else(|| IOError::new(IOErrorKind::Other, "Receive failed"))?;
            self.stats[2] += data.len();
            data
        } else if id == usize::from(self.id.next_id()) {
            let data = self
                .recv_next
                .recv()
                .await
                .ok_or_else(|| IOError::new(IOErrorKind::Other, "Receive failed"))?;
            self.stats[3] += data.len();
            data
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid ID"));
        };
        tracing::trace!("recv_id {}<-{}: done", self.id, id);

        Ok(BytesMut::from(buf.as_ref()))
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

    fn get_id(&self) -> usize {
        self.id.into()
    }

    fn get_num_parties(&self) -> usize {
        Self::NUM_PARTIES
    }

    async fn send_next_id(&mut self, data: Bytes) -> Result<(), IOError> {
        tracing::trace!("send {}->{}: {:?}", self.id, self.id.next_id(), data);
        self.stats[1] += data.len();
        let res = self
            .send_next
            .send(data)
            .map_err(|_| IOError::new(IOErrorKind::Other, "Send failed"));
        tracing::trace!("send {}->{}: done", self.id, self.id.next_id());
        res
    }

    async fn send_prev_id(&mut self, data: Bytes) -> Result<(), IOError> {
        tracing::trace!("send {}->{}: {:?}", self.id, self.id.prev_id(), data);
        self.stats[0] += data.len();
        let res = self
            .send_prev
            .send(data)
            .map_err(|_| IOError::new(IOErrorKind::Other, "Send failed"));
        tracing::trace!("send {}->{}: done", self.id, self.id.prev_id());
        res
    }

    async fn receive_prev_id(&mut self) -> Result<bytes::BytesMut, IOError> {
        tracing::trace!("recv {}<-{}: ", self.id, self.id.prev_id());
        let buf = self
            .recv_prev
            .recv()
            .await
            .ok_or_else(|| IOError::new(IOErrorKind::Other, "Receive failed"))?;
        self.stats[2] += buf.len();

        tracing::trace!("recv {}<-{}: done", self.id, self.id.prev_id());
        Ok(BytesMut::from(buf.as_ref()))
    }

    async fn receive_next_id(&mut self) -> Result<bytes::BytesMut, IOError> {
        tracing::trace!("recv {}<-{}: ", self.id, self.id.next_id());
        let buf = self
            .recv_next
            .recv()
            .await
            .ok_or_else(|| IOError::new(IOErrorKind::Other, "Receive failed"))?;
        self.stats[3] += buf.len();

        tracing::trace!("recv {}<-{}: done", self.id, self.id.next_id());
        Ok(BytesMut::from(buf.as_ref()))
    }

    async fn fork(&mut self) -> Result<Self, IOError> {
        todo!()
    }
}
