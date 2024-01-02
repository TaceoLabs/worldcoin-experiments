use futures::{Sink, SinkExt, Stream, StreamExt};
use std::{
    io::{self},
    pin::Pin,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite, LengthDelimitedCodec};

pub type ReadChannel<T, D> = FramedRead<T, D>;
pub type WriteChannel<T, E> = FramedWrite<T, E>;

#[derive(Debug)]
pub struct Channel<R, W, C> {
    read_conn: ReadChannel<R, C>,
    write_conn: WriteChannel<W, C>,
}

pub type BytesChannel<R, W> = Channel<R, W, LengthDelimitedCodec>;

impl<R: AsyncReadExt + std::marker::Unpin, W: AsyncWriteExt + std::marker::Unpin, C>
    Channel<R, W, C>
{
    /// Create a new [`Channel`], backed by a read and write half. Read and write buffers
    /// are automatically handled by [`LengthDelimitedCodec`].
    pub fn new<MSend>(read_half: R, write_half: W, codec: C) -> Self
    where
        C: Clone + Decoder + Encoder<MSend>,
    {
        Channel {
            write_conn: FramedWrite::new(write_half, codec.clone()),
            read_conn: FramedRead::new(read_half, codec),
        }
    }
    /// Split Connection into a ([`WriteChannel`],[`ReadChannel`]) pair.
    pub fn split(self) -> (WriteChannel<W, C>, ReadChannel<R, C>) {
        (self.write_conn, self.read_conn)
    }

    pub async fn close<MSend>(self) -> Result<(), io::Error>
    where
        C: Encoder<MSend, Error = std::io::Error> + Decoder<Error = std::io::Error>,
    {
        let Channel {
            mut read_conn,
            mut write_conn,
            ..
        } = self;
        write_conn.flush().await?;
        write_conn.close().await?;
        if let Some(x) = read_conn.next().await {
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
impl<R, W: AsyncWriteExt + std::marker::Unpin, MSend, C: Encoder<MSend, Error = io::Error>>
    Sink<MSend> for Channel<R, W, C>
where
    Self: std::marker::Unpin,
{
    type Error = <C as Encoder<MSend>>::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.write_conn.poll_ready_unpin(cx)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: MSend) -> Result<(), Self::Error> {
        self.write_conn.start_send_unpin(item)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.write_conn.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.write_conn.poll_close_unpin(cx)
    }
}
impl<
        R: AsyncReadExt + std::marker::Unpin,
        W,
        MRecv,
        C: Decoder<Item = MRecv, Error = io::Error>,
    > Stream for Channel<R, W, C>
where
    Self: std::marker::Unpin,
{
    type Item = Result<MRecv, <C as Decoder>::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.read_conn.poll_next_unpin(cx)
    }
}
