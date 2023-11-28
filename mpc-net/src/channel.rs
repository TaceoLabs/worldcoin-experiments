use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use std::{
    io::{self},
    pin::Pin,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

pub type ReadChannel<T> = FramedRead<T, LengthDelimitedCodec>;
pub type WriteChannel<T> = FramedWrite<T, LengthDelimitedCodec>;

#[derive(Debug)]
pub struct Channel<
    R: AsyncReadExt + Send + 'static + std::marker::Unpin,
    W: AsyncWriteExt + Send + 'static + std::marker::Unpin,
> {
    read_conn: ReadChannel<R>,
    write_conn: WriteChannel<W>,
}

impl<
        R: AsyncReadExt + Send + 'static + std::marker::Unpin,
        W: AsyncWriteExt + Send + 'static + std::marker::Unpin,
    > Channel<R, W>
{
    /// Create a new [`Channel`], backed by a read and write half. Read and write buffers
    /// are automatically handled by [`LengthDelimitedCodec`].
    pub fn new(read_half: R, write_half: W) -> Self {
        let codec = LengthDelimitedCodec::new();
        Channel {
            write_conn: FramedWrite::new(write_half, codec.clone()),
            read_conn: FramedRead::new(read_half, codec),
        }
    }
    /// Split Connection into a ([`WriteChannel`],[`ReadChannel`]) pair.
    pub fn split(self) -> (WriteChannel<W>, ReadChannel<R>) {
        (self.write_conn, self.read_conn)
    }

    pub async fn close(self) -> Result<(), io::Error> {
        let Channel {
            mut read_conn,
            mut write_conn,
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
impl<
        R: AsyncReadExt + Send + 'static + std::marker::Unpin,
        W: AsyncWriteExt + Send + 'static + std::marker::Unpin,
    > Sink<Bytes> for Channel<R, W>
{
    type Error = io::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.write_conn.poll_ready_unpin(cx)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
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
        R: AsyncReadExt + Send + 'static + std::marker::Unpin,
        W: AsyncWriteExt + Send + 'static + std::marker::Unpin,
    > Stream for Channel<R, W>
{
    type Item = io::Result<BytesMut>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.read_conn.poll_next_unpin(cx)
    }
}
