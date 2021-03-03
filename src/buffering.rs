use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    pin::{self, Pin},
    task::{Context, Poll},
};

use actix_web::{HttpMessage, dev::{BodySize, MessageBody, Payload, ServiceRequest}, error::PayloadError, http::{HeaderName, HeaderValue}, web::{Bytes, BytesMut}};
use futures::{ready, Stream, StreamExt};
use uuid::Uuid;

pub fn enable_request_buffering<T>(builder: T, req: &mut ServiceRequest)
where
    T: AsRef<FileBufferingStreamBuilder>,
{
    const BUFFERED_KEY: &str = "x-buffered-request";

    if !req.headers().contains_key(BUFFERED_KEY) {
        let inner = req.take_payload();
        req.set_payload(Payload::Stream(builder.as_ref().build(inner).boxed_local()));

        req.headers_mut().insert(
            HeaderName::from_static(BUFFERED_KEY),
            HeaderValue::from_static(""),
        );
    }
}

pub struct FileBufferingStreamBuilder {
    tmp_dir: PathBuf,
    threshold: usize,
    produce_block_size: usize,
    buffer_limit: Option<usize>,
}

impl FileBufferingStreamBuilder {
    pub fn new() -> Self {
        Self {
            tmp_dir: std::env::temp_dir(),
            threshold: 1024 * 30,
            produce_block_size: 1024 * 30,
            buffer_limit: None,
        }
    }

    pub fn tmp_dir(mut self, v: impl AsRef<Path>) -> Self {
        self.tmp_dir = v.as_ref().to_path_buf();
        self
    }

    pub fn threshold(mut self, v: usize) -> Self {
        self.threshold = v;
        self
    }

    pub fn produce_block_size(mut self, v: usize) -> Self {
        self.produce_block_size = v;
        self
    }

    pub fn buffer_limit(mut self, v: Option<usize>) -> Self {
        self.buffer_limit = v;
        self
    }

    pub fn build<S>(&self, inner: S) -> FileBufferingStream<S> {
        FileBufferingStream::new(
            inner,
            self.tmp_dir.to_path_buf(),
            self.threshold,
            self.produce_block_size,
            self.buffer_limit,
        )
    }
}

impl AsRef<FileBufferingStreamBuilder> for FileBufferingStreamBuilder {
    fn as_ref(&self) -> &FileBufferingStreamBuilder {
        self
    }
}

enum Buffer {
    Memory(BytesMut),
    File(PathBuf, File),
}

pub struct FileBufferingStream<S> {
    inner: S,
    inner_eof: bool,

    tmp_dir: PathBuf,
    threshold: usize,
    produce_block_size: usize,
    buffer_limit: Option<usize>,

    buffer: Buffer,
    buffer_size: usize,
    produce_index: usize,
}

impl<S> Drop for FileBufferingStream<S> {
    fn drop(&mut self) {
        match self.buffer {
            Buffer::Memory(_) => {}
            Buffer::File(ref path, _) => match std::fs::remove_file(path) {
                Ok(_) => {}
                Err(e) => println!("error at remove buffering file {:?}. {}", path, e),
            },
        };
    }
}

impl<S> FileBufferingStream<S> {
    fn new(
        inner: S,
        tmp_dir: PathBuf,
        threshold: usize,
        produce_block_size: usize,
        buffer_limit: Option<usize>,
    ) -> Self {
        Self {
            inner: inner,
            inner_eof: false,

            tmp_dir,
            threshold,
            produce_block_size,
            buffer_limit: buffer_limit,

            buffer: Buffer::Memory(BytesMut::new()),
            buffer_size: 0,
            produce_index: 0,
        }
    }

    fn write_to_buffer(&mut self, bytes: &Bytes) -> Result<(), std::io::Error> {
        match self.buffer {
            Buffer::Memory(ref mut memory) => {
                if self.threshold < memory.len() + bytes.len() {
                    let mut path = self.tmp_dir.to_path_buf();
                    path.push(Uuid::new_v4().to_simple().to_string());

                    let mut file = OpenOptions::new()
                        .write(true)
                        .read(true)
                        .create_new(true)
                        .open(&path)?;

                    file.write_all(&memory[..])?;
                    file.write_all(bytes)?;

                    self.buffer = Buffer::File(path, file);
                } else {
                    memory.extend_from_slice(bytes)
                }
            }
            Buffer::File(_, ref mut file) => {
                file.write_all(bytes)?;
            }
        }

        self.buffer_size += bytes.len();

        Ok(())
    }

    fn read_from_buffer(&mut self) -> Result<Bytes, std::io::Error> {
        let block_size = self.produce_block_size;
        let buffer_size = self.buffer_size;
        let current_index = self.produce_index;

        if buffer_size <= current_index {
            self.produce_index = 0;
            return Ok(Bytes::new());
        }

        let bytes = match self.buffer {
            Buffer::Memory(ref memory) => {
                let bytes = {
                    if buffer_size <= current_index + block_size {
                        self.produce_index = buffer_size;
                        let start = current_index as usize;
                        Bytes::copy_from_slice(&memory[start..])
                    } else {
                        self.produce_index += block_size;
                        let start = current_index as usize;
                        let end = (current_index + block_size) as usize;
                        Bytes::copy_from_slice(&memory[start..end])
                    }
                };

                bytes
            }
            Buffer::File(_, ref mut file) => {
                if current_index == 0 {
                    file.seek(SeekFrom::Start(0))?;
                    file.flush()?;
                }

                let mut bytes = {
                    if buffer_size <= current_index + block_size {
                        self.produce_index = buffer_size;
                        vec![0u8; buffer_size - current_index]
                    } else {
                        self.produce_index += block_size;
                        vec![0u8; block_size]
                    }
                };

                file.read_exact(bytes.as_mut_slice())?;

                bytes.into()
            }
        };

        Ok(bytes)
    }
}

impl<S, E> MessageBody for FileBufferingStream<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<actix_web::Error>,
{
    fn size(&self) -> BodySize {
        BodySize::Stream
    }

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, actix_web::Error>>> {
        let this = self.get_mut();

        match this.inner_eof {
            false => {
                let op = ready!(Pin::new(&mut this.inner).poll_next(cx));
                match op {
                    Some(ref r) => {
                        if let Ok(ref o) = r {
                            /*if let Some(limit) = this.buffer_limit {
                                if this.buffer_size + o.len() > limit {
                                    return Poll::Ready(Some(Err(actix_web::Error::from(status::))));
                                }
                            }*/

                            this.write_to_buffer(o)?;
                        }
                    }
                    None => {
                        this.inner_eof = true;
                    }
                };

                Poll::Ready(op.map(|res| res.map_err(Into::into)))
            }
            true => {
                let bytes = this.read_from_buffer()?;
                if bytes.len() == 0 {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(bytes)))
                }
            }
        }
        /*let mut stream = self.project().stream;
        loop {
            let stream = stream.as_mut();
            return Poll::Ready(match ready!(stream.poll_next(cx)) {
                Some(Ok(ref bytes)) if bytes.is_empty() => continue,
                opt => opt.map(|res| res.map_err(Into::into)),
            });
        }*/
    }
}
/*
impl<S> MessageBody for FileBufferingStream<S> 
where
    S: MessageBody + Unpin,
{
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, actix_web::Error>>> {
        let this = self.get_mut();

        match this.inner_eof {
            false => {
                let op = ready!(Pin::new(&mut this.inner).poll_next(cx));
                match op {
                    Some(ref r) => {
                        if let Ok(ref o) = r {
                            if let Some(limit) = this.buffer_limit {
                                if this.buffer_size + o.len() > limit {
                                    return Poll::Ready(Some(Err(actix_web::Error::from(status::))));
                                }
                            }

                            this.write_to_buffer(o)?;
                        }
                    }
                    None => {
                        this.inner_eof = true;
                    }
                };

                Poll::Ready(op)
            }
            true => {
                let bytes = this.read_from_buffer()?;
                if bytes.len() == 0 {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(bytes)))
                }
            }
        }
    }

    fn size(&self) -> actix_web::dev::BodySize {
        todo!()
    }
}
*/

impl<S> Stream for FileBufferingStream<S>
where
    S: Stream<Item = Result<Bytes, PayloadError>> + Unpin,
{
    type Item = Result<Bytes, PayloadError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        match this.inner_eof {
            false => {
                let op = ready!(Pin::new(&mut this.inner).poll_next(cx));
                match op {
                    Some(ref r) => {
                        if let Ok(ref o) = r {
                            if let Some(limit) = this.buffer_limit {
                                if this.buffer_size + o.len() > limit {
                                    return Poll::Ready(Some(Err(PayloadError::Overflow)));
                                }
                            }

                            this.write_to_buffer(o)?;
                        }
                    }
                    None => {
                        this.inner_eof = true;
                    }
                };

                Poll::Ready(op)
            }
            true => {
                let bytes = this.read_from_buffer()?;
                if bytes.len() == 0 {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(bytes)))
                }
            }
        }
    }
}
