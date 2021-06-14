use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use crate::MaybeSocketAddr;
use bytes::{Buf, BufMut, BytesMut};
// use tokio_util::codec::Decoder;

/*

+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+

where Trojan Request is a SOCKS5-like request:

+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+

where:

    o  CMD
        o  CONNECT X'01'
        o  UDP ASSOCIATE X'03'
    o  ATYP address type of following address
        o  IP V4 address: X'01'
        o  DOMAINNAME: X'03'
        o  IP V6 address: X'04'
    o  DST.ADDR desired destination address
    o  DST.PORT desired destination port in network octet order

If the connection is a UDP ASSOCIATE, then each UDP packet has the following format:

+------+----------+----------+--------+---------+----------+
| ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
+------+----------+----------+--------+---------+----------+
|  1   | Variable |    2     |   2    | X'0D0A' | Variable |
+------+----------+----------+--------+---------+----------+

*/

#[derive(Debug, PartialEq)]
pub struct SocksHeader {
    atyp: u8,
    addr: Vec<u8>,
    port: u16,
}

macro_rules! aquire {
    ($src:ident,$n:expr) => {
        if $src.len() < $n {
            $src.reserve($n - $src.len());
            return Ok(None);
        }
    };
}

macro_rules! socks_addr {
    ($src:ident,$p:ident) => {
        match $src[$p] {
            0x01 => {
                aquire!($src, $p + 7);
                let port = u16::from_be_bytes([$src[$p + 5], $src[$p + 6]]);
                let addr = SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new($src[$p + 1], $src[$p + 2], $src[$p + 3], $src[$p + 4]),
                    port,
                ));
                $p += 7;
                addr.into()
            }
            0x03 => {
                aquire!($src, $p + 2);
                let len = $src[$p + 1] as usize;
                aquire!($src, $p + 2 + len);
                let data = $src[$p + 2..$p + 2 + len].to_vec();
                let port = u16::from_be_bytes([$src[$p + 2 + len], $src[$p + 3 + len]]);
                let domain = String::from_utf8(data).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.utf8_error())
                })?;
                $p += 4 + len;
                (domain, port).into()
                // if let Some(addr) = (domain.clone(), port).to_socket_addrs()?.next() {
                //     info!("resolve: {} - {:?}", domain, addr);
                //     addr.into()
                // } else {
                //     return Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable));
                // }
            }
            0x04 => {
                aquire!($src, $p + 19);
                let mut ipv6_bytes = [0u8; 16];
                ipv6_bytes.copy_from_slice(&$src[$p + 1..$p + 17]);
                let ipv6 = Ipv6Addr::from(ipv6_bytes);
                let port = u16::from_be_bytes([$src[$p + 17], $src[$p + 18]]);
                let addr = SocketAddr::V6(SocketAddrV6::new(ipv6, port, 0, 0));
                $p += 19;
                addr.into()
            }
            _ => {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
        }
    };
}

macro_rules! line_break {
    ($src:ident,$n:expr) => {
        if $src[$n] != b'\x0D' || $src[$n + 1] != b'\x0A' {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
    };
}

pub struct TrojanHeader {
    pub password: Box<[u8]>,
    pub udp_associate: bool,
    pub addr: MaybeSocketAddr,
}

pub struct TrojanDecoder;

impl Decoder for TrojanDecoder {
    type Item = TrojanHeader;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        aquire!(src, 59);
        let password = src[..56].to_owned().into_boxed_slice();
        line_break!(src, 56);
        let udp_associate = src[58] == 0x03;
        let mut p = 59;
        let addr = socks_addr!(src, p);
        aquire!(src, p + 2);
        line_break!(src, p);
        src.advance(p + 2);
        Ok(Some(TrojanHeader {
            password,
            udp_associate,
            addr,
        }))
    }
}

#[derive(Debug, PartialEq)]
pub struct UdpAssociate<T> {
    pub addr: MaybeSocketAddr,
    pub payload: T,
}

impl<'a> Into<Vec<u8>> for UdpAssociate<&'a [u8]> {
    fn into(self) -> Vec<u8> {
        let Self { addr, payload } = self;
        let mut buf = vec![];
        match addr {
            MaybeSocketAddr::SocketAddr(SocketAddr::V4(x)) => {
                buf.put_u8(b'\x01');
                buf.put_slice(&x.ip().octets());
                buf.put_slice(&x.port().to_be_bytes());
            }
            MaybeSocketAddr::SocketAddr(SocketAddr::V6(x)) => {
                buf.put_u8(b'\x04');
                buf.put_slice(&x.ip().octets());
                buf.put_slice(&x.port().to_be_bytes());
            }
            _ => unreachable!(),
        };
        buf.put_u16(payload.len() as u16);
        buf.put(&b"\r\n"[..]);
        buf.put_slice(&payload);
        buf
    }
}

impl<'a> UdpAssociate<&'a [u8]> {
    pub fn new(addr: SocketAddr, payload: &'a [u8]) -> Self {
        UdpAssociate {
            addr: addr.into(),
            payload,
        }
    }
}

pub struct UdpAssociateDecoder;

impl Decoder for UdpAssociateDecoder {
    type Item = UdpAssociate<Vec<u8>>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut p = 0;
        aquire!(src, 1);
        let addr = socks_addr!(src, p);
        aquire!(src, p + 2);
        let len = u16::from_be_bytes([src[p], src[p + 1]]) as usize;
        aquire!(src, p + 4 + len);
        line_break!(src, p + 2);
        let payload = src[p + 4..p + 4 + len].to_vec();
        src.advance(p + 4 + len);
        Ok(Some(UdpAssociate { addr, payload }))
    }
}

pub trait Decoder {
    /// The type of decoded frames.
    type Item;

    /// The type of unrecoverable frame decoding errors.
    ///
    /// If an individual message is ill-formed but can be ignored without
    /// interfering with the processing of future messages, it may be more
    /// useful to report the failure as an `Item`.
    ///
    /// `From<io::Error>` is required in the interest of making `Error` suitable
    /// for returning directly from a [`FramedRead`], and to enable the default
    /// implementation of `decode_eof` to yield an `io::Error` when the decoder
    /// fails to consume all available data.
    ///
    /// Note that implementors of this trait can simply indicate `type Error =
    /// io::Error` to use I/O errors as this type.
    ///
    /// [`FramedRead`]: crate::codec::FramedRead
    type Error: From<io::Error>;

    /// Attempts to decode a frame from the provided buffer of bytes.
    ///
    /// This method is called by [`FramedRead`] whenever bytes are ready to be
    /// parsed. The provided buffer of bytes is what's been read so far, and
    /// this instance of `Decode` can determine whether an entire frame is in
    /// the buffer and is ready to be returned.
    ///
    /// If an entire frame is available, then this instance will remove those
    /// bytes from the buffer provided and return them as a decoded
    /// frame. Note that removing bytes from the provided buffer doesn't always
    /// necessarily copy the bytes, so this should be an efficient operation in
    /// most circumstances.
    ///
    /// If the bytes look valid, but a frame isn't fully available yet, then
    /// `Ok(None)` is returned. This indicates to the [`Framed`] instance that
    /// it needs to read some more bytes before calling this method again.
    ///
    /// Note that the bytes provided may be empty. If a previous call to
    /// `decode` consumed all the bytes in the buffer then `decode` will be
    /// called again until it returns `Ok(None)`, indicating that more bytes need to
    /// be read.
    ///
    /// Finally, if the bytes in the buffer are malformed then an errors is
    /// returned indicating why. This informs [`Framed`] that the stream is now
    /// corrupt and should be terminated.
    ///
    /// [`Framed`]: crate::codec::Framed
    /// [`FramedRead`]: crate::codec::FramedRead
    ///
    /// # Buffer management
    ///
    /// Before returning from the function, implementations should ensure that
    /// the buffer has appropriate capacity in anticipation of future calls to
    /// `decode`. Failing to do so leads to inefficiency.
    ///
    /// For example, if frames have a fixed length, or if the length of the
    /// current frame is known from a header, a possible buffer management
    /// strategy is:
    ///
    /// ```no_run
    /// # use std::io;
    /// #
    /// # use bytes::BytesMut;
    /// # use tokio_util::codec::Decoder;
    /// #
    /// # struct MyCodec;
    /// #
    /// impl Decoder for MyCodec {
    ///     // ...
    ///     # type Item = BytesMut;
    ///     # type Error = io::Error;
    ///
    ///     fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
    ///         // ...
    ///
    ///         // Reserve enough to complete decoding of the current frame.
    ///         let current_frame_len: usize = 1000; // Example.
    ///         // And to start decoding the next frame.
    ///         let next_frame_header_len: usize = 10; // Example.
    ///         src.reserve(current_frame_len + next_frame_header_len);
    ///
    ///         return Ok(None);
    ///     }
    /// }
    /// ```
    ///
    /// An optimal buffer management strategy minimizes reallocations and
    /// over-allocations.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error>;

    /// A default method available to be called when there are no more bytes
    /// available to be read from the underlying I/O.
    ///
    /// This method defaults to calling `decode` and returns an errors if
    /// `Ok(None)` is returned while there is unconsumed data in `buf`.
    /// Typically this doesn't need to be implemented unless the framing
    /// protocol differs near the end of the stream, or if you need to construct
    /// frames _across_ eof boundaries on sources that can be resumed.
    ///
    /// Note that the `buf` argument may be empty. If a previous call to
    /// `decode_eof` consumed all the bytes in the buffer, `decode_eof` will be
    /// called again until it returns `None`, indicating that there are no more
    /// frames to yield. This behavior enables returning finalization frames
    /// that may not be based on inbound data.
    ///
    /// Once `None` has been returned, `decode_eof` won't be called again until
    /// an attempt to resume the stream has been made, where the underlying stream
    /// actually returned more data.
    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(buf)? {
            Some(frame) => Ok(Some(frame)),
            None => {
                if buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "bytes remaining on stream").into())
                }
            }
        }
    }
}
