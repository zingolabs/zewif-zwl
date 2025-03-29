use std::io;

use byteorder::{ReadBytesExt, WriteBytesExt};
use orchard_old::tree::MerkleHashOrchard;

pub const MERKLE_DEPTH: u8 = 32;

pub const SER_V1: u8 = 1;

/// A hashable node within a Merkle tree.
#[allow(dead_code)]
pub trait HashSer {
    /// Parses a node from the given byte source.
    fn read<R: ReadBytesExt>(reader: R) -> io::Result<Self>
    where
        Self: Sized;

    /// Serializes this node.
    fn write<W: WriteBytesExt>(&self, writer: W) -> io::Result<()>;
}

impl HashSer for MerkleHashOrchard {
    fn read<R: ReadBytesExt>(mut reader: R) -> io::Result<Self>
    where
        Self: Sized,
    {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        <Option<_>>::from(Self::from_bytes(&repr)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Non-canonical encoding of Pallas base field value.",
            )
        })
    }

    fn write<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }
}
