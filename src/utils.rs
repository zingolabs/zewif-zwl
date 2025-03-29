use std::io;

use byteorder::{LittleEndian, ReadBytesExt};

pub fn read_string<R: ReadBytesExt>(mut reader: R) -> io::Result<String> {
    // Strings are written as <littleendian> len + bytes
    let str_len = reader.read_u64::<LittleEndian>()?;
    let mut str_bytes = vec![0; str_len as usize];
    reader.read_exact(&mut str_bytes)?;

    let str = String::from_utf8(str_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    Ok(str)
}
