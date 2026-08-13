// SPDX-License-Identifier: GPL-2.0-only
use std::io::{self, Write};

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_ne_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_ne_bytes());
}

fn attribute(output: &mut Vec<u8>, kind: u16, value: &[u8]) {
    put_u16(output, (4 + value.len()) as u16);
    put_u16(output, kind);
    output.extend_from_slice(value);
    while output.len() % 4 != 0 {
        output.push(0);
    }
}

fn main() -> io::Result<()> {
    let mut output = Vec::new();
    put_u32(&mut output, 0);
    put_u16(&mut output, 0x1234);
    put_u16(&mut output, 0x0005);
    put_u32(&mut output, 0x10203040);
    put_u32(&mut output, 0x55667788);
    output.extend_from_slice(&[1, 1, 0, 0]);
    attribute(&mut output, 1, &7u32.to_ne_bytes());
    attribute(&mut output, 2, &42u16.to_ne_bytes());
    let length = output.len() as u32;
    output[0..4].copy_from_slice(&length.to_ne_bytes());
    io::stdout().write_all(&output)
}
