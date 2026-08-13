// SPDX-License-Identifier: GPL-2.0-only
use std::env;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::process::ExitCode;

const NODE_SIZE: usize = 33;
const NODE_TEXT_SIZE: usize = 55;
const AUTH_REQUIRED: u32 = 1 << 2;

#[repr(C)]
struct NodeId {
    bytes: [u8; NODE_SIZE],
}

#[repr(C)]
struct SocketState {
    descriptor: c_int,
    family: u16,
    portid: u32,
    sequence: u32,
}

#[repr(C)]
struct Received {
    source: NodeId,
    source_service: u16,
    local_service: u16,
    payload: *const u8,
    payload_length: usize,
}

unsafe extern "C" {
    fn if_nametoindex(name: *const c_char) -> u32;
    fn melodi_socket_open(state: *mut SocketState) -> c_int;
    fn melodi_socket_close(state: *mut SocketState);
    fn melodi_nodeid_parse(text: *const c_char, length: usize,
                           node: *mut NodeId) -> c_int;
    fn melodi_nodeid_format(node: *const NodeId,
                            text: *mut c_char) -> c_int;
    fn melodi_client_bind(state: *mut SocketState, ifindex: u32,
                          service: u16) -> c_int;
    fn melodi_client_send(state: *mut SocketState, destination: *const NodeId,
                          service: u16, payload: *const c_void, length: usize,
                          flags: u32, cookie: u64) -> c_int;
    fn melodi_client_receive(state: *mut SocketState, buffer: *mut c_void,
                             capacity: usize, message: *mut Received) -> c_int;
}

fn run(arguments: &[String]) -> Result<(), c_int> {
    if arguments.len() != 6 {
        return Err(-22);
    }
    let interface = CString::new(arguments[1].as_str()).map_err(|_| -22)?;
    let local_service = arguments[2].parse::<u16>().map_err(|_| -22)?;
    let destination_service = arguments[4].parse::<u16>().map_err(|_| -22)?;
    if local_service == 0 || local_service == u16::MAX ||
       destination_service == 0 || destination_service == u16::MAX {
        return Err(-22);
    }
    let destination_text = CString::new(arguments[3].as_str()).map_err(|_| -22)?;
    let mut destination = NodeId { bytes: [0; NODE_SIZE] };
    let mut socket = SocketState { descriptor: -1, family: 0,
                                   portid: 0, sequence: 0 };
    let mut buffer = [0u8; 8192];
    let mut received = Received {
        source: NodeId { bytes: [0; NODE_SIZE] },
        source_service: 0,
        local_service: 0,
        payload: std::ptr::null(),
        payload_length: 0,
    };
    let mut source = [0 as c_char; NODE_TEXT_SIZE];
    let mut error = unsafe {
        melodi_nodeid_parse(destination_text.as_ptr(), arguments[3].len(),
                            &mut destination)
    };
    if error == 0 {
        let ifindex = unsafe { if_nametoindex(interface.as_ptr()) };
        if ifindex == 0 {
            error = -19;
        } else {
            error = unsafe { melodi_socket_open(&mut socket) };
            if error == 0 {
                error = unsafe { melodi_client_bind(&mut socket, ifindex,
                                                     local_service) };
            }
            if error == 0 {
                error = unsafe {
                    melodi_client_send(&mut socket, &destination,
                        destination_service, arguments[5].as_ptr().cast(),
                        arguments[5].len(), AUTH_REQUIRED, 1)
                };
            }
            if error == 0 {
                error = unsafe {
                    melodi_client_receive(&mut socket, buffer.as_mut_ptr().cast(),
                                          buffer.len(), &mut received)
                };
            }
        }
    }
    if error == 0 {
        error = unsafe { melodi_nodeid_format(&received.source, source.as_mut_ptr()) };
    }
    if error == 0 {
        let source_text = unsafe { CStr::from_ptr(source.as_ptr()) }.to_string_lossy();
        let payload = unsafe {
            std::slice::from_raw_parts(received.payload, received.payload_length)
        };
        println!("{} {}: {}", source_text, received.source_service,
                 String::from_utf8_lossy(payload));
    }
    unsafe { melodi_socket_close(&mut socket) };
    if error == 0 { Ok(()) } else { Err(error) }
}

fn main() -> ExitCode {
    match run(&env::args().collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("melodi-example-rust: error {}", error);
            ExitCode::FAILURE
        }
    }
}
