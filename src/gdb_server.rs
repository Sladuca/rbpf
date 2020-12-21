use crate::error::{DebugError, EbpfError};
use byteorder::{ByteOrder, LittleEndian};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::mpsc;

const BRPKT_MAP_THRESH: usize = 30;

const NUM_REGS: usize = 11; // TODO check to see if this is correct
const REG_NUM_BYTES: usize = NUM_REGS * 8;

pub enum DebugTargetString {
    Tcp(String),
    Unix(Box<Path>),
    // * Serial not yet supported
}

pub enum BreakpointTable {
    Few(Vec<(usize, i32)>),
    Many(HashMap<usize, i32>),
}

impl BreakpointTable {
    pub fn check_brkpt(&self, pc: usize) -> Option<i32> {
        match &*self {
            BreakpointTable::Few(pairs) => {
                for (brkpt_addr, brkpt_num) in pairs.iter() {
                    if *brkpt_addr == pc {
                        return Some(*brkpt_num);
                    }
                }
                return None;
            }
            BreakpointTable::Many(map) => map.get(&pc).map(|ptr| *ptr),
        }
    }

    pub fn set_brkpt(&mut self, pc: usize, brkpt_num: i32) {
        match *self {
            BreakpointTable::Few(ref mut pairs) => {
                if pairs.len() > BRPKT_MAP_THRESH {
                    let mut map = HashMap::<usize, i32>::with_capacity(pairs.len() + 1);
                    map.insert(pc, brkpt_num);
                    for (pc, brkpt_num) in pairs.iter() {
                        map.insert(*pc, *brkpt_num);
                    }
                    *self = BreakpointTable::Many(map);
                } else {
                    pairs.push((pc, brkpt_num));
                }
            }
            BreakpointTable::Many(ref mut map) => {
                map.insert(pc, brkpt_num);
            }
        }
    }
}

/// Request from the remote debugger client to execute some GDB command
pub enum DebugRequest {
    ShowMem { addr: usize, len: usize }, // (addr, len): show len bytes as a string from addr
    SetMem { addr: usize, buf: Vec<u8> }, // (addr, buf): write buf to addr
    ShowRegs,                            // show register contents
    SetRegs([u8; NUM_REGS]),             // set the value of the CPU registers
    ShowReg(usize),                      //  show contents of particular register
    SetReg(usize),                       // set contents of a particular register
    Continue(Option<usize>),             // (addr?): continue at addr
    Kill,                                // kill the process
    Load { offset: usize, len: Option<usize> }, // (offset, len?) load len bytes of executable data at offset, or 256 bytes if len not set
    Offsets,   // get offsets to be used by GDB when it follows along in the code
    Symbols,   // get symbols to be used by GDB when it follows along in the code
    Supported, // gets the supported things
    Step,      // step
    WhyHalted,
}

// see https://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.pdf
// walk the buffer to see if it starts with a full packet, and if it does, split it off from the buffer
// fn split_packet(buf: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
//   if buf[0] != b'$' {
//     return Err(DebugError::InvalidPacket(String::from_utf8_lossy(value)));
//   } else {
//     // packet ends in #XX, where XX are arbitrary hex-formatted bytes
//     let end_index =
//   }
// }

// de-escape bytes 0x23 (ASCII ‘#’), 0x24 (ASCII ‘$’), and 0x7d (ASCII ‘}’)
// each of these bytes b is escaped as b, (b ^ 0x20)
// https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html#Overview
fn de_escape(buf: Vec<u8>) -> Vec<u8> {
    buf.windows(2)
        .scan(false, |skip_next, w| match *skip_next {
            true => {
                *skip_next = false;
                Some(None)
            }
            false => {
                if w == [0x7d, 0x5d] || w == [0x23, 0x03] || w == [0x24, 0x04] {
                    *skip_next = true;
                }
                Some(Some(w[0]))
            }
        })
        .filter_map(|option_byte| option_byte)
        .collect();
}

// parse packet according to GDB RSP packet spec:
// and https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html#Remote-Protocol
fn parse_command(packet: Vec<u8>) -> Result<DebugRequest, DebugError> {
    // after '$' should be command
    match value[0] {
        b'?' => DebugRequest::WhyHalted,
        b'c' => {
            if value.len() < 2 {
                DebugRequest::Continue(None)
            } else {
                match un_escaped[1..].iter().enumerate().find_map(|(i, c)| {
                    if c == b']' {
                        Some(i)
                    } else {
                        None
                    }
                }) {
                    Some(right_bracket_index) => {
                        match parse_usize(un_escaped[4..right_bracket_index - 1]) {
                            Some(addr) => DebugRequest::Continue(Some(addr)),
                            None => DebugError::InvalidPacket(std::str::from_utf8_lossy(packet)),
                        }
                    }
                    None => DebugError::InvalidPacket(std::str::from_utf8_lossy(packet)),
                }
            }
        }
        _ => DebugError::InvalidPacket(std::str::from_utf8_lossy(packet)), // b's' => {}
                                                                           // b'D' => {}
                                                                           // b'g' => {}
                                                                           // b'G' => {}
                                                                           // b'H' => {}
                                                                           // b'k' => {}
                                                                           // b'm' => {}
                                                                           // b'M' => {}
                                                                           // b'p' => {}
                                                                           // b'P' => {}
                                                                           // b"q" => {}
                                                                           // b'X' => {}
                                                                           // b'z' => {}
                                                                           // b'Z' => {}
    }

    Ok(DebugRequest::ToggleDebug)
}

fn decode_hex(buf: Vec<u8>) -> Vec<u8> {
    (0..buf.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&std::str::from_utf8_lossy(buf)).unwrap())
        .collect()
}

fn parse_usize(buf: Vec<u8>) -> Option<usize> {
    if buf.len() != 16 {
        None
    } else {
        let from_hex = decode_hex(buf);
        Some(LittleEndian::read_u64(&from_hex[..]))
    }
}

/// Response from the VM containing the result of a command
pub enum DebugReply {
    Ok,
    Err(u8),
    ShowMem(Vec<u8>),
    ShowRegs(Vec<u8>),
    StopReply(StopReply),
    Load(Vec<u8>),
    Offsets {
        text: usize,
        data: usize,
        bss: usize,
    },
    Supported {
        packet_size: usize,
    },
}

// https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
pub enum StopReply {
    Signal(u8),
    SignalWithValue(u8, Vec<StopValue>),
    ExitStatus(u8),
    TerminateSignal(u8),
    Output(Vec<u8>),
}

pub enum StopValue {
    Watch,
    RWatch,
    AWatch,
    SyscallEntry,
    SyscallReturn,
    SwBreak,
}

trait RW: Read + Write {}

impl<T> RW for T where T: Read + Write {}

struct DebugServer {
    req: mpsc::SyncSender<DebugRequest>,
    reply: mpsc::Receiver<DebugReply>,
    conn: Box<dyn RW>,
}

impl DebugServer {
    fn new(
        target_string: DebugTargetString,
    ) -> (
        mpsc::SyncSender<DebugReply>,
        mpsc::Receiver<DebugRequest>,
        Self,
    ) {
        let conn: Box<dyn RW> = match target_string {
            DebugTargetString::Tcp(hostport) => {
                let listener = TcpListener::bind(hostport).unwrap();
                let (stream, _) = listener.accept().unwrap();
                stream.set_nonblocking(true).unwrap();
                Box::new(stream)
            }
            DebugTargetString::Unix(path) => {
                let listener = UnixListener::bind(path.clone()).unwrap();
                let (stream, _) = listener.accept().unwrap();
                stream.set_nonblocking(true).unwrap();
                Box::new(stream)
            }
        };

        let (reply_tx, reply_rx) = mpsc::sync_channel::<DebugReply>(0);
        let (req_tx, req_rx) = mpsc::sync_channel::<DebugRequest>(0);

        (
            reply_tx,
            req_rx,
            DebugServer {
                req: req_tx,
                reply: reply_rx,
                conn: conn,
            },
        )
    }

    // TODO fn run(self) {
    //     loop {
    //         if let Ok(msg) = self.from_vm.try_recv() {
    //             // TODO if case on response
    //         }
    //     }
    // }
}
