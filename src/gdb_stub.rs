use gdbstub::arch;
use gdbstub::target;
use gdbstub::target::ext::base::singleThread::{ResumeAction, SingleThreadOps, StopReason};
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::target::{Target, TargetError, TargetResult};
use std::collections::HashMap;
use std::debug_assert;
use std::net::{TcpListener, TcpStream};
use std::os::Path;
use std::sync::mpsc;

const BRPKT_MAP_THRESH: usize = 30;

const NUM_REGS: usize = 11;
const REG_NUM_BYTES: usize = NUM_REGS * 8;

pub enum DebugTargetString {
    Tcp(String),
    Unix(Box<Path>),
    // * Serial not yet supported
}

fn wait_for_gdb_connection(port: u16) -> std::io::Result<TcpStream> {
    let sockaddr = format!("localhost:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);
    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;

    // Blocks until a GDB client connects via TCP.
    // i.e: Running `target remote localhost:<port>` from the GDB prompt.

    eprintln!("Debugger connected from {}", addr);
    Ok(stream)
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

pub struct DebugServer {
    req: mpsc::SyncSender<VmRequest>,
    reply: mpsc::Receiver<VmReply>,
    regs: BPFRegs,
}

impl DebugServer {
    fn new(
        regs: &[u64; 11],
        pc: u64,
    ) -> (Self, mpsc::SyncSender<VmReply>, mpsc::Receiver<VmRequest>) {
        (req_tx, req_rx) = mpsc::sync_channel::<VmRequest>(0);
        (reply_tx, reply_rx) = mpsc::sync_channel::<VmReply>(0);
        (
            DebugServer {
                req: req_tx,
                reply: reply_rx,
                regs: *regs,
                pc: pc,
            },
            reply_tx,
            req_rx,
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BPFRegs {
    regs: &'a [u64; 11],
    pc: &'a u64,
}

impl Registers for BPFRegs {
    fn gdb_serialize(&self, write_byte: impl FnMut(Option<u8>)) {
        let bytes: [u8; 12 * 8] = unsafe { std::mem::trasmute_copy(self) };
        bytes.iter().for_each(write_byte(Some(b)));
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() != 12 * 8 {
            Err(())
        } else {
            let transmuted: Self = unsafe { std::mem::trasmute_copy(bytes) };
            *self = transmuted;
            Ok(())
        }
    }
}

pub struct BPFRegId(u8);
impl RegId for BPFRegId {
    fn from_raw_id(id: usize) -> Option<(Self, usize)> {
        if id < 13 {
            Some((id as u8, id))
        } else {
            None
        }
    }
}

impl From<u8> for BPFRegId {
    fn from(val: u8) -> BPFRegId {
        BPFRegId(val)
    }
}

pub struct BPFArch;

impl Arch for BPFArch {
    type Usize = u64;
    type Registers = BPFRegs;
    type RegId = BPFRegId;
}

impl Target for DebugServer {
    type Arch = DebugBPF;
    type Error = &'static str;

    fn base_ops(&mut self) -> target::exp::base::BaseOps<Self::Arch, Self::Error> {
        target::exp::base::BaseOps::SingleThread(self)
    }

    fn sw_breakpoint(&mut self) -> Option<target::ext::breakpoints::SwBreakpointOps<Self>> {
        Some(self)
    }

    fn hw_watchpoint(&mut self) -> Option<Target::ext::breakpoints::HwWatchpointOps<Self>> {
        None
    }

    fn extended_mode(&mut self) -> Option<Target::ext::extended_mode::ExtendedModeOps<Self>> {
        None
    }

    fn monitor_cmd(&mut self) -> Option<target::ext::monitor_cmd::MonitorCmdOps<Self>> {
        None
    }

    fn section_offsets(&mut self) -> Option<target::ext::section_offsets::SectionOffsetsOps<Self>> {
        Some(self)
    }
}

pub enum VmRequest {
    Resume,
    Interrupt,
    Step,
    ReadRegs,
    WriteRegs,
    ReadReg(u8),
    WriteReg(u8, usize),
    WriteRegs([u64; 12]),
    ReadMem(usize, usize),
    WriteMem(usize, usize, Vec<u8>),
    Offsets,
}

pub enum VmReply {
    DoneStep,
    Interrupt,
    Halted,
    Breakpoint,
    Err(&'static str),
    ReadRegs([u64; 12]),
    ReadReg(u64),
    WriteRegs,
    WriteReg,
    ReadMem(Vec<u8>),
    WriteMem,
    Offsets(Vec<usize>),
}

impl SingleThreadOps for DebugServer {
    fn resume(
        &mut self,
        action: ResumeAction,
        check_gdb_interrupt: &mut dyn FnMut() -> bool,
    ) -> Result<StopReason<u32>, Self::Error> {
        match action {
            ResumeAction::Step => {
                self.req.send(VmRequest::Step).unwrap();
                match self.reply.recv().unwrap() {
                    VmReply::DoneStep => Ok(StopReason::DoneStep),
                    _ => Err("unexpected reply from vm"),
                }
            }
            ResumeAction::Continue => {
                self.req.send(VmRequest::Resume).unwrap();
                // TODO find a better way to deal with check_gdb_interrupt
                while !check_gdb_interrupt() {
                    if let Ok(event) = self.reply.try_recv() {
                        return match event {
                            VmReply::Breakpoint => Ok(StopReason::SwBreak),
                            VmReply::Halted => Ok(StopReason::Halted),
                            Err(e) => Err(e),
                            _ => Err("unexpected reply from vm"),
                        };
                    }
                }
                self.req.send(VmRequest::Interrupt).unwrap();
                match self.req.recv().unwrap() {
                    VmReply::Interrupt => Ok(StopReason::GdbInterrupt),
                    Err(e) => Err(e),
                    _ => Err("unexpected reply from vm"),
                }
            }
        }
    }

    fn read_registers(&mut self, regs: &mut BPFRegs) -> TargetResult<(), Self> {
        self.req.send(VmRequest::ReadRegs).unwrap();
        match self.reply.recv().unwrap() {
            VmReply::ReadRegs(regfile) => {
                *regs = unsafe { std::mem::trasmute_copy(regfile) };
                Ok(())
            }
            Err(e) => Err(e),
            _ => Err("unexpected reply from vm"),
        }
    }

    fn write_registers(&mut self, regs: &BPFRegs) -> TargetResult<(), Self> {
        let regfile: [u64; 12] = unsafe { std::mem::trasmute_copy(*regs) };
        self.req.send(VmRequest::WriteRegs(regfile)).unwrap();
        match self.reply.recv().unwrap() {
            VmReply::WriteRegs => Ok(()),
            Err(e) => Err(e),
            _ => Err("unexpected reply from vm"),
        }
    }

    fn read_register(&mut self, reg_id: BPFRegId, dst: &mut [u8]) -> TargetResult<(), Self> {
        self.req.send(VmRequest::ReadReg(reg_id)).unwrap();
        match self.reply.recv().unwrap() {
            VmReply::ReadReg(val) => {
                dst.copy_from_slice(&val.to_le_bytes());
                Ok(())
            }
            Err(e) => Err(e),
            _ => Err("unexpected reply from vm"),
        }
    }

    fn write_register(&mut self, reg_id: BPFRegId, val: &[u8]) -> TargetResult<(), Self> {
        if val.len() != 8 {
            return Err("invalid register value: wrong number of bytes");
        } else {
            self.req
                .send(VmRequest::WriteReg(reg_id.into(), u64::from_le_bytes(*val)))
                .unwrap();
            match self.reply.recv().unwrap() {
                VmReply::WriteReg => Ok(()),
                Err(e) => Err(e),
                _ => Err("unexpected reply from vm"),
            }
        }
    }

    fn read_addrs(&mut self, start_addr: usize, data: &mut [u8]) -> TargetResult<(), Self> {
        self.req
            .send(VmRequest::ReadAddr(start_addr, data.len()))
            .unwrap();
        match self.reply.recv().unwrap() {
            VmReply::ReadAddr(bytes) => {
                debug_assert!(
                    bytes.len() == data.len(),
                    "vm returned wrong number of bytes!"
                );
                dst.copy_from_slice(&bytes[..]);
                Ok(())
            }
            Err(e) => Err(e),
            _ => Err("unexpected reply from vm"),
        }
    }

    fn write_addrs(&mut self, start_addr: usize, data: &[u8]) -> TargetResult<(), Self> {
        self.req
            .send(VmRequest::WriteAddr(start_addr, data.len(), data.to_vec()))
            .unwrap();
        match self.reply.recv().unwrap() {
            VmReply::WriteAddr => Ok(()),
            Err(e) => Err(e),
            _ => Err("unexpected reply from vm"),
        }
    }
}
