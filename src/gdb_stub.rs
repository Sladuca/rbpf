use gdbstub::{
    arch,
    target::{
        ext::{
            base::{
                singleThread::{Offsets, ResumeAction, SingleThreadOps, StopReason},
                BaseOps,
            },
            breakpoints::SwBreakpoint,
            section_offsets::{Offsets, SectionOffsets},
        },
        Target, TargetError, TargetResult,
    },
    DisconnectReason, GdbStub, GdbStubError,
};
use std::collections::HashSet;
use std::debug_assert;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::mpsc;

const BRPKT_MAP_THRESH: usize = 30;

const NUM_REGS: usize = 11;
const REG_NUM_BYTES: usize = NUM_REGS * 8;

// TODO make this not use unwrap
// TODO add support for Unix Domain Sockets
pub fn start_debug_server(
    port: u16,
    init_regs: &[u64; 11],
    init_pc: u64,
) -> (mpsc::SyncSender<VmReply>, mpsc::Receiver<VmRequest>) {
    let conn = wait_for_gdb_connection(port).unwrap();
    let (mut target, tx, rx) = DebugServer::new(init_regs, init_pc);

    std::thread::spawn(move || {
        let mut debugger = GdbStub::new(conn);

        match debugger.run(&mut target) {
            Ok(disconnect_reason) => match disconnect_reason {
                DisconnectReason::Disconnect => println!("GDB client disconnected."),
                DisconnectReason::TargetHalted => println!("Target halted!"),
                DisconnectReason::Kill => println!("GDB client sent a kill command!"),
            },
            // Handle any target-specific errors
            Err(GdbStubError::TargetError(e)) => {
                println!("Target raised a fatal error: {:?}", e);
                // e.g: re-enter the debugging session after "freezing" a system to
                // conduct some post-mortem debugging
                debugger.run(&mut target).unwrap();
            }
            Err(e) => {
                eprintf!("Could not run Target {:?}", e);
            }
        }
    });

    (tx, rx)
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
    Few(Vec<usize>),
    Many(HashSet<usize>),
}

impl BreakpointTable {
    pub fn new() -> Self {
        BreakpointTable::Few(Vec::new())
    }

    pub fn check_breakpoint(&self, addr: usize) -> bool {
        match &*self {
            BreakpointTable::Few(addrs) => {
                for brkpt_addr in addrs.iter() {
                    if *brkpt_addr == addr {
                        return true;
                    }
                }
                return false;
            }
            BreakpointTable::Many(addrs) => addrs.contains(&addr),
        }
    }

    pub fn set_breakpoint(&mut self, addr: usize) {
        match *self {
            BreakpointTable::Few(ref mut addrs) => {
                if addrs.len() > BRPKT_MAP_THRESH {
                    let mut set = HashSet::<usize>::with_capacity(addrs.len() + 1);
                    set.insert(addr);
                    for (addr, brkpt_num) in addrs.iter() {
                        set.insert(*addr);
                    }
                    *self = BreakpointTable::Many(set);
                } else {
                    pairs.push(addr);
                }
            }
            BreakpointTable::Many(ref mut addrs) => {
                addrs.insert(addr);
            }
        }
    }

    pub fn remove_breakpoint(&mut self, addr: usize) {
        match *self {
            BreakpointTable::Few(ref mut addrs) => {
                if let Some(i) =
                    addrs
                        .iter()
                        .enumerate()
                        .find_map(|(i, address)| if *address = addr { Some(i) } else { None })
                {
                    addrs.remove(i);
                }
            }
            BreakpointTable::Many(ref mut addrs) => {
                addrs.remove(&addr);
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
                regs: BPFRegs {
                    regs: *regs,
                    pc: pc,
                },
            },
            reply_tx,
            req_rx,
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BPFRegs {
    regs: [u64; 11],
    pc: u64,
}

// TODO use something safer than transmute_copy
impl Registers for BPFRegs {
    fn gdb_serialize(&self, write_byte: impl FnMut(Option<u8>)) {
        let bytes: [u8; 12 * 8] = unsafe { std::mem::transmute_copy(self) };
        bytes.iter().for_each(write_byte(Some(b)));
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() != 12 * 8 {
            Err(())
        } else {
            let transmuted: Self = unsafe { std::mem::transmute_copy(bytes) };
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

    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        target::exp::base::BaseOps::SingleThread(self)
    }

    fn sw_breakpoint(&mut self) -> Option<SwBreakpointOps<Self>> {
        Some(self)
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
    SetBrkpt(usize),
    RemoveBrkpt(usize),
    Offsets,
    Detatch,
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
    SetBrkpt,
    RemoveBrkpt,
    Offsets(Offsets),
}

// TODO make this not use unwrap
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
                    Err(e) => Err(e.into()),
                    _ => Err("unexpected reply from vm"),
                }
            }
        }
    }

    fn read_registers(&mut self, regs: &mut BPFRegs) -> TargetResult<(), Self> {
        self.req.send(VmRequest::ReadRegs).unwrap();
        match self.reply.recv().unwrap() {
            VmReply::ReadRegs(regfile) => {
                *regs = unsafe { std::mem::transmute_copy(regfile) };
                Ok(())
            }
            Err(e) => Err(e.into()),
            _ => Err("unexpected reply from vm"),
        }
    }

    fn write_registers(&mut self, regs: &BPFRegs) -> TargetResult<(), Self> {
        let regfile: [u64; 12] = unsafe { std::mem::transmute_copy(*regs) };
        self.req.send(VmRequest::WriteRegs(regfile)).unwrap();
        match self.reply.recv().unwrap() {
            VmReply::WriteRegs => Ok(()),
            Err(e) => Err(e.into()),
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
            Err(e) => Err(e.into()),
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
                Err(e) => Err(e.into()),
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
            Err(e) => Err(e.into()),
            _ => Err("unexpected reply from vm"),
        }
    }

    fn write_addrs(&mut self, start_addr: usize, data: &[u8]) -> TargetResult<(), Self> {
        self.req
            .send(VmRequest::WriteAddr(start_addr, data.len(), data.to_vec()))
            .unwrap();
        match self.reply.recv().unwrap() {
            VmReply::WriteAddr => Ok(()),
            Err(e) => Err(e.into()),
            _ => Err("unexpected reply from vm"),
        }
    }
}

// TODO make this not use unwrap
impl SwBreakpoint for DebugServer {
    fn add_sw_breakpoint(&mut self, addr: usize) -> TargetResult<bool, Self> {
        self.req.send(VmRequest::SetBrkpt(usize)).unwrap();
        match self.reply.recv().unwrap() {
            VmReply::SetBrkpt => Ok(()),
            Err(e) => Err(e),
            _ => Err("unexpected reply from vm"),
        }
    }

    fn remove_sw_breakpoint(&mut self, addr: usize) -> TargetResult<bool, Self> {
        self.req.send(VmRequest::RemoveBrkpt(usize)).unwrap();
        match self.reply.recv().unwrap() {
            VmReply::RemoveBrkpt => Ok(),
            Err(e) => Err(e),
            _ => Err("unexpect reply from vm"),
        }
    }
}

// TODO make this not use unwrap
impl SectionOffsets for DebugServer {
    fn get_section_offsets(&mut self) -> Result<Offsets<usize>, Self::Error> {
        self.req.send(VmRequest::Offsets).unwrap();
        match self.reply.recv().unwrap() {
            VmReply::Offsets(offsets) => Ok(Offsets),
            Err(e) => Err(e),
            _ => Err("unexpect reply from vm"),
        }
    }
}
