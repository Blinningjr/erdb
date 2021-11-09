use std::path::PathBuf;

use debugserver_types::{
    SourceBreakpoint,
    Source,
};

#[derive(Debug, Clone)]
pub enum DebugRequest {
    Attach { reset: bool, reset_and_halt: bool },
    Status,
    Exit,
    Continue,
    Step,
    Halt,
    SetBinary { path: PathBuf },
    Flash { reset_and_halt: bool },
    Reset { reset_and_halt: bool }, 
    Read { address: u32, byte_size: usize },
    StackTrace,
    SetProbeNumber { number: usize },
    SetChip { chip: String },
    Variable { name: String },
    Variables,
    Registers,
    SetBreakpoint { address: u32, source_file: Option<String>},
    SetBreakpoints { source_file: String, source_breakpoints: Vec<SourceBreakpoint>, source: Option<Source> },
    ClearBreakpoint { address: u32 },
    ClearAllBreakpoints,
    Code,
    Stack,
    SetCWD { cwd: String },
    DAPStackFrames,
    DAPScopes{ frame_id: i64,},
    DAPVariables {id: i64},
}


