use crate::debugger::StackFrame;
use crate::debugger::Variable;
use debugserver_types::Breakpoint;
use probe_rs::CoreStatus;

#[derive(Debug, Clone)]
pub enum DebugResponse {
    Attach,
    Status {
        status: CoreStatus,
        pc: Option<u32>,
    },
    Exit,
    Continue,
    Step,
    Halt,
    SetBinary,
    Flash,
    Reset,
    Read {
        address: u32,
        value: Vec<u8>,
    },
    StackTrace {
        stack_trace: Vec<StackFrame>,
    },
    SetProbeNumber,
    SetChip,
    Variable {
        variable: Variable,
    },
    Variables {
        variables: Vec<Variable>,
    },
    Registers {
        registers: Vec<(String, u32)>,
    },
    SetBreakpoint,
    SetBreakpoints {
        breakpoints: Vec<Breakpoint>,
    },
    ClearBreakpoint,
    ClearAllBreakpoints,
    Code {
        pc: u32,
        instructions: Vec<(u32, String)>,
    },
    Stack {
        stack_pointer: u32,
        stack: Vec<u32>,
    },
    Error {
        message: String,
    },
    SetCWD,
    DAPStackFrames {
        stack_frames: Vec<debugserver_types::StackFrame>,
    },
    DAPScopes {
        scopes: Vec<debugserver_types::Scope>,
    },
    DAPVariables {
        variables: Vec<Variable>,
    },
}
