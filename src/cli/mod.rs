use async_std::io;

use super::commands::{
    commands::Commands, debug_event::DebugEvent, debug_request::DebugRequest,
    debug_response::DebugResponse,
};
use crate::debugger::StackFrame;
use crate::debugger::Variable;
use anyhow::{anyhow, Result};
use debugserver_types::Breakpoint;
use log::error;
use probe_rs::CoreStatus;

pub async fn handle_input(stdin: &io::Stdin, cmd_parser: &Commands) -> Result<DebugRequest> {
    loop {
        // Read next line asynchronously
        let mut line = String::new();
        stdin.read_line(&mut line).await?;

        let request = match cmd_parser.parse_command(line.as_ref()) {
            Ok(cmd) => cmd,
            Err(err) => {
                println!("Error: {:?}", err); // TODO: log
                continue;
            }
        };
        return Ok(request);
    }
}

pub async fn simple_handle_input(stdin: &io::Stdin) -> Result<bool> {
    loop {
        // Read next line asynchronously
        let mut line = String::new();
        stdin.read_line(&mut line).await?;

        return Ok(match line.as_str() {
            "q\n" => true,
            "quit\n" => true,
            "e\n" => true,
            "exit\n" => true,
            _ => false,
        });
    }
}

pub fn handle_response(stdout: &mut io::Stdout, response: Result<DebugResponse>) -> Result<bool> {
    match response {
        Ok(val) => match_debug_response(stdout, val),
        Err(err) => {
            println!("Error: {}", err);
            Ok(false)
        },
    }
}

fn match_debug_response(_stdout: &mut io::Stdout, response: DebugResponse) -> Result<bool> {
    match response {
        DebugResponse::Exit => return Ok(true),
        DebugResponse::Attach => handle_attach_response(),
        DebugResponse::Status { status, pc } => handle_status_response(status, pc),
        DebugResponse::Continue => handle_continue_response(),
        DebugResponse::Step => handle_step_response(),
        DebugResponse::Halt => handle_halt_response(),
        DebugResponse::SetBinary => handle_set_binary_response(),
        DebugResponse::Flash => handle_flash_response(),
        DebugResponse::Reset => handle_reset_response(),
        DebugResponse::Read { address, value } => handle_read_response(address, value),
        DebugResponse::StackTrace { stack_trace } => handle_stack_trace_response(stack_trace),
        DebugResponse::SetProbeNumber => handle_set_probe_number_response(),
        DebugResponse::SetChip => handle_set_chip_response(),
        DebugResponse::Variable { variable } => handle_variable_response(variable),
        DebugResponse::Variables { variables } => handle_variables_response(variables),
        DebugResponse::Registers { registers } => handle_registers_response(registers),
        DebugResponse::SetBreakpoint => handle_set_breakpoint_response(),
        DebugResponse::SetBreakpoints { breakpoints } => {
            handle_set_breakpoints_response(breakpoints)
        }
        DebugResponse::ClearBreakpoint => handle_clear_breakpoint_response(),
        DebugResponse::ClearAllBreakpoints => handle_clear_all_breakpoints_response(),
        DebugResponse::Code { pc, instructions } => handle_code_response(pc, instructions),
        DebugResponse::Stack {
            stack_pointer,
            stack,
        } => handle_stack_response(stack_pointer, stack),
        DebugResponse::Error { message } => handle_error_response(message),
        DebugResponse::SetCWD => handle_set_cwd_response(),
        DebugResponse::DAPStackFrames { stack_frames: _ } => {
            error!("Unreachable");
            return Err(anyhow!("Unreachable"));
        }
        DebugResponse::DAPScopes { scopes: _ } => {
            error!("Unreachable");
            return Err(anyhow!("Unreachable"));
        }
        DebugResponse::DAPVariables { variables: _ } => {
            error!("Unreachable");
            return Err(anyhow!("Unreachable"));
        }
    };

    Ok(false)
}

pub fn handle_event(event: &DebugEvent) {
    println!("{:?}", event);
    match event {
        DebugEvent::Halted {
            pc,
            reason,
            hit_breakpoint_ids: _,
        } => println!("Core halted at pc: {:#010x}, reason: {:?}", pc, reason),
    };
}

fn handle_attach_response() {
    println!("Debugger attached successfully");
}

fn handle_status_response(status: CoreStatus, pc: Option<u32>) {
    println!("Status: {:?}", &status);
    if status.is_halted() && pc.is_some() {
        println!("Core halted at address {:#010x}", pc.unwrap());
    }
}

fn handle_continue_response() {
    println!("Core is running");
}

fn handle_step_response() {
    return ();
}

fn handle_halt_response() {
    return ();
}

fn handle_set_binary_response() {
    println!("Binary file path set ");
}

fn handle_flash_response() {
    println!("Flash successful");
}

fn handle_reset_response() {
    println!("Target reset");
}

fn handle_read_response(address: u32, value: Vec<u8>) {
    // TODO
    let mut value_string = "".to_owned();

    let address_string = format!("0x{:08x}:", address);
    let mut spacer = "".to_string();
    for _ in 0..address_string.len() {
        spacer.push(' ');
    }

    let mut i = 0;
    for val in value {
        // TODO: print in right order.
        if i == 4 {
            value_string = format!("{}\n\t{} {:02x}", value_string, spacer, val);
            i = 0;
        } else {
            value_string = format!("{} {:02x}", value_string, val);
        }
        i += 1;
    }
    println!("\t{}{}", address_string, value_string);
}

fn handle_stack_trace_response(stack_trace: Vec<StackFrame>) {
    println!("\nStack Trace:");
    for sf in &stack_trace {
        print_stack_frame(sf);
    }
}

fn print_stack_frame(stack_frame: &StackFrame) {
    println!("\tName: {}", stack_frame.name);
    println!(
        "\tline: {:?}, column: {:?}, pc: {:?}",
        match stack_frame.source.line {
            Some(l) => l.to_string(),
            None => "< unknown >".to_string(),
        },
        match stack_frame.source.column {
            Some(l) => l.to_string(),
            None => "< unknown >".to_string(),
        },
        stack_frame.call_frame.code_location
    );
    println!(
        "\tfile: {}, directory: {}",
        match &stack_frame.source.file {
            Some(val) => val,
            None => "< unknown >",
        },
        match &stack_frame.source.file {
            Some(val) => val,
            None => "< unknown >",
        }
    );

    println!("\tArguments:");
    for var in &stack_frame.arguments {
        let name = match var.name.clone() {
            Some(n) => n,
            None => "< unknown >".to_owned(),
        };
        println!("\t\t{} = {}", name, var.value_to_string());
    }

    println!("\tVariables:");
    for var in &stack_frame.variables {
        let name = match var.name.clone() {
            Some(n) => n,
            None => "< unknown >".to_owned(),
        };
        println!("\t\t{} = {}", name, var.value_to_string());
    }
    println!("");
}

fn handle_set_probe_number_response() {
    println!("Probe number set ");
}

fn handle_set_chip_response() {
    println!("Chip set");
}

fn handle_variable_response(variable: Variable) {
    //println!("{:#?}", variable);

    let name = match variable.name.clone() {
        Some(n) => n,
        None => "< unknown >".to_owned(),
    };
    println!("\t{} = {}", name, variable.value_to_string());
    println!("\ttype = {}", variable.type_);
    match &variable.source {
        Some(source) => {
            match source.line {
                Some(line) => {
                    println!("\tline: {}", line);
                    match source.column {
                        Some(column) => println!("\tcolumn: {}", column),
                        None => (),
                    };
                }
                None => (),
            };
            match &source.file {
                Some(file) => {
                    println!("\tfile: {}", file);
                    match &source.directory {
                        Some(dir) => println!("\tdirectory: {}", dir),
                        None => (),
                    };
                }
                None => (),
            };
        }
        None => (),
    };
    //    println!("\tLocation: {:?}", variable.location);
}

fn handle_variables_response(variables: Vec<Variable>) {
    println!("Local variables:");
    for var in variables {
        handle_variable_response(var);
        println!("");
    }
}

fn handle_registers_response(registers: Vec<(String, u32)>) {
    println!("Registers:");
    for (name, value) in &registers {
        println!("\t{}: {:#010x}", name, value)
    }
}

fn handle_set_breakpoint_response() {
    println!("Breakpoint set");
}

fn handle_set_breakpoints_response(_breakpoints: Vec<Breakpoint>) {
    error!("Unreachable");
}

fn handle_clear_breakpoint_response() {
    println!("Breakpoint cleared");
}

fn handle_clear_all_breakpoints_response() {
    println!("All hardware breakpoints cleared");
}

fn handle_code_response(pc: u32, instructions: Vec<(u32, String)>) {
    println!("Assembly Code");
    for (address, asm) in instructions {
        let mut spacer = "  ";
        if address == pc {
            spacer = "> ";
        }
        println!("{}{}", spacer, asm);
    }
}

fn handle_stack_response(stack_pointer: u32, stack: Vec<u32>) {
    println!("Current stack value:");
    for i in 0..stack.len() {
        println!(
            "\t{:#010x}: {:#010x}",
            stack_pointer as usize + i * 4,
            stack[i]
        );
    }
}

fn handle_error_response(message: String) {
    println!("Error: {}", message);
}

fn handle_set_cwd_response() {
    println!("Current work directory set");
}
