use clap::{arg, command, value_parser, Arg, ArgAction, ArgMatches, Command};

use super::{DebugRequest, Result};
use std::path::PathBuf;

const BREAKPOINT_CMD: &str = "breakpoint";
const BKPT_SUB_CMD: &str = "set";
const CLEAR_SUB_CMD: &str = "clear";
const CLEAR_ALL_SUB_CMD: &str = "clear-all";

const CONFIG_CMD: &str = "config";
const BINARY_SUB_CMD: &str = "binary";
const CHIP_SUB_CMD: &str = "chip";
const PROBE_SUB_CMD: &str = "probe";
const WORK_DIR_SUB_CMD: &str = "work-directory";

const EXIT_CMD: &str = "exit";

const INFO_CMD: &str = "info";
const CYCLES_SUB_CMD: &str = "cycles";
const DISASSEMBLE_SUB_CMD: &str = "disassemble";
const READ_SUB_CMD: &str = "read";
const REGISTERS_SUB_CMD: &str = "registers";
const STACK_SUB_CMD: &str = "stack";
const STACK_TRACE_SUB_CMD: &str = "stack-trace";
const STATUS_SUB_CMD: &str = "status";
const TRACE_SUB_CMD: &str = "trace";
const VARIABLE_SUB_CMD: &str = "variable";
const VARIABLES_SUB_CMD: &str = "variables";

const TARGET_CMD: &str = "target";
const ATTACH_SUB_CMD: &str = "attach";
const CONTINUE_SUB_CMD: &str = "continue";
const FLASH_SUB_CMD: &str = "flash";
const HALT_SUB_CMD: &str = "halt";
const RESET_SUB_CMD: &str = "reset";
const STEP_SUB_CMD: &str = "step";

fn set_breakpoint_command() -> Command {
    Command::new(BKPT_SUB_CMD)
        .about("Set breakpoint")
        .alias("s")
        .arg(
            arg!([num] "Address or line number if file is given")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(arg!([file] "Source code file path").value_parser(value_parser!(String)))
    // TODO: Set as pathbuf
}

fn clear_breakpoint_command() -> Command {
    Command::new(CLEAR_SUB_CMD)
        .about("Clear breakpoint")
        .alias("c")
        .arg_required_else_help(true)
}

fn clear_breakpoints_command() -> Command {
    Command::new(CLEAR_ALL_SUB_CMD)
        .about("Clear all breakpoints")
        .alias("ca")
}

fn breakpoint_subcommands() -> [Command; 3] {
    [
        set_breakpoint_command(),
        clear_breakpoint_command(),
        clear_breakpoints_command(),
    ]
}

fn breakpoint_commands() -> Command {
    Command::new(BREAKPOINT_CMD)
        .about("Collection of breakpoint commands")
        .alias("bkpt")
        .arg_required_else_help(true)
        .subcommands(breakpoint_subcommands())
}

fn attach_command() -> Command {
    Command::new(ATTACH_SUB_CMD)
        .about("Attach debugger to target")
        .alias("a")
        .arg(
            Arg::new("reset")
                .short('r')
                .long("reset")
                .action(ArgAction::SetTrue)
                .help("Reset target"),
        )
        .arg(
            Arg::new("reset_and_halt")
                .short('s')
                .long("reset-and-halt")
                .action(ArgAction::SetTrue)
                .help("Reset and halt target"),
        )
}

fn continue_command() -> Command {
    Command::new(CONTINUE_SUB_CMD)
        .about("Continue halted program")
        .alias("c")
}

fn flash_command() -> Command {
    Command::new(FLASH_SUB_CMD)
        .about("Flash target")
        .alias("f")
        .arg(
            Arg::new("reset_and_halt")
                .short('s')
                .long("reset-and-halt")
                .action(ArgAction::SetTrue)
                .help("Reset and halt target"),
        )
}

fn halt_command() -> Command {
    Command::new(HALT_SUB_CMD)
        .about("Halt running program")
        .alias("h")
}

fn reset_command() -> Command {
    Command::new(RESET_SUB_CMD)
        .about("Reset target")
        .alias("r")
        .arg(
            Arg::new("reset_and_halt")
                .short('s')
                .long("reset-and-halt")
                .action(ArgAction::SetTrue)
                .help("Reset and halt target"),
        )
}

fn step_command() -> Command {
    Command::new(STEP_SUB_CMD)
        .about("Step one machine code instruction")
        .alias("s")
}

fn target_subcommands() -> [Command; 6] {
    [
        attach_command(),
        continue_command(),
        flash_command(),
        halt_command(),
        reset_command(),
        step_command(),
    ]
}

fn target_commands() -> Command {
    Command::new(TARGET_CMD)
        .about("Collection of target commands")
        .arg_required_else_help(true)
        .subcommands(target_subcommands())
}

fn binary_command() -> Command {
    Command::new(BINARY_SUB_CMD)
        .about("Set absolute file path to binary/Elf file")
        .alias("b")
        .arg(
            arg!([file] "Binary file path")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        ) // TODO: Set as pathbuf
}

fn chip_command() -> Command {
    Command::new(CHIP_SUB_CMD)
        .about("Set type of chip")
        .alias("c")
        .arg(
            arg!([chip] "Chip name")
                .value_parser(value_parser!(String))
                .default_value("STM32F411RETx"),
        )
}

fn probe_command() -> Command {
    Command::new(PROBE_SUB_CMD)
        .about("Set probe to debug with")
        .alias("p")
        .arg(
            arg!([num] "Probe number")
                .required(true)
                .default_value("0")
                .value_parser(value_parser!(usize)),
        )
}

fn work_directory_command() -> Command {
    Command::new(WORK_DIR_SUB_CMD)
        .about("Set current work directory absolute file path")
        .alias("wd")
        .arg_required_else_help(true)
        .arg(arg!([dir] "Work directory path").value_parser(value_parser!(String)))
    // TODO: Set as pathbuf
}

fn config_subcommands() -> [Command; 4] {
    [
        binary_command(),
        chip_command(),
        probe_command(),
        work_directory_command(),
    ]
}

fn config_commands() -> Command {
    Command::new(CONFIG_CMD)
        .about("Collection of configuration commands")
        .arg_required_else_help(true)
        .subcommands(config_subcommands())
}

fn cycles_command() -> Command {
    Command::new(CYCLES_SUB_CMD)
        .about("Print the value of the cycle counter")
        .alias("c")
}

fn disassemble_command() -> Command {
    Command::new(DISASSEMBLE_SUB_CMD)
        .about("Disassemble code at current location")
        .alias("d")
}

fn trace_command() -> Command {
    Command::new(TRACE_SUB_CMD)
        .about("Trace cycle counter at breakpoint instructions until `bkpt_end` is reached")
        .alias("t")
}

fn registers_command() -> Command {
    Command::new(REGISTERS_SUB_CMD)
        .about("Print registers")
        .alias("regs")
}

fn read_command() -> Command {
    Command::new(READ_SUB_CMD)
        .about("Read bytes from a memory address")
        .alias("r")
        .arg(
            arg!([address] "Memory address")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!([bytes] "Number of bytes to read")
                .required(true)
                .value_parser(value_parser!(usize)),
        )
}

fn stack_command() -> Command {
    Command::new(STACK_SUB_CMD).about("Print stack")
}

fn stack_trace_command() -> Command {
    Command::new(STACK_TRACE_SUB_CMD)
        .about("Print stack trace")
        .alias("st")
}

fn status_command() -> Command {
    Command::new(STATUS_SUB_CMD).about("Print target status")
}

fn variable_command() -> Command {
    Command::new(VARIABLE_SUB_CMD)
        .about("Show a variable")
        .alias("var")
        .arg(
            arg!([var] "Variable name")
                .required(true)
                .value_parser(value_parser!(String)),
        )
}

fn variables_command() -> Command {
    Command::new(VARIABLES_SUB_CMD)
        .about("Print all variables in scope")
        .alias("vars")
}

fn info_subcommands() -> [Command; 10] {
    [
        cycles_command(),
        disassemble_command(),
        trace_command(),
        read_command(),
        registers_command(),
        stack_command(),
        stack_trace_command(),
        status_command(),
        variable_command(),
        variables_command(),
    ]
}

fn info_commands() -> Command {
    Command::new(INFO_CMD)
        .about("Collection of debug info commands")
        .arg_required_else_help(true)
        .subcommands(info_subcommands())
}

fn exit_command() -> Command {
    Command::new(EXIT_CMD).about("Exit the debugger")
}

fn all_erdb_commands() -> [Command; 5] {
    [
        breakpoint_commands(),
        config_commands(),
        exit_command(),
        info_commands(),
        target_commands(),
    ]
}

fn erdb_command() -> Command {
    command!("ERDB")
        .author("Blinningjr")
        .about("Embedded Rust Debugger")
        .arg_required_else_help(true)
        //.allow_external_subcommands(true)
        //.multicall(true)
        .subcommands(all_erdb_commands())
}

fn get_command(matches: ArgMatches) -> Result<DebugRequest> {
    Ok(match matches.subcommand().unwrap() {
        (BREAKPOINT_CMD, cmd) => match cmd.subcommand().unwrap() {
            (BKPT_SUB_CMD, sub_cmd) => DebugRequest::SetBreakpoint {
                address: *sub_cmd.get_one::<u32>("address").unwrap(),
                source_file: sub_cmd.get_one::<String>("file").cloned(),
            },
            (CLEAR_SUB_CMD, sub_cmd) => DebugRequest::ClearBreakpoint {
                address: *sub_cmd.get_one::<u32>("address").unwrap(),
            },
            (CLEAR_ALL_SUB_CMD, _) => DebugRequest::ClearAllBreakpoints,
            _ => unreachable!(),
        },
        (CONFIG_CMD, cmd) => match cmd.subcommand().unwrap() {
            (BINARY_SUB_CMD, sub_cmd) => DebugRequest::SetBinary {
                path: sub_cmd.get_one::<PathBuf>("file").unwrap().clone(),
            },
            (CHIP_SUB_CMD, sub_cmd) => DebugRequest::SetChip {
                chip: sub_cmd.get_one::<String>("chip").unwrap().to_string(),
            },
            (PROBE_SUB_CMD, sub_cmd) => DebugRequest::SetProbeNumber {
                number: *sub_cmd.get_one::<usize>("chip").unwrap(),
            },
            (WORK_DIR_SUB_CMD, sub_cmd) => DebugRequest::SetCWD {
                cwd: sub_cmd.get_one::<String>("dir").unwrap().to_string(),
            },
            _ => unreachable!(),
        },
        (EXIT_CMD, _cmd) => DebugRequest::Exit,
        (INFO_CMD, cmd) => match cmd.subcommand().unwrap() {
            (CYCLES_SUB_CMD, _sub_cmd) => DebugRequest::CycleCounter,
            (DISASSEMBLE_SUB_CMD, _sub_cmd) => DebugRequest::Code,
            (READ_SUB_CMD, sub_cmd) => DebugRequest::Read {
                address: *sub_cmd.get_one::<u32>("address").unwrap(),
                byte_size: *sub_cmd.get_one::<usize>("bytes").unwrap(),
            },
            (REGISTERS_SUB_CMD, _sub_cmd) => DebugRequest::Registers,
            (STACK_SUB_CMD, _sub_cmd) => DebugRequest::Stack,
            (STACK_TRACE_SUB_CMD, _sub_cmd) => DebugRequest::StackTrace,
            (STATUS_SUB_CMD, _sub_cmd) => DebugRequest::Status,
            (TRACE_SUB_CMD, _sub_cmd) => DebugRequest::Trace,
            (VARIABLE_SUB_CMD, sub_cmd) => DebugRequest::Variable {
                name: sub_cmd.get_one::<String>("var").unwrap().clone(),
            },
            (VARIABLES_SUB_CMD, _sub_cmd) => DebugRequest::Variables,
            _ => unreachable!(),
        },
        (TARGET_CMD, cmd) => match cmd.subcommand().unwrap() {
            (ATTACH_SUB_CMD, sub_cmd) => DebugRequest::Attach {
                reset: *sub_cmd.get_one::<bool>("reset").unwrap(),
                reset_and_halt: *sub_cmd.get_one::<bool>("reset_and_halt").unwrap(),
            },
            (CONTINUE_SUB_CMD, _sub_cmd) => DebugRequest::Continue,
            (FLASH_SUB_CMD, sub_cmd) => DebugRequest::Flash {
                reset_and_halt: *sub_cmd.get_one::<bool>("reset_and_halt").unwrap(),
            },
            (HALT_SUB_CMD, _sub_cmd) => DebugRequest::Halt,
            (REGISTERS_SUB_CMD, _sub_cmd) => DebugRequest::Registers,
            (RESET_SUB_CMD, sub_cmd) => DebugRequest::Reset {
                reset_and_halt: *sub_cmd.get_one::<bool>("reset_and_halt").unwrap(),
            },
            (STEP_SUB_CMD, _sub_cmd) => DebugRequest::Step,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    })
}

pub fn parse_string_to_erdb_request(line: String) -> Result<Option<DebugRequest>> {
    let split_line = shellwords::split(&line)?;

    match erdb_command().try_get_matches_from(split_line) {
        Ok(val) => Ok(Some(get_command(val)?)),
        Err(err) => {
            let _a = err.print();
            Ok(None)
        }
    }
}

pub fn parse_string_simple_cli(line: String) -> Result<bool> {
    let split_line = shellwords::split(&line)?;

    match command!("ERDB")
        .author("Blinningjr")
        .about("Embedded Rust Debugger")
        .subcommand(exit_command())
        .arg_required_else_help(true)
        .try_get_matches_from(split_line)
    {
        Ok(_val) => Ok(true),
        Err(err) => {
            let _a = err.print();
            Ok(false)
        }
    }
}
