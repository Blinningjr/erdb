use clap:: {
    Command,
    Arg,
    command,
    arg,
};

pub fn set_breakpoint_command() -> Command<'static> {
    Command::new("bkpt")
        .about("Set breakpoint")
        .alias("b")
        .arg_required_else_help(true)
}

pub fn clear_breakpoint_command() -> Command<'static> {
    Command::new("clear")
        .about("Clear a  breakpoint")
        .alias("c")
        .arg_required_else_help(true)
}

pub fn clear_breakpoints_command() -> Command<'static> {
    Command::new("clear-all")
        .about("Clear all breakpoint")
        .alias("ca")
}

pub fn breakpoint_subcommands() -> [Command<'static>; 3] {
    [
        set_breakpoint_command(),
        clear_breakpoint_command(),
        clear_breakpoints_command(),
    ]
}


pub fn breakpoint_commands() -> Command<'static> {
    Command::new("breakpoint")
        .about("Collection of breakpoint commands")
        .alias("b")
        .arg_required_else_help(true)
        .subcommands(breakpoint_subcommands()) 
}




pub fn attach_command() -> Command<'static> {
    Command::new("attach")
        .about("Attach to target")
        .alias("a")
}

pub fn continue_command() -> Command<'static> {
    Command::new("continue")
        .about("Continue halted program")
        .alias("c")
}

pub fn flash_command() -> Command<'static> {
    Command::new("flash")
        .about("Flash target")
        .alias("f")
        .arg_required_else_help(true)
}

pub fn halt_command() -> Command<'static> {
    Command::new("halt")
        .about("Halt running program")
        .alias("h")
}

pub fn reset_command() -> Command<'static> {
    Command::new("reset")
        .about("Reset the program")
        .alias("r")
}

pub fn step_command() -> Command<'static> {
    Command::new("step")
        .about("Step one machine code instruction")
        .alias("s")
}

pub fn target_subcommands() -> [Command<'static>; 6] {
    [
        attach_command(),
        continue_command(),
        flash_command(),
        halt_command(),
        reset_command(),
        step_command(),
    ]
}


pub fn target_commands() -> Command<'static> {
    Command::new("target")
        .about("Collection of target commands")
        .alias("t")
        .arg_required_else_help(true)
        .subcommands(target_subcommands()) 
}



pub fn binary_command() -> Command<'static> {
    Command::new("binary")
        .about("Set file path to binary")
        .alias("b")
        .arg_required_else_help(true)
}

pub fn chip_command() -> Command<'static> {
    Command::new("chip")
        .about("Set chip model")
        .alias("c")
        .arg_required_else_help(true)
}

pub fn probe_command() -> Command<'static> {
    Command::new("probe")
        .about("Set probe id to use")
        .alias("c")
        .arg_required_else_help(true)
}

pub fn work_directory_command() -> Command<'static> {
    Command::new("work-directory")
        .about("Set program work directory")
        .alias("wd")
        .arg_required_else_help(true)
}


pub fn config_subcommands() -> [Command<'static>; 4] {
    [
        binary_command(),
        chip_command(),
        probe_command(),
        work_directory_command(),
    ]
}


pub fn config_commands() -> Command<'static> {
    Command::new("config")
        .about("Collection of configuration commands")
        .alias("c")
        .arg_required_else_help(true)
        .subcommands(config_subcommands())
}


pub fn disassemble_command() -> Command<'static> {
    Command::new("disassemble")
        .about("Disassemble the nearest code")
        .alias("d")
}

pub fn registers_command() -> Command<'static> {
    Command::new("registers")
        .about("Show all the register")
        .alias("r")
}

pub fn read_command() -> Command<'static> {
    Command::new("read")
        .about("Read bytes from memory address")
        .alias("r")
        .arg_required_else_help(true)
}

pub fn stack_command() -> Command<'static> {
    Command::new("stack")
        .about("Show stack frame")
        .alias("s")
}

pub fn stack_trace_command() -> Command<'static> {
    Command::new("stack-trace")
        .about("Show stack trace")
        .alias("st")
}

pub fn status_command() -> Command<'static> {
    Command::new("status")
        .about("Show MCU status")
}

pub fn variable_command() -> Command<'static> {
    Command::new("variable")
        .about("Show a variable")
        .alias("var")
        .arg_required_else_help(true)
}

pub fn variables_command() -> Command<'static> {
    Command::new("variables")
        .about("Show all local variables")
        .alias("var")
}


pub fn info_subcommands() -> [Command<'static>; 8] {
    [
        disassemble_command(),
        read_command(), 
        registers_command(),
        stack_command(),
        stack_trace_command(),
        status_command(),
        variable_command(),
        variables_command(),
    ]
}


pub fn info_commands() -> Command<'static> {
    Command::new("info")
        .about("Collection of debug info commands")
        .alias("i")
        .arg_required_else_help(true)
        .subcommands(info_subcommands())
}

pub fn exit_command() -> Command<'static> {
    Command::new("exit")
        .about("Exit the debugger")
        .alias("e")
}

pub fn all_erdb_commands() -> [Command<'static>; 5] {
    [
        breakpoint_commands(),
        config_commands(),
        exit_command(),
        info_commands(),
        target_commands(),
    ]
}

pub fn erdb_command() -> Command<'static> {
    command!("ERDB")
        .author("Blinningjr")
        .about("Embedded Rust Debugger")
        .arg_required_else_help(true)
        //.allow_external_subcommands(true)
        //.multicall(true)
        .subcommands(all_erdb_commands())
}
