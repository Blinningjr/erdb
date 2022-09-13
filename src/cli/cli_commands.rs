use clap:: {
    Command,
    Arg,
    command,
    arg,
};

pub fn continue_command() -> Command<'static> {
    Command::new("continue")
        .about("Continue halted program")
        .alias("c")
}

pub fn halt_command() -> Command<'static> {
    Command::new("halt")
        .about("Halt running program")
        .alias("h")
}

pub fn target_subcommands() -> [Command<'static>; 2] {
    [
        continue_command(),
        halt_command(),
    ]
}


pub fn target_commands() -> Command<'static> {
    Command::new("target")
        .about("Collection of target commands")
        .alias("t")
        .subcommands(target_subcommands()) 
}


pub fn chip_command() -> Command<'static> {
    Command::new("chip")
        .about("Set chip model")
        .alias("c")
}

pub fn probe_command() -> Command<'static> {
    Command::new("probe")
        .about("Set probe id to use")
        .alias("c")
}


pub fn config_subcommands() -> [Command<'static>; 2] {
    [
        chip_command(),
        probe_command(),
    ]
}


pub fn config_commands() -> Command<'static> {
    Command::new("config")
        .about("Collection of configuration commands")
        .alias("c")
        .subcommands(config_subcommands())
}

pub fn all_erdb_commands() -> [Command<'static>; 2] {
    [
       config_commands(),
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
