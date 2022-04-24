mod cli;
mod commands;
mod debug_adapter;
mod debugger;

//use object::File;
//use gimli::EndianReader;


use commands::{
    debug_request::DebugRequest,
    //debug_response::DebugResponse,
    //debug_event::DebugEvent,
    commands::Commands,
};

use debug_adapter::DebugAdapter;


use log::info;

use rust_debug::utils::in_ranges;


use probe_rs::{Probe, Session};

use object::{Object, ObjectSection};

use gimli::{read::EndianRcSlice, DebugFrame, Dwarf, Error, LittleEndian, Reader, Section, Unit};

use futures::{
    executor::block_on,
    FutureExt,
    pin_mut,
    select,
    future::FusedFuture,
};
use structopt::StructOpt;

use anyhow::{anyhow, Context, Result};


use chrono::Local;
use env_logger::*;
use log::{error, LevelFilter};

// use async_std::{io, task, io::ReadExt};
use async_std::{io, task};
use async_std::net::{SocketAddr, TcpListener, TcpStream};
use async_std::io::BufReader;
//use async_std::io::{BufRead, BufReader, Read};


use std::path::Path;
use std::{borrow, fs};
use std::rc::Rc;
use std::time::Duration;
use std::path::PathBuf;
use std::str::FromStr;
use std::io::Write;


#[derive(Debug, Clone)]
enum Mode {
    Debug,
    DebugAdapter,
} impl FromStr for Mode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Debug" => Ok(Mode::Debug),
            "debug" => Ok(Mode::Debug),
            "DebugAdapter" => Ok(Mode::DebugAdapter),
            "server" => Ok(Mode::DebugAdapter),
            _ => Err("Error: invalid mode"),
        }
    }
}

#[derive(Debug, StructOpt, Clone)]
#[structopt(
    name = "embedded-rust-debugger",
    about = "A simple and extendable debugger for embedded Rust."
)]
pub struct Opt {
    /// Set Mode
    #[structopt(short = "m", long = "mode", default_value = "Debug")]
    mode: Mode,

    /// Set log level
    #[structopt(short = "v", long = "verbosity", default_value = "Off")]
    verbosity: LevelFilter,

    /// Elf file path
    #[structopt(short = "elf", long = "elf-file")]
    elf_file_path: Option<PathBuf>,

    /// Current working directory
    #[structopt(short = "wd", long = "work-directory")]
    work_directory: Option<String>,

    /// Type of Chip
    #[structopt(short = "c", long = "chip")]
    chip: Option<String>,

    /// Set Port: only required when `mode` is set to `DebugAdapter`
    #[structopt(
        short = "p",
        long = "port",
        required_if("mode", "DebugAdapter"),
        default_value = "8800"
    )]
    port: u16,
}

fn main() -> Result<()> {
    let future = async_main();
    block_on(future)
}


async fn async_main() -> Result<()> {
    let opt = Opt::from_args();

    // Setup log
    let log_level = opt.verbosity;
    let probe_rs_log_level = match log_level {
        LevelFilter::Debug => LevelFilter::Info,
        LevelFilter::Trace => LevelFilter::Info,
        LevelFilter::Info => LevelFilter::Warn,
        _ => log_level,
    };

    let mut builder = Builder::from_default_env();
    builder
        .format(|buf, record| {
            writeln!(
                buf,
                "{} {}:{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.level(),
                record.args()
            )
        })
        .filter(None, log_level)
        .filter_module("probe_rs", probe_rs_log_level)
        .init();

    match opt.mode {
        Mode::Debug => cli_mode(opt).await,
        Mode::DebugAdapter => server_mode(opt).await,
    }
}


/*
 *  Run the debugger as a CLI application.
 *
 *  1. Create needed data structures, like one for debugging state.
 *  2. Create the different tasks.
 *      * CLI: Text input to Request.
 *      * Poller Event: Timer that is used to tell the event loop to poll the state of the
 *      debug target device.
 *  3. Event loop: Handle the results from the tasks. 
 */
async fn cli_mode(opt: Opt) -> Result<()> {
    // Setup needed variables
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let commands = Commands::new();
    let sleep_duration = 100;

    let mut debug_handler = debugger::NewDebugHandler::new(opt, load_loader);

    // Create the tasks
    let cli_task = cli::handle_input(&stdin, &commands).fuse();
    let heartbeat_task = task::sleep(Duration::from_millis(sleep_duration)).fuse();
    pin_mut!(cli_task, heartbeat_task);

    // Event loop
    loop {
        select! {
            c = cli_task => {
                match c? {
                    DebugRequest::Help { description } => println!("{}", description),
                    request => {
                        // Execute request
                        let response = debug_handler.handle_request(request)?;

                        // Print response to user and exit if requested
                        if cli::handle_response(&mut stdout, &response)? {
                            break;
                        }
                    },
                };

                // Restart the task
                if cli_task.is_terminated() {
                    cli_task.set(cli::handle_input(&stdin, &commands).fuse())
                }
            },
            () = heartbeat_task => { 
                // Check if debug target state has changed
                if let Ok(Some(event)) = debug_handler.poll_state() {
                    cli::handle_event(&event);
                }

                // Restart the task
                if heartbeat_task.is_terminated() {
                    heartbeat_task.set(task::sleep(Duration::from_millis(sleep_duration)).fuse());
                }
            },
        }
    }

    Ok(())
}


/*
 * Run the CLI and TCP server listening for a new connection.
 * 
 * When new connection is established the server starts to listen for DAP messages
 * and continues with the CLI task.
 */
async fn server_mode(opt: Opt) -> Result<()> {
    // Setup needed variables
    let stdin = io::stdin();
//    let mut stdout = io::stdout();
    let sleep_duration = 100;

    // Setup TCP server
    let addr = SocketAddr::from(([127, 0, 0, 1], opt.port.clone()));
    let listner = TcpListener::bind(addr).await?;


    // Create the tasks
    let cli_task = cli::simple_handle_input(&stdin).fuse();
    let tcp_connect_task = listner.accept().fuse();
    pin_mut!(cli_task, tcp_connect_task);

    // Event loop
    loop {
        select! {
            c = cli_task => {
                if c? {
                    break;
                }

                // Restart the task
                if cli_task.is_terminated() {
                    cli_task.set(cli::simple_handle_input(&stdin).fuse())
                }
            },
            connection = tcp_connect_task => {
                let (socket, addr) = connection?;
                info!("Accepted connection from {}", addr);
                println!("Accepted connection from {}", addr);

                debug_server(opt.clone(), socket.clone(), &stdin).await?;

                if tcp_connect_task.is_terminated() {
                    tcp_connect_task.set(listner.accept().fuse());
                }
            }, 
        }
    }

    Ok(())
}

/*
 * Run the CLI, DAP server and Debugger tasks.
 * 
 * If connection is stopped then return to the previous state of listening for TCP connections.
 */
async fn debug_server(opt: Opt, socket: TcpStream, stdin: &io::Stdin) -> Result<()> {
    // Setup needed variables
    let sleep_duration = 100;
    

    // Setup debugger
    let mut debug_handler = debugger::NewDebugHandler::new(opt, load_loader);

    // Setup DAP server
//    let mut reader = BufReader::new(socket.clone());
    let writer = socket.clone();
    let mut debug_adapter = DebugAdapter::new(writer);

    // Create the tasks
    let cli_task = cli::simple_handle_input(&stdin).fuse();
    let heartbeat_task = task::sleep(Duration::from_millis(sleep_duration)).fuse();
    let msg_task = debug_adapter::read_dap_msg(BufReader::new(socket.clone())).fuse();

    // Pin the task to the stack
    pin_mut!(cli_task, heartbeat_task, msg_task);

    // Event loop
    loop {
        select! {
            c = cli_task => {
                if c? {
                    break;
                }

                // Restart the task
                if cli_task.is_terminated() {
                    cli_task.set(cli::simple_handle_input(&stdin).fuse())
                }
            },
            () = heartbeat_task => { 
                // Check if debug target state has changed
                if let Ok(Some(event)) = debug_handler.poll_state() {
                    debug_adapter.handle_event(event).await?;
                }

                // Restart the task
                if heartbeat_task.is_terminated() {
                    heartbeat_task.set(task::sleep(Duration::from_millis(sleep_duration)).fuse());
                }
            },
            dap_msg = msg_task => {
                let msg = dap_msg?;
                println!("< {:#?}", msg);
               
                // Recreate the task. 
                if msg_task.is_terminated() {
                    msg_task.set(debug_adapter::read_dap_msg(BufReader::new(socket.clone())).fuse());
                }

                // Handle DAP request.
                if debug_adapter.handle_dap_message(&mut debug_handler, msg).await? {
                    break;
                }
            }, 
        }
    }

    println!("Debug adapter session stopped");
    info!("Debug adapter session stopped");
    Ok(())
}



fn attach_probe(chip: &str, probe_num: usize) -> Result<Session> {
    // Get a list of all available debug probes.
    let probes = Probe::list_all();

    // Use the first probe found.
    let probe = match probes.len() > probe_num {
        true => probes[probe_num].open().context("Failed to open probe")?,
        false => return Err(anyhow!("Probe {} not available", probe_num)),
    };

    // Attach to a chip.
    let session = probe
        .attach_under_reset(chip)
        .context("Failed to attach probe to target")?;

    Ok(session)
}



fn load_loader(data: &[u8]) -> EndianRcSlice<LittleEndian> {
   gimli::read::EndianRcSlice::new(
       Rc::from(&*data),
       gimli::LittleEndian,
   )
}



fn read_dwarf<'a, R: Reader<Offset = usize>>(
    path: &Path,
    load_loader: fn(data: &[u8]) -> R,
) -> Result<(
    Dwarf<R>,
    DebugFrame<R>,
)> {
    let file = fs::File::open(&path)?;
    let mmap = unsafe { memmap::Mmap::map(&file)? };
    let object = object::File::parse(&*mmap)?;

    // Load a section and return as `Cow<[u8]>`.
    let loader = |id: gimli::SectionId| -> Result<R, gimli::Error> {
        let data = object
            .section_by_name(id.name())
            .and_then(|section| section.uncompressed_data().ok())
            .unwrap_or_else(|| borrow::Cow::Borrowed(&[][..]));

        
        Ok(load_loader(&*data))
    };

    // Load a supplementary section. We don't have a supplementary object file,
    // so always return an empty slice.
    //let sup_loader = |_| {
    //    Ok(EndianRcSlice::new(
    //        Rc::from(&*borrow::Cow::Borrowed(&[][..])),
    //        LittleEndian,
    //    ))
    //};

    // Load all of the sections.
    let dwarf = Dwarf::load(&loader)?; //, &sup_loader)?;

    let frame_section = DebugFrame::load(loader)?;

    Ok((dwarf, frame_section))
}

pub fn get_current_unit<'a, R>(dwarf: &'a Dwarf<R>, pc: u32) -> Result<Unit<R>, Error>
where
    R: Reader<Offset = usize>,
{
    // TODO: Maybe return a Vec of units
    let mut res = None;

    let mut iter = dwarf.units();
    let mut i = 0;
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        if Some(true) == in_ranges(pc, &mut dwarf.unit_ranges(&unit)?) {
            res = Some(unit);
            i += 1;
        }
    }

    if i > 1 {
        error!("Found more then one unit in range {}", i);
    }

    return match res {
        Some(u) => Ok(u),
        None => Err(Error::MissingUnitDie),
    };
}
