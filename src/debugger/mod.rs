pub mod config;

use config::Config;

use rust_debug::call_stack::{CallFrame, MemoryAccess};
use rust_debug::evaluate::evaluate::{get_udata, BaseTypeValue, EvaluatorValue};
use rust_debug::registers::Registers;
use rust_debug::source_information::{find_breakpoint_location, SourceInformation};

use std::num::NonZeroU64;

use gimli::DebugFrame;
use gimli::Dwarf;
use gimli::Reader;

use super::commands::{
    debug_event::DebugEvent, debug_request::DebugRequest, debug_response::DebugResponse,
};

use super::Opt;
use super::{attach_probe, read_dwarf};
use anyhow::{anyhow, Context, Result};
use capstone::arch::BuildsCapstone;
use debugserver_types::{Breakpoint, SourceBreakpoint};
use log::{error, info, warn};
use probe_rs::flashing::{download_file, Format};
use probe_rs::{CoreStatus, MemoryInterface};
use regex::Regex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str;
use std::time::Duration;

pub struct NewDebugHandler<R: Reader<Offset = usize>> {
    config: Config,
    session: Option<DebugSession<R>>,
    load_loader: fn(data: &[u8]) -> R,
}
impl<R: Reader<Offset = usize>> NewDebugHandler<R> {
    pub fn new(opt: Opt, load_loader: fn(data: &[u8]) -> R) -> NewDebugHandler<R> {
        NewDebugHandler {
            config: Config::new(opt),
            session: None,
            load_loader,
        }
    }

    pub fn handle_request(&mut self, request: DebugRequest) -> Result<DebugResponse> {
        Ok(match request {
            DebugRequest::Exit => DebugResponse::Exit,
            DebugRequest::SetBinary { path } => {
                self.config.binary_file_path = Some(path);
                DebugResponse::SetBinary
            }
            DebugRequest::SetProbeNumber { number } => {
                self.config.probe_num = number;
                DebugResponse::SetProbeNumber
            }
            DebugRequest::SetChip { chip } => {
                self.config.chip = Some(chip);
                DebugResponse::SetChip
            }
            DebugRequest::SetCWD { cwd } => {
                self.config.work_directory = Some(cwd);
                DebugResponse::SetCWD
            }
            _ => match &mut self.session {
                Some(session) => session.handle_request(request)?,
                None => {
                    if self.config.is_missing_config() {
                        DebugResponse::Error {
                            message: self.config.missing_config_message(),
                        }
                    } else {
                        self.session = Some(DebugSession::new(
                            match self.config.binary_file_path.clone() {
                                Some(val) => val,
                                None => {
                                    unreachable!();
                                }
                            },
                            self.config.probe_num,
                            match self.config.chip.clone() {
                                Some(val) => val,
                                None => {
                                    unreachable!();
                                }
                            },
                            match self.config.work_directory.clone() {
                                Some(val) => val,
                                None => {
                                    unreachable!();
                                }
                            },
                            self.load_loader,
                        )?);
                        self.handle_request(request)?
                    }
                }
            },
        })
    }

    pub fn poll_state(&mut self) -> Result<Option<DebugEvent>> {
        match &mut self.session {
            Some(session) => session.poll_state(),
            None => Ok(None),
        }
    }
}

pub struct DebugSession<R: Reader<Offset = usize>> {
    debug_info: DebugInformation<R>,
    session: probe_rs::Session,
    capstone: capstone::Capstone,
    breakpoints: HashMap<u32, Breakpoint>,
    file_path: PathBuf,
    cwd: String,
    running: bool,
    registers: Registers,
    stack_trace: Option<Vec<StackFrame>>,
    id_gen: IdGen,
    stack_frames: Option<Vec<debugserver_types::StackFrame>>,
    scopes: Option<HashMap<i64, Vec<debugserver_types::Scope>>>,
    variables: Option<HashMap<i64, Vec<Variable>>>,
    trace: bool,
}

impl<R: Reader<Offset = usize>> DebugSession<R> {
    pub fn new(
        file_path: PathBuf,
        probe_number: usize,
        chip: String,
        cwd: String,
        load_loader: fn(data: &[u8]) -> R,
    ) -> Result<DebugSession<R>> {
        let capstone = capstone::Capstone::new() // TODO: Set the capstone base on the arch of the chip.
            .arm()
            .mode(capstone::arch::arm::ArchMode::Thumb)
            .build()
            .expect("Failed to create Capstone object");

        let (owned_dwarf, owned_debug_frame) = read_dwarf::<R>(&file_path, load_loader)?;
        let debug_info = DebugInformation::new(owned_dwarf, owned_debug_frame);

        let mut session = attach_probe(&chip, probe_number)?;

        let (pc_reg, link_reg, sp_reg) = {
            let core = session.core(0)?;
            let pc_reg = probe_rs::RegisterId::from(core.registers().program_counter()).0 as usize;
            let link_reg = probe_rs::RegisterId::from(core.registers().return_address()).0 as usize;
            let sp_reg = probe_rs::RegisterId::from(core.registers().stack_pointer()).0 as usize;
            (pc_reg, link_reg, sp_reg)
        };
        let mut registers = Registers::default();
        registers.program_counter_register = Some(pc_reg);
        registers.link_register = Some(link_reg);
        registers.stack_pointer_register = Some(sp_reg);
        Ok(DebugSession {
            debug_info,
            session,
            capstone,
            breakpoints: HashMap::new(),
            file_path,
            cwd,
            running: true,
            registers,
            stack_trace: None,
            stack_frames: None,
            scopes: None,
            variables: None,
            id_gen: IdGen::new(),
            trace: false,
        })
    }

    pub fn handle_request(&mut self, request: DebugRequest) -> Result<DebugResponse> {
        match request {
            DebugRequest::Attach {
                reset,
                reset_and_halt,
            } => self.attach_command(reset, reset_and_halt),
            DebugRequest::Stack => self.stack_command(),
            DebugRequest::Code => self.code_command(),
            DebugRequest::ClearAllBreakpoints => self.clear_all_breakpoints_command(),
            DebugRequest::ClearBreakpoint { address } => self.clear_breakpoint_command(address),
            DebugRequest::SetBreakpoint {
                address,
                source_file,
            } => self.set_breakpoint_command(address, source_file),
            DebugRequest::Registers => self.registers_command(),
            DebugRequest::Variable { name } => self.variable_command(&name),
            DebugRequest::Variables => self.variables_command(),
            DebugRequest::StackTrace => self.stack_trace_command(),
            DebugRequest::Read { address, byte_size } => self.read_command(address, byte_size),
            DebugRequest::Reset {
                reset_and_halt: rah,
            } => self.reset_command(rah),
            DebugRequest::Flash {
                reset_and_halt: rah,
            } => self.flash_command(rah),
            DebugRequest::Halt => self.halt_command(),
            DebugRequest::Status => self.status_command(),
            DebugRequest::Continue => self.continue_command(),
            DebugRequest::Step => self.step_command(),
            DebugRequest::SetBreakpoints {
                source_file,
                source_breakpoints,
                source,
            } => self.set_breakpoints_command(source_file, source_breakpoints, source),
            DebugRequest::DAPStackFrames => self.dap_stack_frames(),
            DebugRequest::DAPScopes { frame_id } => self.dap_scopes(frame_id),
            DebugRequest::DAPVariables { id } => self.dap_variables(id),

            DebugRequest::CycleCounter => self.cycle_counter_command(),
            DebugRequest::Trace => self.trace_command(),

            _ => unreachable!(), //Ok(Command::Request(request)),
        }
    }

    pub fn poll_state(&mut self) -> Result<Option<DebugEvent>> {
        if self.running {
            let mut core = self.session.core(0)?;
            let status = core.status()?;
            if let CoreStatus::Halted(reason) = status {
                self.running = false;

                let pc = core.read_core_reg(core.registers().program_counter())?;
                let mut hit_breakpoint_ids = vec![];
                match self.breakpoints.get(&pc) {
                    Some(bkpt) => hit_breakpoint_ids.push(match bkpt.id {
                        Some(val) => val,
                        None => {
                            error!("Breakpoint id is required");
                            return Err(anyhow!("Breakpoint id is required"));
                        }
                    } as u32),
                    None => (),
                };

                if self.trace {
                    drop(core);
                    todo!(); //self.trace_event(pc);
                } else {
                    return Ok(Some(DebugEvent::Halted {
                        pc,
                        reason,
                        hit_breakpoint_ids: Some(hit_breakpoint_ids),
                    }));
                }
            }
        }

        Ok(None)
    }

    fn clear_temporaries(&mut self) {
        self.registers.clear();
        self.stack_trace = None;
        self.stack_frames = None;
        self.scopes = None;
        self.variables = None;
    }

    fn attach_command(&mut self, reset: bool, reset_and_halt: bool) -> Result<DebugResponse> {
        if reset_and_halt {
            self.clear_temporaries();
            let mut core = self.session.core(0)?;
            core.reset_and_halt(std::time::Duration::from_millis(10))
                .context("Failed to reset and halt the core")?;
        } else if reset {
            self.clear_temporaries();
            let mut core = self.session.core(0)?;
            core.reset().context("Failed to reset the core")?;
        }

        Ok(DebugResponse::Attach)
    }

    fn stack_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let status = core.status()?;

        if status.is_halted() {
            let sp_reg = probe_rs::RegisterId::from(core.registers().stack_pointer());

            let fp_reg = probe_rs::RegisterId::from(core.registers().frame_pointer());
            let fp: u32 = core.read_core_reg(fp_reg)?;
            let sp = core.read_core_reg(sp_reg)?;

            if fp < sp {
                // The previous stack pointer is less then current.
                // This happens when there is no stack.
                return Ok(DebugResponse::Stack {
                    stack_pointer: sp,
                    stack: vec![],
                });
            }

            let length = (((fp - sp) + 4 - 1) / 4) as usize;
            let mut stack = vec![0u32; length];
            core.read_32(sp.into(), &mut stack)?;

            Ok(DebugResponse::Stack {
                stack_pointer: sp,
                stack,
            })
        } else {
            Err(anyhow!("Core must be halted"))
        }
    }

    fn code_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let status = core.status()?;

        if status.is_halted() {
            let pc = core.registers().program_counter();
            let pc_val = core.read_core_reg(pc)?;

            let mut code = [0u8; 16 * 2];

            core.read_8(pc_val, &mut code)?;

            let insns = self
                .capstone
                .disasm_all(&code, pc_val as u64)
                .expect("Failed to disassemble");

            let mut instructions = vec![];
            for i in insns.iter() {
                instructions.push((i.address() as u32, i.to_string()));
            }

            Ok(DebugResponse::Code {
                pc: pc_val,
                instructions,
            })
        } else {
            warn!("Core is not halted, status: {:?}", status);
            Err(anyhow!("Core must be halted"))
        }
    }

    fn clear_all_breakpoints_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        core.clear_all_hw_breakpoints()?;
        self.breakpoints = HashMap::new();

        info!("All breakpoints cleared");

        Ok(DebugResponse::ClearAllBreakpoints)
    }

    fn clear_breakpoint_command(&mut self, address: u32) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;

        match self.breakpoints.remove(&address) {
            Some(_bkpt) => {
                core.clear_hw_breakpoint(address.into())?;
                info!("Breakpoint cleared from: 0x{:08x}", address);
                Ok(DebugResponse::ClearBreakpoint)
            }
            None => {
                core.clear_hw_breakpoint(address.into())?;
                Err(anyhow!("Can't remove hardware breakpoint at {}", address))
            }
        }
    }

    fn set_breakpoint_command(
        &mut self,
        mut address: u32,
        source_file: Option<String>,
    ) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        address = match source_file {
            Some(path) => find_breakpoint_location(
                &self.debug_info.dwarf,
                &self.cwd,
                &path,
                match NonZeroU64::new(address as u64) {
                    Some(val) => val,
                    None => {
                        error!("Could not convert address to NonZeroU64");
                        return Err(anyhow!("Could not convert address to NonZeroU64"));
                    }
                },
                None,
            )?
            .expect("Could not file location form source file line number")
                as u32,
            None => address,
        };

        let num_bkpt = self.breakpoints.len() as u32;
        let tot_bkpt = core.available_breakpoint_units()?;

        if num_bkpt < tot_bkpt {
            core.set_hw_breakpoint(address.into())?;

            let breakpoint = Breakpoint {
                id: Some(address as i64),
                verified: true,
                message: None,
                source: None, // TODO
                line: None,   // TODO
                column: None, // TODO
                end_line: None,
                end_column: None,
            };
            let _bkpt = self.breakpoints.insert(address, breakpoint);

            info!("Breakpoint set at: 0x{:08x}", address);
            Ok(DebugResponse::SetBreakpoint)
        } else {
            Err(anyhow!("All hardware breakpoints are already set"))
        }
    }

    fn registers_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let register_file = core.registers();

        let mut registers = vec![];
        for register in register_file.platform_registers() {
            let value = core.read_core_reg(register)?;

            registers.push((register.name().to_string(), value));
        }

        Ok(DebugResponse::Registers { registers })
    }

    fn variable_command(&mut self, name: &str) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let status = core.status()?;
        drop(core);

        match status.is_halted() {
            true => match &self.stack_trace {
                Some(stack_trace) => {
                    if stack_trace.is_empty() {
                        return Err(anyhow!("Variable {:?} not found", name));
                    }
                    let variable = match stack_trace[0].find_variable(name) {
                        Some(var) => var.clone(),
                        None => {
                            return Ok(DebugResponse::Error {
                                message: format!("Variable {:?} not found", name),
                            })
                        }
                    };

                    Ok(DebugResponse::Variable { variable })
                }
                None => {
                    self.set_stack_trace()?;
                    self.set_stack_frames()?;
                    self.variable_command(name)
                }
            },
            false => Err(anyhow!("Core must be halted")),
        }
    }

    fn variables_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let status = core.status()?;
        drop(core);

        match status.is_halted() {
            true => match &self.stack_trace {
                Some(stack_trace) => {
                    let variables = match stack_trace.len() {
                        0 => vec![],
                        _ => stack_trace[0].variables.clone(),
                    };

                    Ok(DebugResponse::Variables { variables })
                }
                None => {
                    self.set_stack_trace()?;
                    self.set_stack_frames()?;
                    self.variables_command()
                }
            },
            false => Err(anyhow!("Core must be halted")),
        }
    }

    fn stack_trace_command(&mut self) -> Result<DebugResponse> {
        match &self.stack_trace {
            Some(stack_trace) => Ok(DebugResponse::StackTrace {
                stack_trace: stack_trace.clone(),
            }),
            None => {
                self.set_stack_trace()?;
                self.set_stack_frames()?;
                self.stack_trace_command()
            }
        }
    }

    fn read_command(&mut self, address: u32, byte_size: usize) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let mut buff: Vec<u8> = vec![0; byte_size];
        core.read_8(address.into(), &mut buff)?;

        Ok(DebugResponse::Read {
            address,
            value: buff,
        })
    }

    fn reset_command(&mut self, reset_and_halt: bool) -> Result<DebugResponse> {
        if reset_and_halt {
            self.clear_temporaries();

            let mut core = self.session.core(0)?;
            core.reset_and_halt(std::time::Duration::from_millis(10))
                .context("Failed to reset and halt the core")?;
        } else {
            self.clear_temporaries();

            let mut core = self.session.core(0)?;
            core.reset().context("Failed to reset the core")?;
        }

        self.running = true;

        Ok(DebugResponse::Reset)
    }

    fn flash_command(&mut self, reset_and_halt: bool) -> Result<DebugResponse> {
        download_file(&mut self.session, &self.file_path, Format::Elf)
            .context("Failed to flash target")?;

        if reset_and_halt {
            self.clear_temporaries();

            let mut core = self.session.core(0)?;
            core.reset_and_halt(std::time::Duration::from_millis(10))
                .context("Failed to reset and halt the core")?;
        } else {
            self.clear_temporaries();

            let mut core = self.session.core(0)?;
            core.reset().context("Failed to reset the core")?;
        }

        self.running = true;

        Ok(DebugResponse::Flash)
    }

    fn halt_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let status = core.status()?;

        if status.is_halted() {
            warn!("Core is already halted, status: {:?}", status);
            return Err(anyhow!("Core is already halted"));
        } else {
            let cpu_info = core.halt(Duration::from_millis(100))?;
            info!("Core halted at pc = 0x{:08x}", cpu_info.pc);
        };

        Ok(DebugResponse::Halt)
    }

    fn status_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let status = core.status()?;
        let mut pc = None;

        if status.is_halted() {
            pc = Some(core.read_core_reg(core.registers().program_counter())?);
        }

        Ok(DebugResponse::Status { status, pc })
    }

    fn step_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let status = core.status()?;

        if status.is_halted() {
            let pc = continue_fix(&mut core, &self.breakpoints)?;
            self.running = true;
            info!("Stopped at pc = 0x{:08x}", pc);

            drop(core);

            self.clear_temporaries();
            return Ok(DebugResponse::Step);
        }

        Ok(DebugResponse::Error {
            message: "Can only step when core is halted".to_owned(),
        })
    }

    fn continue_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let mut status = core.status()?;

        if status.is_halted() {
            let _pc = continue_fix(&mut core, &self.breakpoints)?;
            core.run()?;
            self.running = true;
            status = core.status()?;

            drop(core);

            self.clear_temporaries();
        }

        info!("Core status: {:?}", status);

        Ok(DebugResponse::Continue)
    }

    fn set_breakpoints_command(
        &mut self,
        source_file: String,
        source_breakpoints: Vec<SourceBreakpoint>,
        source: Option<debugserver_types::Source>,
    ) -> Result<DebugResponse> {
        // Clear all existing breakpoints
        let mut core = self.session.core(0)?;
        core.clear_all_hw_breakpoints()?;
        self.breakpoints = HashMap::new();

        let mut breakpoints = vec![];
        for bkpt in source_breakpoints {
            let breakpoint = match find_breakpoint_location(
                &self.debug_info.dwarf,
                &self.cwd,
                &source_file,
                match NonZeroU64::new(bkpt.line as u64) {
                    Some(val) => val,
                    None => {
                        error!("Could not convert to NonZeroU64");
                        return Err(anyhow!("Could not convert to NonZeroU64"));
                    }
                },
                bkpt.column.map(|c| NonZeroU64::new(c as u64).unwrap()),
            )? {
                Some(address) => {
                    let mut breakpoint = Breakpoint {
                        id: Some(address as i64),
                        verified: true,
                        message: None,
                        source: source.clone(),
                        line: Some(bkpt.line),
                        column: bkpt.column,
                        end_line: None,
                        end_column: None,
                    };

                    // Set breakpoint
                    if self.breakpoints.len() < core.available_breakpoint_units()? as usize {
                        self.breakpoints.insert(address as u32, breakpoint.clone());
                        core.set_hw_breakpoint(address)?;
                    } else {
                        breakpoint.verified = false;
                    }

                    breakpoint
                }
                None => Breakpoint {
                    id: None,
                    verified: false,
                    message: None,
                    source: source.clone(),
                    line: Some(bkpt.line),
                    column: bkpt.column,
                    end_line: None,
                    end_column: None,
                },
            };

            breakpoints.push(breakpoint);
        }

        Ok(DebugResponse::SetBreakpoints { breakpoints })
    }

    fn dap_stack_frames(&mut self) -> Result<DebugResponse> {
        match &self.stack_frames {
            Some(stack_frames) => Ok(DebugResponse::DAPStackFrames {
                stack_frames: stack_frames.clone(),
            }),
            None => {
                self.set_stack_trace()?;
                self.set_stack_frames()?;
                self.dap_stack_frames()
            }
        }
    }

    fn dap_scopes(&mut self, frame_id: i64) -> Result<DebugResponse> {
        match &self.scopes {
            Some(scopes) => Ok(DebugResponse::DAPScopes {
                scopes: match scopes.get(&frame_id) {
                    Some(val) => val,
                    None => {
                        error!("Could not find scope");
                        return Err(anyhow!("Could not find scope"));
                    }
                }
                .clone(),
            }),
            None => {
                self.set_stack_trace()?;
                self.set_stack_frames()?;
                self.dap_stack_frames()
            }
        }
    }

    fn dap_variables(&mut self, vars_id: i64) -> Result<DebugResponse> {
        match &self.variables {
            Some(variables) => Ok(DebugResponse::DAPVariables {
                variables: match variables.get(&vars_id) {
                    Some(val) => val.clone(),
                    None => {
                        error!("Missing variables");
                        return Err(anyhow!("Missing variables"));
                    }
                },
            }),
            None => {
                self.set_stack_trace()?;
                self.set_stack_frames()?;
                self.dap_stack_frames()
            }
        }
    }

    pub fn set_variables(
        &mut self,
        variables: &mut HashMap<i64, Vec<Variable>>,
        mut children: Vec<Variable>,
        id: i64,
    ) -> Result<()> {
        for child in &mut children {
            if !child.children.is_empty() {
                child.id = self.id_gen.gen();
                self.set_variables(variables, child.children.clone(), child.id)?;
            }
        }
        variables.insert(id, children.clone());

        Ok(())
    }

    fn set_stack_trace(&mut self) -> Result<()> {
        let core = self.session.core(0)?;
        let mut my_core = MyCore { core };

        log::debug!("start stack trace");

        read_and_add_registers(&mut my_core.core, &mut self.registers)?;
        log::debug!("read registers");

        let stack_trace = rust_debug::call_stack::stack_trace(
            &self.debug_info.dwarf,
            &self.debug_info.debug_frame,
            self.registers.clone(),
            &mut my_core,
            &self.cwd,
        )
        .unwrap();
        log::debug!("stack trace done");
        self.stack_trace = Some(resolve_stack_trace(stack_trace, &mut my_core.core)?);

        Ok(())
    }

    fn set_stack_frames(&mut self) -> Result<()> {
        let mut stack_frames = vec![];
        let mut scopes = HashMap::new();
        let mut variables = HashMap::new();

        let mut vars = vec![];

        for s in self.stack_trace.as_ref().unwrap() {
            let source_info = SourceInformation::get_from_address(
                &self.debug_info.dwarf,
                s.call_frame.code_location as u64,
                &self.cwd,
            )?;

            let id = self.id_gen.gen();
            {
                let mut scope = vec![];
                let source = debugserver_types::Source {
                    // TODO: Make path os independent?
                    name: source_info.file.clone(),
                    path: match &source_info.directory {
                        Some(dir) => source_info
                            .file
                            .as_ref()
                            .map(|file| format!("{}/{}", dir, file)),
                        None => None,
                    },
                    source_reference: None,
                    presentation_hint: None,
                    origin: None,
                    sources: None,
                    adapter_data: None,
                    checksums: None,
                };
                {
                    let (indexed, named) = get_num_diff_children(&s.variables);
                    let scope_id = self.id_gen.gen();
                    scope.push(debugserver_types::Scope {
                        column: source_info.column.map(|v| v.get() as i64),
                        end_column: None,
                        end_line: None,
                        expensive: false,
                        indexed_variables: Some(indexed),
                        named_variables: Some(named),
                        line: source_info.line.map(|v| v.get() as i64),
                        name: "locale".to_owned(),
                        source: Some(source.clone()),
                        variables_reference: scope_id,
                    });
                    vars.push((s.variables.clone(), scope_id));
                }
                {
                    let (indexed, named) = get_num_diff_children(&s.arguments);
                    let scope_id = self.id_gen.gen();
                    scope.push(debugserver_types::Scope {
                        column: source_info.column.map(|v| v.get() as i64),
                        end_column: None,
                        end_line: None,
                        expensive: false,
                        indexed_variables: Some(indexed),
                        named_variables: Some(named),
                        line: source_info.line.map(|v| v.get() as i64),
                        name: "arguments".to_owned(),
                        source: Some(source),
                        variables_reference: scope_id,
                    });
                    vars.push((s.arguments.clone(), scope_id));
                }
                {
                    let (indexed, named) = get_num_diff_children(&s.registers);
                    let scope_id = self.id_gen.gen();
                    scope.push(debugserver_types::Scope {
                        column: None,
                        end_column: None,
                        end_line: None,
                        expensive: false,
                        indexed_variables: Some(indexed),
                        named_variables: Some(named),
                        line: None,
                        name: "registers".to_owned(),
                        source: None,
                        variables_reference: scope_id,
                    });
                    vars.push((s.registers.clone(), scope_id));
                }
                scopes.insert(id, scope);
            }

            // Create Source object
            let source = debugserver_types::Source {
                name: source_info.file.clone(),
                path: match &source_info.directory {
                    // TODO: Make path os independent?
                    Some(dir) => source_info
                        .file
                        .as_ref()
                        .map(|file| format!("{}/{}", dir, file)),
                    None => None,
                },
                source_reference: None,
                presentation_hint: None,
                origin: None,
                sources: None,
                adapter_data: None,
                checksums: None,
            };

            // Crate and add StackFrame object
            stack_frames.push(debugserver_types::StackFrame {
                id,
                name: s.name.clone(),
                source: Some(source),
                line: match source_info.line {
                    Some(v) => v.get() as i64,
                    None => 1,
                },
                column: match source_info.column {
                    Some(v) => v.get() as i64,
                    None => 1,
                },
                end_column: None,
                end_line: None,
                module_id: None,
                presentation_hint: Some("normal".to_owned()),
            });
        }
        for (vs, sid) in vars {
            self.set_variables(&mut variables, vs, sid)?;
        }

        self.stack_frames = Some(stack_frames);
        self.scopes = Some(scopes);
        self.variables = Some(variables);
        Ok(())
    }

    // A simple example of a custom command
    fn cycle_counter_command(&mut self) -> Result<DebugResponse> {
        let mut core = self.session.core(0)?;
        let (pc_val, cycle_counter) = read_cycle_counter(&mut core)?;
        println!("pc: {:#010x}, cycle counter: {}", pc_val, cycle_counter);
        drop(core);
        self.status_command()
    }

    // A more advanced stateful command
    fn trace_command(&mut self) -> Result<DebugResponse> {
        self.trace = true;
        self.continue_command()
    }

    fn trace_event(&mut self, _pc_val: u32) -> Result<()> {
        let mut core = self.session.core(0)?;
        let (pc_val, cycle_counter) = read_cycle_counter(&mut core)?;
        println!("pc: {:#010x}, cycle counter: {}", pc_val, cycle_counter);

        match read_bkpt(&mut core, pc_val) {
            Ok(nr) => {
                // intermediate trace point
                let bkpt_type = match nr {
                    1 => "end",
                    2 => "enter",
                    3 => "exit",
                    _ => "other",
                };
                println!("Halted on: {}", bkpt_type);
                if nr == 1 {
                    // trace end terminated

                    self.trace = false;
                    self.running = false;
                    Ok(())
                } else {
                    // intermediate break point
                    // continue
                    drop(core);
                    self.continue_command()?;
                    Ok(())
                }
            }

            Err(err) => Err(anyhow!(err)),
        }
    }
}

fn read_cycle_counter(core: &mut probe_rs::Core) -> Result<(u32, u32), probe_rs::Error> {
    let mut buff: Vec<u32> = vec![0; 1];
    core.read_32(0xe0001004, &mut buff)?;
    let pc = core.registers().program_counter();
    let pc_val = core.read_core_reg(pc)?;
    Ok((pc_val, buff[0]))
}

fn read_bkpt(core: &mut probe_rs::Core, pc_val: u32) -> Result<u8, probe_rs::Error> {
    let mut code = [0u8; 2];
    core.read_8(pc_val.into(), &mut code)?;
    if code[1] == 0b1011_1110 {
        // 0b1011_1110 is the binary encoding of the BKPT #NR instruction
        // code[0] holds the breakpoint number #NR (0..255)
        Ok(code[0])
    } else {
        Err(probe_rs::Error::Other(anyhow!("Breakpoint expected")))
    }
}

fn continue_fix(
    core: &mut probe_rs::Core,
    breakpoints: &HashMap<u32, Breakpoint>,
) -> Result<u32, probe_rs::Error> {
    if let probe_rs::CoreStatus::Halted(r) = core.status()? {
        if r == probe_rs::HaltReason::Breakpoint {
            let pc = core.registers().program_counter();
            let pc_val = core.read_core_reg(pc)?;

            match read_bkpt(core, pc_val) {
                Ok(_) => {
                    // For now we treat all breakpoints equally
                    // NOTE: Increment with 2 because bkpt is 2 byte instruction.
                    let step_pc = pc_val + 0x2; // TODO: Fix for other CPU types.
                    core.write_core_reg(pc.into(), step_pc)?;

                    return Ok(step_pc);
                }
                Err(_) => {
                    match breakpoints.get(&pc_val) {
                        Some(_bkpt) => {
                            core.clear_hw_breakpoint(pc_val.into())?;
                            let pc = core.step()?.pc;
                            core.set_hw_breakpoint(pc_val.into())?;
                            return Ok(pc as u32);
                        }
                        None => (),
                    };
                }
            }
        }
    }

    Ok(core.step()?.pc as u32)
}

pub struct MyCore<'a> {
    pub core: probe_rs::Core<'a>,
}

impl MemoryAccess for MyCore<'_> {
    fn get_address(&mut self, address: &u32, num_bytes: usize) -> Option<Vec<u8>> {
        let mut buff = vec![0u8; num_bytes];
        match self.core.read_8((*address).into(), &mut buff) {
            Ok(_) => (),
            Err(_) => return None,
        };
        Some(buff)
    }
}

fn read_and_add_registers(core: &mut probe_rs::Core, registers: &mut Registers) -> Result<()> {
    let register_file = core.registers();
    for register in register_file.platform_registers() {
        let value = core.read_core_reg(register)?;
        registers.add_register_value(probe_rs::RegisterId::from(register).0, value);
    }

    Ok(())
}

#[derive(Debug)]
pub struct DebugInformation<R: Reader<Offset = usize>> {
    pub dwarf: Dwarf<R>,
    pub debug_frame: DebugFrame<R>,
    pub breakpoints: Vec<u32>,
}

impl<R: Reader<Offset = usize>> DebugInformation<R> {
    pub fn new(dwarf: Dwarf<R>, debug_frame: DebugFrame<R>) -> DebugInformation<R> {
        DebugInformation {
            dwarf,
            debug_frame,
            breakpoints: vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub enum VariableKind {
    Indexed,
    Named,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Variable {
    pub id: i64,
    pub name: Option<String>,
    pub value: String,
    pub type_: String,
    pub source: Option<SourceInformation>,
    pub kind: VariableKind,
    pub children: Vec<Variable>,
}

impl Variable {
    pub fn get_num_diff_children(&self) -> (i64, i64) {
        get_num_diff_children(&self.children)
    }

    pub fn value_to_string(&self) -> String {
        self.value_to_string_recursive(true)
    }

    fn value_to_string_recursive(&self, first: bool) -> String {
        let mut result = self.value.to_string();
        if !first {
            match self.name.clone() {
                Some(name) => result = format!("{}: {}", name, self.value),
                None => (),
            };
        }

        if !self.children.is_empty() {
            result = format!("{} {{", result);
            for child in &self.children {
                result = format!("{} {},", result, child.value_to_string_recursive(false));
            }
            result = format!("{} }}", result);
        }
        result
    }

    pub fn resolve_varialbe<R: Reader<Offset = usize>>(
        var: &rust_debug::variable::Variable<R>,
        core: &mut probe_rs::Core,
    ) -> Result<Variable> {
        //        println!("raw_var: {:#?}\n\n", var);
        //match var.name.clone() {
        //    Some(v) => {
        //        if v == "test_str" {
        //            println!("test_u32: {:#?}", var);
        //        }
        //    },
        //    _=>(),
        //};
        let mut variable = Variable {
            id: 0,
            name: var.name.clone(),
            value: "This should be overwritten with the correct value".to_string(),
            type_: "".to_owned(),
            source: var.source.clone(),
            kind: VariableKind::Unknown,
            children: vec![],
        };

        variable.evaluate(&var.value, &var.source, core)?;

        //println!("p_variable: {:#?}\n\n", variable);

        Ok(variable)
    }

    fn evaluate<R: Reader<Offset = usize>>(
        &mut self,
        value: &EvaluatorValue<R>,
        source: &Option<SourceInformation>,
        core: &mut probe_rs::Core,
    ) -> Result<()> {
        match value {
            EvaluatorValue::Value(val, _) => {
                self.value = format!("{}", val);
                self.type_ = format!("{}::{}", self.type_, val.get_type());
            }
            EvaluatorValue::PointerTypeValue(pointer_type) => {
                match &pointer_type.name {
                    Some(name) => self.type_ = format!("{}::{}", self.type_, name),
                    None => (),
                };
                self.evaluate(&pointer_type.value, source, core)?;
            }
            EvaluatorValue::VariantValue(variant_value) => {
                let name = variant_value.discr_value.map(|val| format!("{}", val));
                let mut variable = Variable {
                    id: 0,
                    name,
                    value: match variant_value.discr_value {
                        Some(val) => format!("{}", val),
                        None => "< OptimizedOut >".to_owned(),
                    },
                    type_: "u64".to_string(),
                    source: source.clone(),
                    kind: VariableKind::Indexed,
                    children: vec![],
                };
                variable.evaluate(
                    &EvaluatorValue::Member(Box::new(variant_value.child.clone())),
                    source,
                    core,
                )?;
                self.children.push(variable);
            }
            EvaluatorValue::VariantPartValue(variant_part) => {
                match &variant_part.variant {
                    Some(variant) => {
                        self.evaluate(
                            &EvaluatorValue::Member(Box::new(variant.clone())),
                            source,
                            core,
                        )?;
                        let mut child = self.children.pop().ok_or_else(|| anyhow!("Error"))?;
                        match &child.name {
                            Some(_) => (),
                            None => child.name = Some("< Variant >".to_owned()),
                        };
                        self.children.push(child);
                    }
                    None => {
                        //let variable = Variable {
                        //    name: Some("< Variant >".to_owned()),
                        //    value: "< OptimizedOut >".to_owned(),
                        //    type_: "u64".to_string(),
                        //    source: source.clone(),
                        //       kind: VariableKind::Unknown,
                        //    children: vec![],
                        //};
                        //self.children.push(variable);
                    }
                };
                for variant_value in &variant_part.variants {
                    self.evaluate(
                        &EvaluatorValue::VariantValue(Box::new(variant_value.clone())),
                        source,
                        core,
                    )?;
                }
            }
            EvaluatorValue::SubrangeTypeValue(subrange_type_value) => {
                match subrange_type_value.count {
                    Some(count) => {
                        let variable = Variable {
                            id: 0,
                            name: Some("< Length >".to_owned()),
                            value: format!("{}", count),
                            type_: "u64".to_owned(),
                            source: source.clone(),
                            kind: VariableKind::Named,
                            children: vec![],
                        };
                        self.children.push(variable);
                    }
                    None => {
                        match subrange_type_value.base_type_value.clone() {
                            Some((base_type_value, loc)) => {
                                let mut variable = Variable {
                                    id: 0,
                                    name: Some("< Length >".to_owned()),
                                    value: "".to_owned(),
                                    type_: "".to_owned(),
                                    source: source.clone(),
                                    kind: VariableKind::Named,
                                    children: vec![],
                                };
                                variable.evaluate(
                                    &EvaluatorValue::<R>::Value(base_type_value, loc),
                                    source,
                                    core,
                                )?;
                                self.children.push(variable);
                            }
                            None => {
                                //let variable = Variable {
                                //    name: Some("< Length >".to_owned()),
                                //    value: "< OptimizedOut >".to_owned(),
                                //    type_: "u64".to_owned(),
                                //    source: source.clone(),
                                //    children: vec![],
                                //};
                                //self.children.push(variable);
                            }
                        };
                    }
                };
            }
            EvaluatorValue::Bytes(bt) => {
                self.value = format!("{:?}", bt);
                self.type_ = format!("{}::{}", self.type_, "< Bytes >");
            }
            EvaluatorValue::Array(array_type_value) => {
                self.value = "".to_owned();
                self.evaluate(
                    &EvaluatorValue::<R>::SubrangeTypeValue(
                        array_type_value.subrange_type_value.clone(),
                    ),
                    source,
                    core,
                )?;
                for i in 0..array_type_value.values.len() {
                    let mut variable = Variable {
                        id: 0,
                        name: Some(format!("{}", i)),
                        value: "< OptimizedOut >".to_owned(),
                        type_: "".to_owned(),
                        source: source.clone(),
                        kind: VariableKind::Indexed,
                        children: vec![],
                    };
                    variable.evaluate(&array_type_value.values[i], source, core)?;
                    self.children.push(variable);
                }
            }
            EvaluatorValue::Struct(structure_type_value) => {
                //self.name = Some(structure_type_value.name.clone());

                self.kind = VariableKind::Named;
                self.type_ = format!("{}::{}", self.type_, structure_type_value.name.clone());

                let name = structure_type_value.name.clone();
                if name.contains("str") || name.contains("String") {
                    // TODO: Redesign how string are evaluated

                    let mut num_bytes = 0;
                    let mut address = 0;
                    for member in &structure_type_value.members {
                        match member {
                            EvaluatorValue::Member(m) => {
                                match m.value.clone() {
                                    EvaluatorValue::PointerTypeValue(ptv) => {
                                        match ptv.address.clone() {
                                            EvaluatorValue::Value(v, _) => {
                                                address = match v {
                                                    BaseTypeValue::Address32(a) => a,
                                                    //BaseTypeValue::Generic(a) => a as u32,
                                                    BaseTypeValue::U8(a) => a as u32,
                                                    BaseTypeValue::U16(a) => a as u32,
                                                    BaseTypeValue::U32(a) => a,
                                                    //BaseTypeValue::U64(a) => a as u32,
                                                    _ => unimplemented!(),
                                                };
                                            }
                                            _ => panic!("ptv.value: {:#?}", ptv.value),
                                        };
                                    }
                                    EvaluatorValue::Value(v, _) => {
                                        num_bytes = match v {
                                            BaseTypeValue::Address32(a) => a as usize,
                                            BaseTypeValue::Generic(a) => a as usize,
                                            BaseTypeValue::U8(a) => a as usize,
                                            BaseTypeValue::U16(a) => a as usize,
                                            BaseTypeValue::U32(a) => a as usize,
                                            BaseTypeValue::U64(a) => a as usize,
                                            _ => unimplemented!(),
                                        };
                                    }
                                    _ => panic!("m: {:#?}", m.value),
                                };
                            }
                            _ => unreachable!(),
                        };
                    }
                    let mut raw_string = vec![0u8; num_bytes];
                    core.read_8(address.into(), &mut raw_string)?;
                    match str::from_utf8(raw_string.as_ref()) {
                        Ok(v) => self.value = format!("{:?}", v),
                        Err(_err) => {
                            self.value = structure_type_value.name.clone();
                            for member in &structure_type_value.members {
                                self.evaluate(member, source, core)?;
                            }
                        }
                    };
                } else {
                    self.value = structure_type_value.name.clone();
                    for member in &structure_type_value.members {
                        self.evaluate(member, source, core)?;
                    }
                }
            }
            EvaluatorValue::Enum(enumeration_type_value) => {
                self.kind = VariableKind::Named;
                // self.name = Some(enumeration_type_value.name.clone());
                self.type_ = format!("{}::{}", self.type_, enumeration_type_value.name.clone());
                self.value = "< OptimizedOut >".to_owned();
                match &enumeration_type_value.variant {
                    EvaluatorValue::Value(base_type_value, _) => {
                        let variant = get_udata(base_type_value.clone())?;
                        for enu in &enumeration_type_value.enumerators {
                            if enu.const_value == variant {
                                match &enu.name {
                                    Some(name) => self.value = name.clone(),
                                    None => (),
                                };
                            }
                        }
                    }
                    _ => {
                        error!("Unimplemented");
                        return Err(anyhow!("Unimplemented"));
                    }
                };
            }
            EvaluatorValue::Union(union_type_value) => {
                //self.name = Some(union_type_value.name.clone());
                self.kind = VariableKind::Named;
                self.type_ = format!("{}::{}", self.type_, union_type_value.name);
                for member in &union_type_value.members {
                    self.evaluate(member, source, core)?;
                }
            }
            EvaluatorValue::Member(member_value) => {
                let mut kind = VariableKind::Unknown;

                let name = match member_value.name.clone() {
                    Some(name) => {
                        let re = Regex::new(r"__\d+").unwrap();
                        if re.is_match(&name) {
                            let index = match name[2..].parse::<i32>() {
                                Ok(val) => val,
                                Err(err) => {
                                    error!("{:?}", err);
                                    return Err(anyhow!("{:?}", err));
                                }
                            };
                            kind = VariableKind::Indexed;
                            Some(format!("{}", index))
                        } else {
                            kind = VariableKind::Named;
                            Some(name)
                        }
                    }
                    None => None,
                };

                let mut variable = Variable {
                    id: 0,
                    name,
                    value: "< OptimizedOut >".to_owned(),
                    type_: "".to_owned(),
                    source: source.clone(),
                    kind,
                    children: vec![],
                };
                variable.evaluate(&member_value.value, source, core)?;
                self.children.push(variable);
            }
            EvaluatorValue::OptimizedOut => self.value = "< OptimizedOut >".to_string(),
            EvaluatorValue::LocationOutOfRange => self.value = "< LocationOutOfRange >".to_string(),
            EvaluatorValue::ZeroSize => self.value = "< OptimizedOut >".to_string(),
        };
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub name: String,
    pub call_frame: CallFrame,
    pub source: SourceInformation,
    pub variables: Vec<Variable>,
    pub arguments: Vec<Variable>,
    pub registers: Vec<Variable>,
}

impl StackFrame {
    pub fn resolve_stackframe<R: Reader<Offset = usize>>(
        frame: &rust_debug::call_stack::StackFrame<R>,
        core: &mut probe_rs::Core,
    ) -> Result<StackFrame> {
        let mut variables = vec![];
        for var in &frame.variables {
            variables.push(Variable::resolve_varialbe(var, core)?);
        }

        let mut arguments = vec![];
        for var in &frame.arguments {
            arguments.push(Variable::resolve_varialbe(var, core)?);
        }

        let mut registers = vec![];
        for var in &frame.registers {
            registers.push(Variable::resolve_varialbe(var, core)?);
        }

        Ok(StackFrame {
            name: frame.name.clone(),
            call_frame: frame.call_frame.clone(),
            source: frame.source.clone(),
            variables,
            arguments,
            registers,
        })
    }

    pub fn find_variable(&self, name: &str) -> Option<&Variable> {
        for v in &self.variables {
            match &v.name {
                Some(var_name) => {
                    if *var_name == name {
                        return Some(v);
                    }
                }
                None => (),
            };
        }
        None
    }
}

pub fn resolve_stack_trace<R: Reader<Offset = usize>>(
    stack_frames: Vec<rust_debug::call_stack::StackFrame<R>>,
    core: &mut probe_rs::Core,
) -> Result<Vec<StackFrame>> {
    let mut stack_trace = vec![];
    for sf in &stack_frames {
        stack_trace.push(StackFrame::resolve_stackframe(sf, core)?);
    }
    Ok(stack_trace)
}

pub struct IdGen {
    next_id: i64,
}

impl IdGen {
    pub fn new() -> IdGen {
        IdGen { next_id: 0 }
    }

    pub fn gen(&mut self) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

pub fn get_num_diff_children(children: &Vec<Variable>) -> (i64, i64) {
    let mut indexed_children = 0;
    let mut named_children = 0;
    for child in children {
        match child.kind {
            VariableKind::Indexed => indexed_children += 1,
            VariableKind::Named => named_children += 1,
            _ => (),
        };
    }

    (indexed_children, named_children)
}
