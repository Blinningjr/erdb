use std::path::PathBuf;

use async_std::io::{BufReader, Read, ReadExt, Write, WriteExt};
use async_std::prelude::*;

use anyhow::{anyhow, Result};

use log::{debug, error, info, trace, warn};

use debugserver_types::{
    Breakpoint, Capabilities, ContinueResponseBody, DisconnectArguments, EvaluateResponseBody,
    Event, InitializedEvent, ProtocolMessage, Request, Response, SetBreakpointsArguments,
    SetBreakpointsResponseBody, StackTraceResponseBody, Thread, ThreadsResponseBody,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{from_slice, from_value, json, to_vec};

use gimli::Reader;

use super::{
    commands::{
        debug_event::DebugEvent, debug_request::DebugRequest, debug_response::DebugResponse,
    },
    debugger::NewDebugHandler,
};

use probe_rs::HaltReason;

pub struct DebugAdapter<W: Write + Unpin> {
    pub first_msg: bool,
    seq: i64,
    writer: W,
}

impl<W: Write + Unpin> DebugAdapter<W> {
    pub fn new(writer: W) -> DebugAdapter<W> {
        DebugAdapter {
            first_msg: true,
            seq: 0,
            writer: writer,
        }
    }

    pub async fn handle_dap_message<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        dap_msg: DebugAdapterMessage,
    ) -> Result<bool> {
        match dap_msg {
            DebugAdapterMessage::Request(req) => self.handle_dap_request(debug_handler, req).await,
            DebugAdapterMessage::Response(_res) => todo!(),
            DebugAdapterMessage::Event(_event) => todo!(),
        }
    }

    pub async fn handle_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: Request,
    ) -> Result<bool> {
        let result = match request.command.as_ref() {
            "initialize" => self.handle_init_dap_request(&request).await,
            "launch" => {
                self.handle_launch_dap_request(debug_handler, &request)
                    .await
            }
            "attach" => {
                self.handle_attach_dap_request(debug_handler, &request)
                    .await
            }
            "setBreakpoints" => {
                self.handle_set_breakpoints_dap_request(debug_handler, &request)
                    .await
            }
            "threads" => self.handle_threads_dap_request(&request).await,
            //  "setDataBreakpoints"        => Ok(()), // TODO
            //  "setExceptionBreakpoints"   => Ok(()), // TODO
            "configurationDone" => self.handle_configuration_done_dap_request(&request).await,
            "pause" => self.handle_pause_dap_request(debug_handler, &request).await,
            "stackTrace" => {
                self.handle_stack_trace_dap_request(debug_handler, &request)
                    .await
            }
            "disconnect" => {
                self.handle_disconnect_dap_request(debug_handler, &request)
                    .await
            }
            "continue" => {
                self.handle_continue_dap_request(debug_handler, &request)
                    .await
            }
            "scopes" => {
                self.handle_scopes_dap_request(debug_handler, &request)
                    .await
            }
            "source" => {
                error!("Unimpleemted");
                Ok(false) // NOTE: Return Error maybe
            }
            "variables" => {
                self.handle_variables_dap_request(debug_handler, &request)
                    .await
            }
            "next" => self.handle_next_dap_request(debug_handler, &request).await,
            "stepIn" => self.handle_next_dap_request(debug_handler, &request).await, // TODO
            "stepOut" => self.handle_next_dap_request(debug_handler, &request).await, // TODO
            "evaluate" => {
                self.handle_evaluate_dap_request(debug_handler, &request)
                    .await
            }
            _ => {
                error!("command: {}", request.command);
                Err(anyhow!("Unimpleemted command: {}", request.command))
                //Ok(false) // NOTE: Return Error maybe
            }
        };

        match result {
            Ok(v) => Ok(v),
            Err(err) => {
                warn!("Error when handeling DAP message: {}", err.to_string());
                let response = Response {
                    body: None,
                    command: request.command.clone(),
                    message: Some(err.to_string()),
                    request_seq: request.seq,
                    seq: self.seq,
                    success: false,
                    type_: "response".to_string(),
                };

                self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

                Ok(false)
            }
        }
    }

    pub async fn handle_event(&mut self, event: DebugEvent) -> Result<()> {
        debug!("event {:?}", event);
        match event {
            DebugEvent::Halted {
                pc: _,
                reason,
                hit_breakpoint_ids,
            } => {
                let (reason_str, description) = match reason {
                    HaltReason::Breakpoint => (
                        "breakpoint".to_owned(),
                        Some("Target stopped due to breakpoint.".to_owned()),
                    ),
                    _ => (format!("{:?}", reason), None),
                };
                let body = StoppedEventBody {
                    reason: reason_str,
                    description,
                    thread_id: Some(0),
                    preserve_focus_hint: None,
                    text: None,
                    all_threads_stopped: None,
                    hit_breakpoint_ids,
                };

                self.seq = send_data(
                    &mut self.writer,
                    &to_vec(&Event {
                        body: Some(json!(body)),
                        event: "stopped".to_owned(),
                        seq: self.seq,
                        type_: "event".to_owned(),
                    })?,
                    self.seq,
                )
                .await?;
            }
        };

        Ok(())
    }

    async fn handle_init_dap_request(&mut self, request: &Request) -> Result<bool> {
        self.first_msg = false;

        let capabilities = Capabilities {
            supports_configuration_done_request: Some(true), // Supports config after init request
            //            supports_data_breakpoints:              Some(true),
            //        supportsCancelRequest:                  Some(true),
            ..Default::default()
        };

        let resp = Response {
            body: Some(json!(capabilities)),
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&resp)?, self.seq).await?;

        self.seq = send_data(
            &mut self.writer,
            &to_vec(&InitializedEvent {
                seq: self.seq,
                body: None,
                type_: "event".to_owned(),
                event: "initialized".to_owned(),
            })?,
            self.seq,
        )
        .await?;

        Ok(false)
    }

    async fn handle_launch_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        let args: LaunchRequestArguments = get_arguments(&request)?;
        debug!("launch args: {:#?}", args);
        info!("program: {:?}", args.program);

        // Set binary path
        let path = PathBuf::from(args.program);
        let _sb_ack = debug_handler.handle_request(DebugRequest::SetBinary { path })?;

        // Set chip
        let _sc_ack = debug_handler.handle_request(DebugRequest::SetChip {
            chip: args.chip.clone(),
        })?;

        match args.cwd {
            Some(cwd) => {
                // Set Current Working Directory (CWD)
                let _cwd_ack = debug_handler.handle_request(DebugRequest::SetCWD { cwd })?;
            }
            None => return Err(anyhow!("Missing cwd")),
        };
        
        info!("Flashing");
        // Flash binary to target
        let flash_ack = debug_handler.handle_request(DebugRequest::Flash {
            reset_and_halt: args.halt_after_reset.unwrap_or(false)
        })?;
        info!("Done Flashing:{:?}", flash_ack);


        let response = Response {
            body: None,
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: request.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_attach_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        let args: AttachRequestArguments = get_arguments(&request)?;
        debug!("attach args: {:#?}", args);
        info!("program: {:?}", args.program);

        // Set binary path
        let path = PathBuf::from(args.program);
        let _sb_ack = debug_handler.handle_request(DebugRequest::SetBinary { path })?;

        // Set chip
        let _sc_ack = debug_handler.handle_request(DebugRequest::SetChip {
            chip: args.chip.clone(),
        })?;

        match args.cwd {
            Some(cwd) => {
                // Set Current Working Directory (CWD)
                let _cwd_ack = debug_handler.handle_request(DebugRequest::SetCWD { cwd })?;
            }
            None => return Err(anyhow!("Missing cwd")),
        };

        // Attach to target
        let _attach_ack = debug_handler.handle_request(DebugRequest::Attach {
            reset: args.reset.unwrap_or(false),
            reset_and_halt: args.halt_after_reset.unwrap_or(false),
        })?;

        let response = Response {
            body: None,
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: request.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_configuration_done_dap_request(&mut self, request: &Request) -> Result<bool> {
        let response = Response {
            body: None,
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_threads_dap_request(&mut self, request: &Request) -> Result<bool> {
        let body = ThreadsResponseBody {
            threads: vec![Thread {
                id: 0,
                name: "Main Thread".to_string(),
            }],
        };

        let response = Response {
            body: Some(json!(body)),
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_pause_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        // Send halt DebugRequest
        let _ack = debug_handler.handle_request(DebugRequest::Halt)?;

        let response = Response {
            body: None,
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };
        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_stack_trace_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        let args: debugserver_types::StackTraceArguments = get_arguments(&request)?;
        debug!("args: {:?}", args);

        // Get DAP stack frames
        let ack = debug_handler.handle_request(DebugRequest::DAPStackFrames)?;

        // Get stack frames from response
        let stack_frames = match ack {
            DebugResponse::DAPStackFrames { stack_frames } => stack_frames,
            _ => {
                error!("Unreachable");
                return Err(anyhow!("Unreachable"));
            }
        };

        let total_frames = stack_frames.len() as i64;
        let body = StackTraceResponseBody {
            stack_frames,
            total_frames: Some(total_frames),
        };

        let response = Response {
            body: Some(json!(body)),
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_scopes_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        let args: debugserver_types::ScopesArguments = get_arguments(&request)?;
        debug!("args: {:?}", args);

        // Get stack trace
        let ack = debug_handler.handle_request(DebugRequest::DAPScopes {
            frame_id: args.frame_id,
        })?;

        // Get scopes from response.
        let scopes = match ack {
            DebugResponse::DAPScopes { scopes } => scopes,
            _ => {
                error!("Unreachable");
                vec![]
            }
        };

        let body = debugserver_types::ScopesResponseBody { scopes };

        let response = Response {
            body: Some(json!(body)),
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_variables_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        let args: debugserver_types::VariablesArguments = get_arguments(&request)?;
        debug!("args: {:?}", args);

        // Get stack trace
        let ack = debug_handler.handle_request(DebugRequest::DAPVariables {
            id: args.variables_reference,
        })?;

        // Get variables from debugger response
        let vars = match ack {
            DebugResponse::DAPVariables { variables } => variables,
            _ => {
                error!("Unreachable");
                return Err(anyhow!("Unreachable"));
            }
        };

        // Parse variables
        let mut variables = vec![];

        for var in &vars {
            let (indexed_variables, named_variables) = var.get_num_diff_children();
            variables.push(debugserver_types::Variable {
                evaluate_name: None, //Option<String>,
                indexed_variables: Some(indexed_variables),
                name: var.name.clone().unwrap_or("<unknown>".to_string()),
                named_variables: Some(named_variables),
                presentation_hint: None,
                type_: Some(var.type_.clone()),
                value: var.value_to_string(),
                variables_reference: var.id, // i64,
            });
        }

        let body = debugserver_types::VariablesResponseBody { variables };

        let response = Response {
            body: Some(json!(body)),
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_continue_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        // Send continue DebugRequest
        let _ack = debug_handler.handle_request(DebugRequest::Continue)?;

        let body = ContinueResponseBody {
            all_threads_continued: Some(true),
        };

        let response = Response {
            body: Some(json!(body)),
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_disconnect_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        let args: DisconnectArguments = get_arguments(&request)?;
        debug!("args: {:?}", args);
        // TODO: Stop the debuggee, if conditions are meet

        // Send Exit DebugRequest
        let _ack = debug_handler.handle_request(DebugRequest::Exit)?;

        let response = Response {
            body: None,
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(true)
    }

    async fn handle_next_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        // Send Step DebugRequest
        let _ack = debug_handler.handle_request(DebugRequest::Step)?;

        // Send response
        let response = Response {
            body: None,
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };
        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_evaluate_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        _debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        // TODO: Implement this feature
        let body = EvaluateResponseBody {
            result: "This feature is not yet implemented".to_owned(),
            variables_reference: 0.0,
            type_: None,
            indexed_variables: None,
            named_variables: None,
            presentation_hint: None,
        };

        let response = Response {
            body: Some(json!(body)),
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }

    async fn handle_set_breakpoints_dap_request<R: Reader<Offset = usize>>(
        &mut self,
        debug_handler: &mut NewDebugHandler<R>,
        request: &Request,
    ) -> Result<bool> {
        let args: SetBreakpointsArguments = get_arguments(request)?;
        debug!("args: {:#?}", args);

        let source_breakpoints = match args.breakpoints {
            Some(bkpts) => bkpts,
            None => vec![],
        };

        let breakpoints: Vec<Breakpoint> = match args.source.path.clone() {
            Some(path) => {
                // Send SetBreakpoints DebugRequest
                let ack = debug_handler.handle_request(DebugRequest::SetBreakpoints {
                    source_file: path,
                    source_breakpoints,
                    source: Some(args.source.clone()),
                })?;

                // Handle response
                let breakpoints = match ack {
                    DebugResponse::SetBreakpoints { breakpoints } => breakpoints,
                    _ => {
                        error!("Unreachable: {:#?}", ack);
                        vec![]
                    }
                };
                breakpoints
            }
            None => vec![],
        };

        let body = SetBreakpointsResponseBody { breakpoints };

        let response = Response {
            body: Some(json!(body)),
            command: request.command.clone(),
            message: None,
            request_seq: request.seq,
            seq: self.seq,
            success: true,
            type_: "response".to_string(),
        };

        self.seq = send_data(&mut self.writer, &to_vec(&response)?, self.seq).await?;

        Ok(false)
    }
}

pub async fn read_dap_msg<R: Read + Unpin>(
    mut reader: BufReader<R>,
) -> Result<DebugAdapterMessage, anyhow::Error> {
    let mut header = String::new();

    reader.read_line(&mut header).await?;
    trace!("< {}", header.trim_end());

    // we should read an empty line here
    let mut buff = String::new();
    reader.read_line(&mut buff).await?;

    let len = get_content_len(&header)
        .ok_or_else(|| anyhow!("Failed to read content length from header '{}'", header))?;

    let mut content = vec![0u8; len];
    let _bytes_read = reader.read(&mut content).await?;

    // Extract protocol message
    let protocol_msg: ProtocolMessage = from_slice(&content)?;

    let msg = match protocol_msg.type_.as_ref() {
        "request" => DebugAdapterMessage::Request(from_slice(&content)?),
        "response" => DebugAdapterMessage::Response(from_slice(&content)?),
        "event" => DebugAdapterMessage::Event(from_slice(&content)?),
        other => return Err(anyhow!("Unknown message type: {}", other)),
    };

    trace!("< {:#?}", msg);
    Ok(msg)
}

fn get_content_len(header: &str) -> Option<usize> {
    let mut parts = header.trim_end().split_ascii_whitespace();

    // discard first part
    parts.next()?;
    parts.next()?.parse::<usize>().ok()
}

#[derive(Debug)]
pub enum DebugAdapterMessage {
    Request(Request),
    Response(Response),
    Event(Event),
}

pub fn get_arguments<T: DeserializeOwned>(req: &Request) -> Result<T> {
    let value = match req.arguments.as_ref() {
        Some(val) => val,
        None => {
            error!("Expected arguments");
            return Err(anyhow!("Expected arguments"));
        }
    };
    from_value(value.to_owned()).map_err(|e| e.into())
}

pub async fn send_data<W: Write + Unpin>(writer: &mut W, raw_data: &[u8], seq: i64) -> Result<i64> {
    let resp_body = raw_data;

    let resp_header = format!("Content-Length: {}\r\n\r\n", resp_body.len());

    println!("> {}", resp_header.trim_end());
    println!("> {}", std::str::from_utf8(resp_body)?);
    trace!("> {}", resp_header.trim_end());
    trace!("> {}", std::str::from_utf8(resp_body)?);

    writer.write(resp_header.as_bytes()).await?;
    writer.write(resp_body).await?;

    writer.flush().await?;

    Ok(seq + 1)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StoppedEventBody {
    pub all_threads_stopped: Option<bool>,
    pub description: Option<String>,
    pub preserve_focus_hint: Option<bool>,
    pub reason: String,
    pub text: Option<String>,
    pub thread_id: Option<i64>,
    pub hit_breakpoint_ids: Option<Vec<u32>>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct AttachRequestArguments {
    program: String,
    chip: String,
    cwd: Option<String>,
    reset: Option<bool>,
    halt_after_reset: Option<bool>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct LaunchRequestArguments {
    program: String,
    chip: String,
    cwd: Option<String>,
    no_debug: Option<bool>,
    halt_after_reset: Option<bool>,
}
