pub mod commands;
pub mod debug_event;
pub mod debug_request;
pub mod debug_response;

pub enum Command {
    Request(debug_request::DebugRequest),
    Response(debug_response::DebugResponse),
    Event(debug_event::DebugEvent),
}
