//! IPC port descriptors, open requests, and fixed-capacity port tables.

use crate::{DataClass, IpcError, IpcResult, IpcRights, TraceContext};

/// Maximum port name length.
pub const MAX_PORT_NAME_LEN: usize = 96;

/// Stable IPC port identifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PortId(pub u64);

impl PortId {
    /// Invalid port identifier.
    pub const INVALID: Self = Self(0);

    /// Creates a port identifier.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw identifier.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Validates the identifier.
    pub const fn validate(self) -> IpcResult<()> {
        if self.0 == 0 {
            return Err(IpcError::InvalidPort);
        }
        Ok(())
    }
}

/// IPC port kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortKind {
    /// Kernel subsystem port.
    Kernel = 0,
    /// Runtime service port.
    Runtime = 1,
    /// Userspace agent port.
    Agent = 2,
    /// Named service port.
    Service = 3,
    /// Device mediation port.
    Device = 4,
    /// Audit ingestion or query port.
    Audit = 5,
    /// Debug or diagnostics port.
    Debug = 6,
}

impl PortKind {
    /// Stable kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Runtime => "runtime",
            Self::Agent => "agent",
            Self::Service => "service",
            Self::Device => "device",
            Self::Audit => "audit",
            Self::Debug => "debug",
        }
    }

    /// Returns `true` when route or open operations should be audited.
    pub const fn audit_relevant(self) -> bool {
        matches!(
            self,
            Self::Kernel | Self::Device | Self::Audit | Self::Debug
        )
    }
}

/// Port lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortState {
    /// Port was allocated but not yet bound.
    Created = 0,
    /// Port has a stable name and owner.
    Bound = 1,
    /// Port accepts incoming messages.
    Listening = 2,
    /// Port is connected to a channel.
    Connected = 3,
    /// Port is draining and no longer accepts new messages.
    Draining = 4,
    /// Port is closed.
    Closed = 5,
    /// Port faulted.
    Faulted = 6,
}

impl PortState {
    /// Stable state label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Bound => "bound",
            Self::Listening => "listening",
            Self::Connected => "connected",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Faulted => "faulted",
        }
    }

    /// Returns `true` when the port can be opened or connected.
    pub const fn allows_connect(self) -> bool {
        matches!(self, Self::Bound | Self::Listening | Self::Connected)
    }

    /// Returns `true` when messages may be sent from or to this port.
    pub const fn allows_message(self) -> bool {
        matches!(self, Self::Listening | Self::Connected)
    }
}

/// Port descriptor published by kernel or runtime owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortDescriptor<'a> {
    /// Port identifier.
    pub id: PortId,
    /// Stable port name.
    pub name: &'a str,
    /// Port owner task or service identifier.
    pub owner: u64,
    /// Port kind.
    pub kind: PortKind,
    /// Lifecycle state.
    pub state: PortState,
    /// Rights required to connect to this port.
    pub required_rights: IpcRights,
    /// Maximum inline message length accepted by this port.
    pub max_message_len: u64,
    /// Receive queue capacity hint.
    pub queue_depth: usize,
    /// Diagnostic data class.
    pub data_class: DataClass,
    /// Whether connection or delivery is audit-critical.
    pub audit_required: bool,
}

impl<'a> PortDescriptor<'a> {
    /// Creates a descriptor for a named port.
    pub const fn new(id: PortId, name: &'a str, owner: u64, kind: PortKind) -> Self {
        Self {
            id,
            name,
            owner,
            kind,
            state: PortState::Bound,
            required_rights: IpcRights(crate::IPC_RIGHT_CONNECT),
            max_message_len: crate::channel::MAX_MESSAGE_BYTES,
            queue_depth: 16,
            data_class: DataClass::Operational,
            audit_required: kind.audit_relevant(),
        }
    }

    /// Sets lifecycle state.
    pub const fn with_state(mut self, state: PortState) -> Self {
        self.state = state;
        self
    }

    /// Sets required rights.
    pub const fn with_required_rights(mut self, required_rights: IpcRights) -> Self {
        self.required_rights = required_rights;
        self
    }

    /// Sets maximum message length and queue depth.
    pub const fn with_limits(mut self, max_message_len: u64, queue_depth: usize) -> Self {
        self.max_message_len = max_message_len;
        self.queue_depth = queue_depth;
        self
    }

    /// Sets data class.
    pub const fn with_data_class(mut self, data_class: DataClass) -> Self {
        self.data_class = data_class;
        self
    }

    /// Validates port metadata.
    pub fn validate(self) -> IpcResult<()> {
        self.id.validate()?;
        if self.name.is_empty() || self.owner == 0 {
            return Err(IpcError::MissingField);
        }
        if self.name.len() > MAX_PORT_NAME_LEN {
            return Err(IpcError::FieldTooLong);
        }
        IpcRights::from_bits(self.required_rights.bits())?;
        if self.max_message_len == 0 || self.max_message_len > crate::channel::MAX_MESSAGE_BYTES {
            return Err(IpcError::InvalidPort);
        }
        if self.queue_depth == 0 {
            return Err(IpcError::InvalidPort);
        }
        if matches!(self.state, PortState::Closed | PortState::Faulted) {
            return Err(IpcError::Closed);
        }
        Ok(())
    }
}

/// Request to open or connect to a port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortOpenRequest<'a> {
    /// Target port.
    pub port_id: PortId,
    /// Principal requesting access.
    pub principal: &'a str,
    /// Caller rights.
    pub rights: IpcRights,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> PortOpenRequest<'a> {
    /// Creates an open request.
    pub const fn new(port_id: PortId, principal: &'a str, rights: IpcRights) -> Self {
        Self {
            port_id,
            principal,
            rights,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates the request.
    pub fn validate(self) -> IpcResult<()> {
        self.port_id.validate()?;
        if self.principal.is_empty() {
            return Err(IpcError::MissingField);
        }
        if self.principal.len() > MAX_PORT_NAME_LEN {
            return Err(IpcError::FieldTooLong);
        }
        self.rights.require(IpcRights::CONNECT)?;
        self.trace.validate()
    }
}

/// Fixed-capacity port table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortTable<'a, const N: usize> {
    ports: [Option<PortDescriptor<'a>>; N],
    len: usize,
}

impl<'a, const N: usize> PortTable<'a, N> {
    /// Creates an empty port table.
    pub const fn new() -> Self {
        Self {
            ports: [None; N],
            len: 0,
        }
    }

    /// Returns registered port count.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns `true` when no ports are registered.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Registers one port.
    pub fn register(&mut self, descriptor: PortDescriptor<'a>) -> IpcResult<()> {
        if self.len >= N {
            return Err(IpcError::CapacityExceeded);
        }
        descriptor.validate()?;
        if self.contains_id(descriptor.id) {
            return Err(IpcError::DuplicatePort);
        }
        if self.contains_name(descriptor.name) {
            return Err(IpcError::DuplicatePort);
        }
        self.ports[self.len] = Some(descriptor);
        self.len += 1;
        Ok(())
    }

    /// Returns `true` when an identifier is registered.
    pub fn contains_id(self, id: PortId) -> bool {
        self.find_index(id).is_some()
    }

    /// Returns `true` when a name is registered.
    pub fn contains_name(self, name: &str) -> bool {
        let mut index = 0;
        while index < self.len {
            if self.ports[index].is_some_and(|port| port.name == name) {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Finds a port descriptor.
    pub fn get(self, id: PortId) -> Option<PortDescriptor<'a>> {
        self.find_index(id).and_then(|index| self.ports[index])
    }

    /// Applies a port open request and returns the descriptor.
    pub fn open(self, request: PortOpenRequest<'_>) -> IpcResult<PortDescriptor<'a>> {
        request.validate()?;
        let Some(port) = self.get(request.port_id) else {
            return Err(IpcError::PortNotFound);
        };
        port.validate()?;
        if !port.state.allows_connect() {
            return Err(IpcError::Closed);
        }
        request.rights.require(port.required_rights)?;
        Ok(port)
    }

    /// Updates port state.
    pub fn set_state(&mut self, id: PortId, state: PortState) -> IpcResult<()> {
        let Some(index) = self.find_index(id) else {
            return Err(IpcError::PortNotFound);
        };
        let Some(mut port) = self.ports[index] else {
            return Err(IpcError::Internal);
        };
        port.state = state;
        self.ports[index] = Some(port);
        Ok(())
    }

    fn find_index(self, id: PortId) -> Option<usize> {
        let mut index = 0;
        while index < self.len {
            if self.ports[index].is_some_and(|port| port.id == id) {
                return Some(index);
            }
            index += 1;
        }
        None
    }
}

impl<'a, const N: usize> Default for PortTable<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}
