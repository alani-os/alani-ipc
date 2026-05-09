#![cfg_attr(not(feature = "std"), no_std)]

//! Dependency-free IPC contracts for the Alani MVK.
//!
//! This crate owns the public skeleton for capability-aware ports, channels,
//! message envelopes, shared-memory handles, event queues, and routing
//! contracts. Sibling repositories remain represented as Cargo metadata until
//! their public APIs stabilize.

pub mod channel;
pub mod port;
pub mod queue;
pub mod router;
pub mod shared_memory;

pub use channel::{
    ChannelDescriptor, ChannelId, ChannelState, DeliveryMode, MessageEnvelope, MessageHeader,
    MessageKind, PayloadDescriptor, MAX_CHANNEL_NAME_LEN, MAX_MESSAGE_BYTES, MESSAGE_FLAG_AUDIT,
    MESSAGE_FLAG_REQUIRES_REPLY, MESSAGE_FLAG_SHARED_MEMORY, MESSAGE_KNOWN_FLAGS,
};
pub use port::{
    PortDescriptor, PortId, PortKind, PortOpenRequest, PortState, PortTable, MAX_PORT_NAME_LEN,
};
pub use queue::{
    EventKind, EventQueue, IpcEvent, QueueDescriptor, QueuePolicy, QueueStatus, WaitReason,
};
pub use router::{
    IpcRouter, RouteDecision, RouteDescriptor, RouteRule, RouteState, MAX_ROUTE_LABEL_LEN,
};
pub use shared_memory::{
    MemoryAccess, MemoryGrant, MemoryMapIntent, SharedMemoryDescriptor, SharedMemoryHandle,
    SharedMemoryRegion, SharedMemoryState, MAX_SHARED_MEMORY_LEN,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-ipc";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this crate.
pub const MODULES: &[&str] = &["channel", "port", "shared_memory", "router", "queue"];

/// Feature bit for port descriptors and tables.
pub const IPC_FEATURE_PORTS: u64 = 1 << 0;
/// Feature bit for channel descriptors and message envelopes.
pub const IPC_FEATURE_CHANNELS: u64 = 1 << 1;
/// Feature bit for bounded event queues.
pub const IPC_FEATURE_QUEUES: u64 = 1 << 2;
/// Feature bit for shared-memory handles.
pub const IPC_FEATURE_SHARED_MEMORY: u64 = 1 << 3;
/// Feature bit for route tables.
pub const IPC_FEATURE_ROUTER: u64 = 1 << 4;
/// Feature bit for audit and trace metadata.
pub const IPC_FEATURE_TRACE_AUDIT: u64 = 1 << 5;

/// All IPC feature bits known by this crate version.
pub const IPC_KNOWN_FEATURES: u64 = IPC_FEATURE_PORTS
    | IPC_FEATURE_CHANNELS
    | IPC_FEATURE_QUEUES
    | IPC_FEATURE_SHARED_MEMORY
    | IPC_FEATURE_ROUTER
    | IPC_FEATURE_TRACE_AUDIT;

/// Right to connect to a port.
pub const IPC_RIGHT_CONNECT: u64 = 1 << 0;
/// Right to send messages.
pub const IPC_RIGHT_SEND: u64 = 1 << 1;
/// Right to receive messages.
pub const IPC_RIGHT_RECEIVE: u64 = 1 << 2;
/// Right to share memory handles.
pub const IPC_RIGHT_SHARE_MEMORY: u64 = 1 << 3;
/// Right to route or forward messages.
pub const IPC_RIGHT_ROUTE: u64 = 1 << 4;
/// Right to administer ports, channels, or routes.
pub const IPC_RIGHT_ADMIN: u64 = 1 << 5;
/// Right to observe queue and channel state.
pub const IPC_RIGHT_OBSERVE: u64 = 1 << 6;
/// Right to seal or revoke shared memory.
pub const IPC_RIGHT_SEAL: u64 = 1 << 7;
/// Right to signal wait queues.
pub const IPC_RIGHT_SIGNAL: u64 = 1 << 8;

/// All IPC rights known by this crate version.
pub const IPC_KNOWN_RIGHTS: u64 = IPC_RIGHT_CONNECT
    | IPC_RIGHT_SEND
    | IPC_RIGHT_RECEIVE
    | IPC_RIGHT_SHARE_MEMORY
    | IPC_RIGHT_ROUTE
    | IPC_RIGHT_ADMIN
    | IPC_RIGHT_OBSERVE
    | IPC_RIGHT_SEAL
    | IPC_RIGHT_SIGNAL;

/// Trace flag indicating the event was sampled.
pub const TRACE_FLAG_SAMPLED: u32 = 1 << 0;
/// Trace flag indicating verbose diagnostics are allowed.
pub const TRACE_FLAG_DEBUG: u32 = 1 << 1;
/// Trace flags known by this crate version.
pub const TRACE_KNOWN_FLAGS: u32 = TRACE_FLAG_SAMPLED | TRACE_FLAG_DEBUG;

/// Result alias used by IPC validation and host-mode APIs.
pub type IpcResult<T> = Result<T, IpcError>;

/// Error taxonomy for IPC ports, channels, queues, routes, and memory grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    /// Required field was omitted.
    MissingField,
    /// String metadata exceeded a documented maximum.
    FieldTooLong,
    /// Reserved flag or right bits were present.
    ReservedBits,
    /// Port metadata or state was invalid.
    InvalidPort,
    /// Port identifier already exists.
    DuplicatePort,
    /// Port could not be found.
    PortNotFound,
    /// Channel metadata or state was invalid.
    InvalidChannel,
    /// Channel identifier already exists.
    DuplicateChannel,
    /// Message metadata or envelope was invalid.
    InvalidMessage,
    /// Payload length exceeded the supported bound.
    PayloadTooLarge,
    /// Shared-memory metadata was invalid.
    InvalidSharedMemory,
    /// Shared memory must be sealed before transfer.
    NotSealed,
    /// Shared memory was revoked.
    Revoked,
    /// Route metadata was invalid.
    InvalidRoute,
    /// Route identifier already exists.
    DuplicateRoute,
    /// No matching route exists.
    RouteNotFound,
    /// Required IPC capability was missing.
    AccessDenied,
    /// Fixed-capacity queue, table, or route list is full.
    CapacityExceeded,
    /// Operation would block under the selected queue policy.
    WouldBlock,
    /// Endpoint or channel is closed.
    Closed,
    /// Deadline expired before delivery.
    DeadlineExceeded,
    /// Trace context was malformed.
    InvalidTrace,
    /// Sensitive payload metadata lacked an acceptable redaction state.
    SensitiveData,
    /// Internal invariant failed.
    Internal,
}

impl IpcError {
    /// Stable reason label for diagnostics and tests.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MissingField => "missing_field",
            Self::FieldTooLong => "field_too_long",
            Self::ReservedBits => "reserved_bits",
            Self::InvalidPort => "invalid_port",
            Self::DuplicatePort => "duplicate_port",
            Self::PortNotFound => "port_not_found",
            Self::InvalidChannel => "invalid_channel",
            Self::DuplicateChannel => "duplicate_channel",
            Self::InvalidMessage => "invalid_message",
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidSharedMemory => "invalid_shared_memory",
            Self::NotSealed => "not_sealed",
            Self::Revoked => "revoked",
            Self::InvalidRoute => "invalid_route",
            Self::DuplicateRoute => "duplicate_route",
            Self::RouteNotFound => "route_not_found",
            Self::AccessDenied => "access_denied",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::WouldBlock => "would_block",
            Self::Closed => "closed",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::InvalidTrace => "invalid_trace",
            Self::SensitiveData => "sensitive_data",
            Self::Internal => "internal",
        }
    }

    /// Returns `true` when this error represents a fail-closed trust boundary.
    pub const fn is_security_relevant(self) -> bool {
        matches!(
            self,
            Self::ReservedBits
                | Self::AccessDenied
                | Self::PayloadTooLarge
                | Self::InvalidSharedMemory
                | Self::NotSealed
                | Self::Revoked
                | Self::InvalidRoute
                | Self::InvalidTrace
                | Self::SensitiveData
        )
    }
}

/// IPC rights bitset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcRights(pub u64);

impl IpcRights {
    /// Empty rights set.
    pub const EMPTY: Self = Self(0);
    /// Connect right.
    pub const CONNECT: Self = Self(IPC_RIGHT_CONNECT);
    /// Send right.
    pub const SEND: Self = Self(IPC_RIGHT_SEND);
    /// Receive right.
    pub const RECEIVE: Self = Self(IPC_RIGHT_RECEIVE);
    /// Share-memory right.
    pub const SHARE_MEMORY: Self = Self(IPC_RIGHT_SHARE_MEMORY);
    /// Route right.
    pub const ROUTE: Self = Self(IPC_RIGHT_ROUTE);
    /// Administration right.
    pub const ADMIN: Self = Self(IPC_RIGHT_ADMIN);
    /// Observe right.
    pub const OBSERVE: Self = Self(IPC_RIGHT_OBSERVE);
    /// Seal right.
    pub const SEAL: Self = Self(IPC_RIGHT_SEAL);
    /// Signal right.
    pub const SIGNAL: Self = Self(IPC_RIGHT_SIGNAL);

    /// Creates rights from raw bits.
    pub const fn from_bits(bits: u64) -> IpcResult<Self> {
        if bits & !IPC_KNOWN_RIGHTS != 0 {
            return Err(IpcError::ReservedBits);
        }
        Ok(Self(bits))
    }

    /// Returns raw bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` when all required rights are present.
    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Combines two rights sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Requires the given rights.
    pub const fn require(self, required: Self) -> IpcResult<()> {
        if self.0 & !IPC_KNOWN_RIGHTS != 0 {
            return Err(IpcError::ReservedBits);
        }
        if !self.contains(required) {
            return Err(IpcError::AccessDenied);
        }
        Ok(())
    }
}

/// Data sensitivity classification for IPC diagnostics and payload metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataClass {
    /// Public data.
    Public = 0,
    /// Operational metadata.
    Operational = 1,
    /// Sensitive data requiring redaction.
    Sensitive = 2,
    /// Secret data that must not be broadly exported.
    Secret = 3,
}

impl DataClass {
    /// Stable class label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::Sensitive => "sensitive",
            Self::Secret => "secret",
        }
    }

    /// Returns `true` when broad diagnostics require redaction.
    pub const fn requires_redaction(self) -> bool {
        matches!(self, Self::Sensitive | Self::Secret)
    }
}

/// Redaction state for IPC payload metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionState {
    /// No redaction needed.
    Public = 0,
    /// Operational metadata only.
    Operational = 1,
    /// Sensitive data was redacted.
    SensitiveRedacted = 2,
    /// Secret data was redacted.
    SecretRedacted = 3,
    /// Sensitive or secret data remains present.
    Unredacted = 4,
}

impl RedactionState {
    /// Stable redaction label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::SensitiveRedacted => "sensitive_redacted",
            Self::SecretRedacted => "secret_redacted",
            Self::Unredacted => "unredacted",
        }
    }

    /// Returns `true` when this state is acceptable for the data class.
    pub const fn satisfies(self, data_class: DataClass) -> bool {
        match data_class {
            DataClass::Public | DataClass::Operational => true,
            DataClass::Sensitive => {
                matches!(self, Self::SensitiveRedacted | Self::SecretRedacted)
            }
            DataClass::Secret => matches!(self, Self::SecretRedacted),
        }
    }
}

/// Trace context propagated through IPC operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceContext {
    /// Stable trace identifier.
    pub trace_id: u64,
    /// Current span identifier.
    pub span_id: u64,
    /// Parent span identifier.
    pub parent_span_id: u64,
    /// Trace flags.
    pub flags: u32,
}

impl TraceContext {
    /// Empty trace context.
    pub const EMPTY: Self = Self {
        trace_id: 0,
        span_id: 0,
        parent_span_id: 0,
        flags: 0,
    };

    /// Creates a root trace context.
    pub const fn root(trace_id: u64, span_id: u64) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: 0,
            flags: TRACE_FLAG_SAMPLED,
        }
    }

    /// Creates a child span context.
    pub const fn child(self, span_id: u64) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id,
            parent_span_id: self.span_id,
            flags: self.flags,
        }
    }

    /// Returns `true` when identifiers are present.
    pub const fn is_present(self) -> bool {
        self.trace_id != 0 || self.span_id != 0 || self.parent_span_id != 0
    }

    /// Validates trace metadata.
    pub const fn validate(self) -> IpcResult<()> {
        if self.flags & !TRACE_KNOWN_FLAGS != 0 {
            return Err(IpcError::ReservedBits);
        }
        if !self.is_present() {
            return Ok(());
        }
        if self.trace_id == 0 || self.span_id == 0 {
            return Err(IpcError::InvalidTrace);
        }
        Ok(())
    }
}

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Compact root view of the IPC crate contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcCatalog {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Feature bitmap.
    pub features: u64,
    /// Known IPC rights.
    pub known_rights: u64,
    /// Maximum inline message bytes.
    pub max_message_bytes: u64,
    /// Maximum shared memory region length.
    pub max_shared_memory_len: u64,
}

impl IpcCatalog {
    /// Current IPC catalog.
    pub const CURRENT: Self = Self {
        repository: REPOSITORY,
        version: VERSION,
        features: IPC_KNOWN_FEATURES,
        known_rights: IPC_KNOWN_RIGHTS,
        max_message_bytes: MAX_MESSAGE_BYTES,
        max_shared_memory_len: MAX_SHARED_MEMORY_LEN,
    };

    /// Returns the current catalog.
    pub const fn current() -> Self {
        Self::CURRENT
    }

    /// Validates catalog metadata.
    pub const fn validate(self) -> IpcResult<()> {
        if self.repository.is_empty() || self.version.is_empty() {
            return Err(IpcError::MissingField);
        }
        if self.features & !IPC_KNOWN_FEATURES != 0 || self.known_rights & !IPC_KNOWN_RIGHTS != 0 {
            return Err(IpcError::ReservedBits);
        }
        if self.max_message_bytes == 0 || self.max_shared_memory_len == 0 {
            return Err(IpcError::InvalidMessage);
        }
        Ok(())
    }
}

/// Current IPC catalog.
pub const IPC_CATALOG: IpcCatalog = IpcCatalog::CURRENT;

/// Returns the current IPC catalog.
pub const fn ipc_catalog() -> IpcCatalog {
    IpcCatalog::CURRENT
}
