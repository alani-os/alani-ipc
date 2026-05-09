//! IPC channel descriptors and message envelopes.

use crate::port::PortId;
use crate::shared_memory::SharedMemoryHandle;
use crate::{DataClass, IpcError, IpcResult, IpcRights, RedactionState, TraceContext};

/// Maximum channel name length.
pub const MAX_CHANNEL_NAME_LEN: usize = 96;
/// Maximum inline message bytes.
pub const MAX_MESSAGE_BYTES: u64 = 64 * 1024;
/// Maximum payload descriptors per message envelope.
pub const MAX_PAYLOAD_DESCRIPTORS: usize = 4;

/// Message requires a response.
pub const MESSAGE_FLAG_REQUIRES_REPLY: u32 = 1 << 0;
/// Message references shared memory.
pub const MESSAGE_FLAG_SHARED_MEMORY: u32 = 1 << 1;
/// Message should emit audit evidence.
pub const MESSAGE_FLAG_AUDIT: u32 = 1 << 2;
/// Message carries high-priority wakeup semantics.
pub const MESSAGE_FLAG_SIGNAL: u32 = 1 << 3;
/// Message flags known by this crate version.
pub const MESSAGE_KNOWN_FLAGS: u32 = MESSAGE_FLAG_REQUIRES_REPLY
    | MESSAGE_FLAG_SHARED_MEMORY
    | MESSAGE_FLAG_AUDIT
    | MESSAGE_FLAG_SIGNAL;

/// Stable IPC channel identifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChannelId(pub u64);

impl ChannelId {
    /// Invalid channel identifier.
    pub const INVALID: Self = Self(0);

    /// Creates a channel identifier.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns raw identifier.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Validates the identifier.
    pub const fn validate(self) -> IpcResult<()> {
        if self.0 == 0 {
            return Err(IpcError::InvalidChannel);
        }
        Ok(())
    }
}

/// Message kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// Request expecting a response.
    Request = 0,
    /// Response to a request.
    Response = 1,
    /// Event notification.
    Event = 2,
    /// Signal or wakeup notification.
    Signal = 3,
    /// Control-plane message.
    Control = 4,
}

impl MessageKind {
    /// Stable kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Event => "event",
            Self::Signal => "signal",
            Self::Control => "control",
        }
    }

    /// Required rights to send this message kind.
    pub const fn required_rights(self) -> IpcRights {
        match self {
            Self::Signal => IpcRights(crate::IPC_RIGHT_SEND | crate::IPC_RIGHT_SIGNAL),
            Self::Control => IpcRights(crate::IPC_RIGHT_SEND | crate::IPC_RIGHT_ADMIN),
            _ => IpcRights::SEND,
        }
    }
}

/// Channel delivery mode.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryMode {
    /// Best-effort delivery.
    BestEffort = 0,
    /// Reliable ordered delivery.
    Reliable = 1,
    /// Rendezvous delivery with receiver acknowledgement.
    Rendezvous = 2,
}

impl DeliveryMode {
    /// Stable mode label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::BestEffort => "best_effort",
            Self::Reliable => "reliable",
            Self::Rendezvous => "rendezvous",
        }
    }
}

/// Channel lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelState {
    /// Channel was created but is not yet bound.
    Created = 0,
    /// Channel endpoints are bound.
    Bound = 1,
    /// Channel is open for messages.
    Open = 2,
    /// Channel is draining queued messages.
    Draining = 3,
    /// Channel is closed.
    Closed = 4,
    /// Channel faulted.
    Faulted = 5,
}

impl ChannelState {
    /// Stable state label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Bound => "bound",
            Self::Open => "open",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Faulted => "faulted",
        }
    }

    /// Returns `true` when messages can be sent.
    pub const fn allows_send(self) -> bool {
        matches!(self, Self::Open)
    }
}

/// Channel descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelDescriptor<'a> {
    /// Channel identifier.
    pub id: ChannelId,
    /// Channel name.
    pub name: &'a str,
    /// Source port.
    pub source: PortId,
    /// Target port.
    pub target: PortId,
    /// Delivery mode.
    pub mode: DeliveryMode,
    /// Lifecycle state.
    pub state: ChannelState,
    /// Rights required to send on this channel.
    pub send_rights: IpcRights,
    /// Rights required to receive from this channel.
    pub receive_rights: IpcRights,
    /// Maximum inline message bytes accepted by the channel.
    pub max_message_len: u64,
    /// Queue capacity hint.
    pub queue_capacity: usize,
    /// Whether channel traffic is audit-critical.
    pub audit_required: bool,
}

impl<'a> ChannelDescriptor<'a> {
    /// Creates a channel descriptor.
    pub const fn new(id: ChannelId, name: &'a str, source: PortId, target: PortId) -> Self {
        Self {
            id,
            name,
            source,
            target,
            mode: DeliveryMode::Reliable,
            state: ChannelState::Bound,
            send_rights: IpcRights(crate::IPC_RIGHT_SEND),
            receive_rights: IpcRights(crate::IPC_RIGHT_RECEIVE),
            max_message_len: MAX_MESSAGE_BYTES,
            queue_capacity: 16,
            audit_required: true,
        }
    }

    /// Sets delivery mode.
    pub const fn with_mode(mut self, mode: DeliveryMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets lifecycle state.
    pub const fn with_state(mut self, state: ChannelState) -> Self {
        self.state = state;
        self
    }

    /// Sets required rights.
    pub const fn with_rights(mut self, send_rights: IpcRights, receive_rights: IpcRights) -> Self {
        self.send_rights = send_rights;
        self.receive_rights = receive_rights;
        self
    }

    /// Sets queue and message limits.
    pub const fn with_limits(mut self, max_message_len: u64, queue_capacity: usize) -> Self {
        self.max_message_len = max_message_len;
        self.queue_capacity = queue_capacity;
        self
    }

    /// Validates channel metadata.
    pub fn validate(self) -> IpcResult<()> {
        self.id.validate()?;
        self.source.validate()?;
        self.target.validate()?;
        if self.name.is_empty() {
            return Err(IpcError::MissingField);
        }
        if self.name.len() > MAX_CHANNEL_NAME_LEN {
            return Err(IpcError::FieldTooLong);
        }
        IpcRights::from_bits(self.send_rights.bits())?;
        IpcRights::from_bits(self.receive_rights.bits())?;
        if self.max_message_len == 0 || self.max_message_len > MAX_MESSAGE_BYTES {
            return Err(IpcError::InvalidChannel);
        }
        if self.queue_capacity == 0 {
            return Err(IpcError::InvalidChannel);
        }
        if matches!(self.state, ChannelState::Closed | ChannelState::Faulted) {
            return Err(IpcError::Closed);
        }
        Ok(())
    }
}

/// Payload descriptor inside a message envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadDescriptor {
    /// Inline payload offset.
    pub offset: u32,
    /// Payload length.
    pub len: u32,
    /// Optional shared-memory handle.
    pub shared_memory: SharedMemoryHandle,
}

impl PayloadDescriptor {
    /// Creates an inline payload descriptor.
    pub const fn inline(offset: u32, len: u32) -> Self {
        Self {
            offset,
            len,
            shared_memory: SharedMemoryHandle::INVALID,
        }
    }

    /// Creates a shared-memory payload descriptor.
    pub const fn shared(shared_memory: SharedMemoryHandle, len: u32) -> Self {
        Self {
            offset: 0,
            len,
            shared_memory,
        }
    }

    /// Returns `true` when the payload uses shared memory.
    pub const fn uses_shared_memory(self) -> bool {
        self.shared_memory.raw() != 0
    }

    /// Validates payload metadata.
    pub const fn validate(self) -> IpcResult<()> {
        if self.len == 0 {
            return Err(IpcError::InvalidMessage);
        }
        if self.len as u64 > MAX_MESSAGE_BYTES {
            return Err(IpcError::PayloadTooLarge);
        }
        if self.uses_shared_memory() {
            match self.shared_memory.validate() {
                Ok(()) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

/// Message header used by IPC queues and routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    /// Message identifier.
    pub message_id: u64,
    /// Correlation identifier for request/response flows.
    pub correlation_id: u64,
    /// Source port.
    pub source: PortId,
    /// Target port.
    pub target: PortId,
    /// Message kind.
    pub kind: MessageKind,
    /// Priority bucket.
    pub priority: u8,
    /// Message flags.
    pub flags: u32,
    /// Total payload length.
    pub payload_len: u64,
    /// Payload data class.
    pub data_class: DataClass,
    /// Payload redaction state.
    pub redaction: RedactionState,
    /// Trace context.
    pub trace: TraceContext,
}

impl MessageHeader {
    /// Creates a message header.
    pub const fn new(message_id: u64, source: PortId, target: PortId, kind: MessageKind) -> Self {
        Self {
            message_id,
            correlation_id: 0,
            source,
            target,
            kind,
            priority: 0,
            flags: 0,
            payload_len: 0,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets correlation id.
    pub const fn with_correlation(mut self, correlation_id: u64) -> Self {
        self.correlation_id = correlation_id;
        self
    }

    /// Sets priority.
    pub const fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Sets flags.
    pub const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Sets payload metadata.
    pub const fn with_payload(
        mut self,
        payload_len: u64,
        data_class: DataClass,
        redaction: RedactionState,
    ) -> Self {
        self.payload_len = payload_len;
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates header metadata.
    pub const fn validate(self) -> IpcResult<()> {
        if self.message_id == 0 {
            return Err(IpcError::InvalidMessage);
        }
        match self.source.validate() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match self.target.validate() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if self.flags & !MESSAGE_KNOWN_FLAGS != 0 {
            return Err(IpcError::ReservedBits);
        }
        if self.payload_len > MAX_MESSAGE_BYTES {
            return Err(IpcError::PayloadTooLarge);
        }
        if !self.redaction.satisfies(self.data_class) {
            return Err(IpcError::SensitiveData);
        }
        self.trace.validate()
    }
}

/// Fixed-size message envelope with up to four payload descriptors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageEnvelope<'a> {
    /// Header.
    pub header: MessageHeader,
    /// Routing topic or operation name.
    pub topic: &'a str,
    payloads: [Option<PayloadDescriptor>; MAX_PAYLOAD_DESCRIPTORS],
    len: usize,
}

impl<'a> MessageEnvelope<'a> {
    /// Creates an empty envelope.
    pub const fn new(header: MessageHeader, topic: &'a str) -> Self {
        Self {
            header,
            topic,
            payloads: [None; MAX_PAYLOAD_DESCRIPTORS],
            len: 0,
        }
    }

    /// Adds a payload descriptor.
    pub fn push_payload(&mut self, payload: PayloadDescriptor) -> IpcResult<()> {
        if self.len >= MAX_PAYLOAD_DESCRIPTORS {
            return Err(IpcError::CapacityExceeded);
        }
        payload.validate()?;
        self.payloads[self.len] = Some(payload);
        self.len += 1;
        self.header.payload_len += payload.len as u64;
        if payload.uses_shared_memory() {
            self.header.flags |= MESSAGE_FLAG_SHARED_MEMORY;
        }
        Ok(())
    }

    /// Returns payload count.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns `true` when no payload descriptors are present.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns a payload descriptor by index.
    pub const fn payload(self, index: usize) -> Option<PayloadDescriptor> {
        if index >= self.len {
            return None;
        }
        self.payloads[index]
    }

    /// Validates envelope metadata against a channel.
    pub fn validate_for_channel(
        self,
        channel: ChannelDescriptor<'_>,
        rights: IpcRights,
    ) -> IpcResult<()> {
        channel.validate()?;
        self.validate()?;
        if !channel.state.allows_send() {
            return Err(IpcError::Closed);
        }
        if self.header.source != channel.source || self.header.target != channel.target {
            return Err(IpcError::InvalidChannel);
        }
        rights.require(channel.send_rights)?;
        rights.require(self.header.kind.required_rights())?;
        if self.header.payload_len > channel.max_message_len {
            return Err(IpcError::PayloadTooLarge);
        }
        Ok(())
    }

    /// Validates the envelope independently.
    pub fn validate(self) -> IpcResult<()> {
        self.header.validate()?;
        if self.topic.is_empty() {
            return Err(IpcError::MissingField);
        }
        if self.topic.len() > MAX_CHANNEL_NAME_LEN {
            return Err(IpcError::FieldTooLong);
        }
        let mut total = 0_u64;
        let mut index = 0;
        while index < self.len {
            let Some(payload) = self.payloads[index] else {
                return Err(IpcError::InvalidMessage);
            };
            payload.validate()?;
            total += payload.len as u64;
            index += 1;
        }
        if total != self.header.payload_len {
            return Err(IpcError::InvalidMessage);
        }
        Ok(())
    }
}
