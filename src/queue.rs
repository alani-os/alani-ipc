//! Fixed-capacity IPC event queues and wait reasons.

use crate::channel::ChannelId;
use crate::port::PortId;
use crate::{DataClass, IpcError, IpcResult, TraceContext};

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> QueueDescriptor<'a> {
    /// Creates a queue descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

/// IPC event kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// Message was enqueued or delivered.
    Message = 0,
    /// Port became ready.
    PortReady = 1,
    /// Channel closed or drained.
    ChannelClosed = 2,
    /// Shared memory was revoked.
    SharedMemoryRevoked = 3,
    /// Route was denied by rights or policy.
    RouteDenied = 4,
    /// Queue back-pressure was observed.
    BackPressure = 5,
}

impl EventKind {
    /// Stable event label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::PortReady => "port_ready",
            Self::ChannelClosed => "channel_closed",
            Self::SharedMemoryRevoked => "shared_memory_revoked",
            Self::RouteDenied => "route_denied",
            Self::BackPressure => "back_pressure",
        }
    }
}

/// Wait reason for tasks blocked on IPC.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitReason {
    /// Waiting to send.
    Send = 0,
    /// Waiting to receive.
    Receive = 1,
    /// Waiting for route availability.
    Route = 2,
    /// Waiting for shared-memory seal or revoke.
    SharedMemory = 3,
    /// Waiting for a deadline.
    Deadline = 4,
}

impl WaitReason {
    /// Stable wait label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Receive => "receive",
            Self::Route => "route",
            Self::SharedMemory => "shared_memory",
            Self::Deadline => "deadline",
        }
    }
}

/// Queue overflow behavior.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuePolicy {
    /// Reject new entries when full.
    FailClosed = 0,
    /// Drop newest entry when full.
    DropNewest = 1,
    /// Drop oldest entry to make room.
    DropOldest = 2,
}

impl QueuePolicy {
    /// Stable policy label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::DropNewest => "drop_newest",
            Self::DropOldest => "drop_oldest",
        }
    }
}

/// Queue status summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueStatus {
    /// Current queue length.
    pub len: usize,
    /// Queue capacity.
    pub capacity: usize,
    /// Number of overflow events.
    pub overflow_count: u64,
    /// Whether the queue is full.
    pub full: bool,
}

/// IPC event record for deferred routing and observability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcEvent {
    /// Monotonic event sequence.
    pub sequence: u64,
    /// Event kind.
    pub kind: EventKind,
    /// Port associated with the event.
    pub port: PortId,
    /// Channel associated with the event.
    pub channel: ChannelId,
    /// Message identifier associated with the event.
    pub message_id: u64,
    /// Wait reason, when this event wakes a task.
    pub wait_reason: Option<WaitReason>,
    /// Data class for diagnostic export.
    pub data_class: DataClass,
    /// Trace context.
    pub trace: TraceContext,
}

impl IpcEvent {
    /// Creates a message event.
    pub const fn message(sequence: u64, port: PortId, channel: ChannelId, message_id: u64) -> Self {
        Self {
            sequence,
            kind: EventKind::Message,
            port,
            channel,
            message_id,
            wait_reason: Some(WaitReason::Receive),
            data_class: DataClass::Operational,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets event kind.
    pub const fn with_kind(mut self, kind: EventKind) -> Self {
        self.kind = kind;
        self
    }

    /// Sets wait reason.
    pub const fn with_wait_reason(mut self, wait_reason: Option<WaitReason>) -> Self {
        self.wait_reason = wait_reason;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates event metadata.
    pub const fn validate(self) -> IpcResult<()> {
        if self.sequence == 0 {
            return Err(IpcError::InvalidMessage);
        }
        match self.port.validate() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match self.channel.validate() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if matches!(self.kind, EventKind::Message) && self.message_id == 0 {
            return Err(IpcError::InvalidMessage);
        }
        self.trace.validate()
    }
}

/// Fixed-capacity event queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventQueue<const N: usize> {
    events: [Option<IpcEvent>; N],
    head: usize,
    len: usize,
    overflow_count: u64,
    policy: QueuePolicy,
}

impl<const N: usize> EventQueue<N> {
    /// Creates an empty queue with fail-closed overflow policy.
    pub const fn new() -> Self {
        Self::with_policy(QueuePolicy::FailClosed)
    }

    /// Creates an empty queue with the selected policy.
    pub const fn with_policy(policy: QueuePolicy) -> Self {
        Self {
            events: [None; N],
            head: 0,
            len: 0,
            overflow_count: 0,
            policy,
        }
    }

    /// Returns queue length.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns `true` when queue is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns queue status.
    pub const fn status(self) -> QueueStatus {
        QueueStatus {
            len: self.len,
            capacity: N,
            overflow_count: self.overflow_count,
            full: self.len == N,
        }
    }

    /// Pushes an event.
    pub fn push(&mut self, event: IpcEvent) -> IpcResult<()> {
        event.validate()?;
        if N == 0 {
            self.overflow_count += 1;
            return Err(IpcError::CapacityExceeded);
        }
        if self.len >= N {
            self.overflow_count += 1;
            return match self.policy {
                QueuePolicy::FailClosed => Err(IpcError::CapacityExceeded),
                QueuePolicy::DropNewest => Ok(()),
                QueuePolicy::DropOldest => {
                    let _ = self.pop();
                    let index = (self.head + self.len) % N;
                    self.events[index] = Some(event);
                    self.len += 1;
                    Ok(())
                }
            };
        }
        let index = (self.head + self.len) % N;
        self.events[index] = Some(event);
        self.len += 1;
        Ok(())
    }

    /// Pops the oldest event.
    pub fn pop(&mut self) -> Option<IpcEvent> {
        if self.len == 0 {
            return None;
        }
        let event = self.events[self.head];
        self.events[self.head] = None;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        event
    }
}

impl<const N: usize> Default for EventQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}
