//! Shared-memory handle and grant contracts for IPC payload transfer.

use crate::port::PortId;
use crate::{DataClass, IpcError, IpcResult, IpcRights, RedactionState, TraceContext};

/// Maximum shared memory region length.
pub const MAX_SHARED_MEMORY_LEN: u64 = 16 * 1024 * 1024;

/// Stable shared memory handle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedMemoryHandle(pub u64);

impl SharedMemoryHandle {
    /// Invalid handle.
    pub const INVALID: Self = Self(0);

    /// Creates a handle.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns raw handle.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Validates the handle.
    pub const fn validate(self) -> IpcResult<()> {
        if self.0 == 0 {
            return Err(IpcError::InvalidSharedMemory);
        }
        Ok(())
    }
}

/// Shared memory access mode.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryAccess {
    /// Read-only mapping.
    Read = 0,
    /// Write-only mapping.
    Write = 1,
    /// Read-write mapping.
    ReadWrite = 2,
}

impl MemoryAccess {
    /// Stable access label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
        }
    }

    /// Returns `true` when reading is allowed.
    pub const fn allows_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    /// Returns `true` when writing is allowed.
    pub const fn allows_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

/// Shared memory lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedMemoryState {
    /// Region was created.
    Created = 0,
    /// Region is mapped.
    Mapped = 1,
    /// Region is pinned.
    Pinned = 2,
    /// Region is sealed against mutation.
    Sealed = 3,
    /// Region was transferred.
    Transferred = 4,
    /// Region was revoked.
    Revoked = 5,
}

impl SharedMemoryState {
    /// Stable state label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Mapped => "mapped",
            Self::Pinned => "pinned",
            Self::Sealed => "sealed",
            Self::Transferred => "transferred",
            Self::Revoked => "revoked",
        }
    }

    /// Returns `true` when the region can be attached to an IPC message.
    pub const fn allows_transfer(self) -> bool {
        matches!(self, Self::Sealed | Self::Transferred)
    }
}

/// Mapping intent used by kernel/runtime mediation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMapIntent {
    /// Use as message payload.
    Payload = 0,
    /// Use as response output.
    Response = 1,
    /// Use as cognitive tensor or embedding payload.
    CognitiveBuffer = 2,
    /// Use as audit evidence payload.
    AuditEvidence = 3,
}

impl MemoryMapIntent {
    /// Stable intent label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Payload => "payload",
            Self::Response => "response",
            Self::CognitiveBuffer => "cognitive_buffer",
            Self::AuditEvidence => "audit_evidence",
        }
    }
}

/// Shared memory region descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedMemoryRegion {
    /// Region handle.
    pub handle: SharedMemoryHandle,
    /// Owner port.
    pub owner: PortId,
    /// Region byte length.
    pub len: u64,
    /// Access mode.
    pub access: MemoryAccess,
    /// Lifecycle state.
    pub state: SharedMemoryState,
    /// Data class.
    pub data_class: DataClass,
    /// Redaction state.
    pub redaction: RedactionState,
    /// Rights held by the owner.
    pub rights: IpcRights,
    /// Handle generation.
    pub generation: u32,
}

impl SharedMemoryRegion {
    /// Creates a shared memory region descriptor.
    pub const fn new(
        handle: SharedMemoryHandle,
        owner: PortId,
        len: u64,
        access: MemoryAccess,
    ) -> Self {
        Self {
            handle,
            owner,
            len,
            access,
            state: SharedMemoryState::Created,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            rights: IpcRights(crate::IPC_RIGHT_SHARE_MEMORY | crate::IPC_RIGHT_SEAL),
            generation: 1,
        }
    }

    /// Sets lifecycle state.
    pub const fn with_state(mut self, state: SharedMemoryState) -> Self {
        self.state = state;
        self
    }

    /// Sets data class and redaction state.
    pub const fn with_class(mut self, data_class: DataClass, redaction: RedactionState) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Sets rights.
    pub const fn with_rights(mut self, rights: IpcRights) -> Self {
        self.rights = rights;
        self
    }

    /// Marks the region pinned.
    pub const fn pin(mut self) -> IpcResult<Self> {
        match self.validate_basic() {
            Ok(()) => {
                self.state = SharedMemoryState::Pinned;
                Ok(self)
            }
            Err(error) => Err(error),
        }
    }

    /// Seals the region for transfer.
    pub const fn seal(mut self) -> IpcResult<Self> {
        match self.validate_basic() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match self.rights.require(IpcRights::SEAL) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if matches!(self.state, SharedMemoryState::Revoked) {
            return Err(IpcError::Revoked);
        }
        self.state = SharedMemoryState::Sealed;
        Ok(self)
    }

    /// Revokes the region.
    pub const fn revoke(mut self) -> Self {
        self.state = SharedMemoryState::Revoked;
        self
    }

    /// Validates identity, size, rights, and sensitivity.
    pub const fn validate_basic(self) -> IpcResult<()> {
        match self.handle.validate() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match self.owner.validate() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if self.len == 0 {
            return Err(IpcError::InvalidSharedMemory);
        }
        if self.len > MAX_SHARED_MEMORY_LEN {
            return Err(IpcError::PayloadTooLarge);
        }
        if self.generation == 0 {
            return Err(IpcError::InvalidSharedMemory);
        }
        match self.rights.require(IpcRights::SHARE_MEMORY) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if !self.redaction.satisfies(self.data_class) {
            return Err(IpcError::SensitiveData);
        }
        Ok(())
    }

    /// Validates transfer readiness.
    pub const fn validate_for_transfer(self) -> IpcResult<()> {
        match self.validate_basic() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if matches!(self.state, SharedMemoryState::Revoked) {
            return Err(IpcError::Revoked);
        }
        if !self.state.allows_transfer() {
            return Err(IpcError::NotSealed);
        }
        Ok(())
    }
}

/// Shared memory grant from owner to recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryGrant {
    /// Region handle.
    pub handle: SharedMemoryHandle,
    /// Source port.
    pub source: PortId,
    /// Target port.
    pub target: PortId,
    /// Access granted to target.
    pub access: MemoryAccess,
    /// Mapping intent.
    pub intent: MemoryMapIntent,
    /// Trace context.
    pub trace: TraceContext,
}

impl MemoryGrant {
    /// Creates a memory grant.
    pub const fn new(
        region: SharedMemoryRegion,
        target: PortId,
        access: MemoryAccess,
        intent: MemoryMapIntent,
    ) -> Self {
        Self {
            handle: region.handle,
            source: region.owner,
            target,
            access,
            intent,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates grant metadata against a source region.
    pub const fn validate(self, region: SharedMemoryRegion) -> IpcResult<()> {
        match region.validate_for_transfer() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if self.handle.raw() != region.handle.raw() || self.source.raw() != region.owner.raw() {
            return Err(IpcError::InvalidSharedMemory);
        }
        match self.target.validate() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if self.access.allows_write() && !region.access.allows_write() {
            return Err(IpcError::AccessDenied);
        }
        self.trace.validate()
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedMemoryDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> SharedMemoryDescriptor<'a> {
    /// Creates a shared memory module descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
