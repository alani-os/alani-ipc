//! IPC route rules and fixed-capacity router tables.

use crate::channel::{ChannelDescriptor, ChannelId, MessageEnvelope, MessageKind};
use crate::port::{PortDescriptor, PortId};
use crate::{IpcError, IpcResult, IpcRights};

/// Maximum route label length.
pub const MAX_ROUTE_LABEL_LEN: usize = 96;

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> RouteDescriptor<'a> {
    /// Creates a route descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

/// Route lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteState {
    /// Route exists but is not active.
    Created = 0,
    /// Route can be used.
    Active = 1,
    /// Route is administratively disabled.
    Disabled = 2,
    /// Route was revoked.
    Revoked = 3,
}

impl RouteState {
    /// Stable route state label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
        }
    }

    /// Returns `true` when routing can proceed.
    pub const fn allows_route(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// One route rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteRule<'a> {
    /// Route identifier.
    pub id: u64,
    /// Route label.
    pub label: &'a str,
    /// Source port.
    pub source: PortId,
    /// Target port.
    pub target: PortId,
    /// Channel used by the route.
    pub channel: ChannelId,
    /// Optional message kind filter.
    pub kind: Option<MessageKind>,
    /// Required rights.
    pub required_rights: IpcRights,
    /// Route state.
    pub state: RouteState,
    /// Whether route decisions should be auditable.
    pub audit_required: bool,
}

impl<'a> RouteRule<'a> {
    /// Creates a route rule.
    pub const fn new(
        id: u64,
        label: &'a str,
        source: PortId,
        target: PortId,
        channel: ChannelId,
    ) -> Self {
        Self {
            id,
            label,
            source,
            target,
            channel,
            kind: None,
            required_rights: IpcRights(crate::IPC_RIGHT_SEND | crate::IPC_RIGHT_ROUTE),
            state: RouteState::Active,
            audit_required: true,
        }
    }

    /// Restricts the route to a message kind.
    pub const fn with_kind(mut self, kind: MessageKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Sets required rights.
    pub const fn with_required_rights(mut self, required_rights: IpcRights) -> Self {
        self.required_rights = required_rights;
        self
    }

    /// Sets route state.
    pub const fn with_state(mut self, state: RouteState) -> Self {
        self.state = state;
        self
    }

    /// Validates route metadata.
    pub fn validate(self) -> IpcResult<()> {
        if self.id == 0 || self.label.is_empty() {
            return Err(IpcError::MissingField);
        }
        if self.label.len() > MAX_ROUTE_LABEL_LEN {
            return Err(IpcError::FieldTooLong);
        }
        self.source.validate()?;
        self.target.validate()?;
        self.channel.validate()?;
        IpcRights::from_bits(self.required_rights.bits())?;
        if matches!(self.state, RouteState::Revoked) {
            return Err(IpcError::InvalidRoute);
        }
        Ok(())
    }

    /// Returns `true` when this rule matches an envelope.
    pub const fn matches(self, envelope: MessageEnvelope<'_>) -> bool {
        if self.source.raw() != envelope.header.source.raw()
            || self.target.raw() != envelope.header.target.raw()
        {
            return false;
        }
        match self.kind {
            Some(kind) => kind as u8 == envelope.header.kind as u8,
            None => true,
        }
    }
}

/// Route decision result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteDecision<'a> {
    /// Matched rule.
    pub rule: RouteRule<'a>,
    /// Channel descriptor.
    pub channel: ChannelDescriptor<'a>,
    /// Whether audit evidence should be emitted.
    pub audit_required: bool,
}

impl<'a> RouteDecision<'a> {
    /// Validates the route decision.
    pub fn validate(self) -> IpcResult<()> {
        self.rule.validate()?;
        self.channel.validate()?;
        if self.rule.channel != self.channel.id {
            return Err(IpcError::InvalidRoute);
        }
        Ok(())
    }
}

/// Fixed-capacity route table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcRouter<'a, const N: usize> {
    routes: [Option<RouteRule<'a>>; N],
    len: usize,
}

impl<'a, const N: usize> IpcRouter<'a, N> {
    /// Creates an empty router.
    pub const fn new() -> Self {
        Self {
            routes: [None; N],
            len: 0,
        }
    }

    /// Returns route count.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns `true` when no routes are registered.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Adds a route.
    pub fn add_route(&mut self, route: RouteRule<'a>) -> IpcResult<()> {
        if self.len >= N {
            return Err(IpcError::CapacityExceeded);
        }
        route.validate()?;
        if self.contains_id(route.id) {
            return Err(IpcError::DuplicateRoute);
        }
        self.routes[self.len] = Some(route);
        self.len += 1;
        Ok(())
    }

    /// Returns `true` when a route id exists.
    pub fn contains_id(self, id: u64) -> bool {
        let mut index = 0;
        while index < self.len {
            if self.routes[index].is_some_and(|route| route.id == id) {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Resolves an envelope against registered routes and channel descriptors.
    pub fn resolve<const CHANNELS: usize>(
        self,
        envelope: MessageEnvelope<'_>,
        source: PortDescriptor<'_>,
        target: PortDescriptor<'_>,
        channels: &[ChannelDescriptor<'a>; CHANNELS],
        rights: IpcRights,
    ) -> IpcResult<RouteDecision<'a>> {
        envelope.validate()?;
        source.validate()?;
        target.validate()?;
        if source.id != envelope.header.source || target.id != envelope.header.target {
            return Err(IpcError::InvalidRoute);
        }
        if !source.state.allows_message() || !target.state.allows_message() {
            return Err(IpcError::Closed);
        }

        let mut index = 0;
        while index < self.len {
            let Some(route) = self.routes[index] else {
                return Err(IpcError::Internal);
            };
            if route.matches(envelope) {
                route.validate()?;
                if !route.state.allows_route() {
                    return Err(IpcError::InvalidRoute);
                }
                rights.require(route.required_rights)?;
                let Some(channel) = find_channel(channels, route.channel) else {
                    return Err(IpcError::InvalidRoute);
                };
                envelope.validate_for_channel(channel, rights)?;
                return Ok(RouteDecision {
                    rule: route,
                    channel,
                    audit_required: route.audit_required || channel.audit_required,
                });
            }
            index += 1;
        }
        Err(IpcError::RouteNotFound)
    }
}

impl<'a, const N: usize> Default for IpcRouter<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

fn find_channel<'a, const N: usize>(
    channels: &[ChannelDescriptor<'a>; N],
    id: ChannelId,
) -> Option<ChannelDescriptor<'a>> {
    channels.iter().copied().find(|channel| channel.id == id)
}
