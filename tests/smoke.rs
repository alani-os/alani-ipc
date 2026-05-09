use alani_ipc::{
    ipc_catalog, ChannelDescriptor, ChannelId, ChannelState, ComponentStatus, DataClass,
    DeliveryMode, EventQueue, IpcError, IpcEvent, IpcRights, IpcRouter, MemoryAccess, MemoryGrant,
    MemoryMapIntent, MessageEnvelope, MessageHeader, MessageKind, PayloadDescriptor,
    PortDescriptor, PortId, PortKind, PortOpenRequest, PortState, PortTable, QueuePolicy,
    RedactionState, RouteRule, RouteState, SharedMemoryHandle, SharedMemoryRegion,
    SharedMemoryState, TraceContext, IPC_CATALOG, IPC_FEATURE_ROUTER, IPC_KNOWN_FEATURES,
    IPC_RIGHT_ADMIN, IPC_RIGHT_CONNECT, IPC_RIGHT_ROUTE, IPC_RIGHT_SEAL, IPC_RIGHT_SEND,
    IPC_RIGHT_SHARE_MEMORY, IPC_RIGHT_SIGNAL, MESSAGE_FLAG_REQUIRES_REPLY,
};

fn rights(bits: u64) -> IpcRights {
    IpcRights::from_bits(bits).unwrap()
}

fn source_port() -> PortDescriptor<'static> {
    PortDescriptor::new(PortId::new(1), "runtime.control", 10, PortKind::Runtime)
        .with_state(PortState::Connected)
        .with_required_rights(IpcRights::CONNECT)
}

fn target_port() -> PortDescriptor<'static> {
    PortDescriptor::new(PortId::new(2), "kernel.control", 1, PortKind::Kernel)
        .with_state(PortState::Connected)
        .with_required_rights(rights(IPC_RIGHT_CONNECT | IPC_RIGHT_SEND))
}

fn channel() -> ChannelDescriptor<'static> {
    ChannelDescriptor::new(
        ChannelId::new(7),
        "runtime-to-kernel",
        PortId::new(1),
        PortId::new(2),
    )
    .with_mode(DeliveryMode::Reliable)
    .with_state(ChannelState::Open)
    .with_rights(IpcRights::SEND, IpcRights::RECEIVE)
}

fn message() -> MessageEnvelope<'static> {
    let header = MessageHeader::new(100, PortId::new(1), PortId::new(2), MessageKind::Request)
        .with_correlation(99)
        .with_flags(MESSAGE_FLAG_REQUIRES_REPLY)
        .with_payload(0, DataClass::Operational, RedactionState::Operational)
        .with_trace(TraceContext::root(44, 1));
    let mut envelope = MessageEnvelope::new(header, "sys_task_spawn");
    envelope
        .push_payload(PayloadDescriptor::inline(0, 32))
        .unwrap();
    envelope
}

#[test]
fn repository_identity_and_catalog_are_stable() {
    let info = alani_ipc::component_info();

    assert_eq!(alani_ipc::repository_name(), "alani-ipc");
    assert_eq!(info.repository, "alani-ipc");
    assert_eq!(info.status, ComponentStatus::Experimental);
    assert_eq!(
        alani_ipc::module_names(),
        &["channel", "port", "shared_memory", "router", "queue"]
    );
    assert_eq!(ipc_catalog(), IPC_CATALOG);
    assert_eq!(ipc_catalog().validate(), Ok(()));
    assert_eq!(
        ipc_catalog().features & IPC_FEATURE_ROUTER,
        IPC_FEATURE_ROUTER
    );
    assert_eq!(IPC_KNOWN_FEATURES & !ipc_catalog().features, 0);
}

#[test]
fn rights_trace_and_redaction_fail_closed() {
    let send = rights(IPC_RIGHT_SEND | IPC_RIGHT_SIGNAL);

    assert_eq!(send.require(IpcRights::SEND), Ok(()));
    assert_eq!(
        send.require(IpcRights::RECEIVE),
        Err(IpcError::AccessDenied)
    );
    assert_eq!(IpcRights::from_bits(1 << 63), Err(IpcError::ReservedBits));
    assert_eq!(TraceContext::root(1, 2).child(3).validate(), Ok(()));
    assert_eq!(
        TraceContext {
            trace_id: 1,
            span_id: 0,
            parent_span_id: 0,
            flags: 0,
        }
        .validate(),
        Err(IpcError::InvalidTrace)
    );
    assert!(RedactionState::SecretRedacted.satisfies(DataClass::Secret));
    assert!(!RedactionState::Unredacted.satisfies(DataClass::Sensitive));
    assert!(IpcError::NotSealed.is_security_relevant());
}

#[test]
fn port_table_prevents_duplicates_and_authorizes_open() {
    let mut table = PortTable::<2>::new();
    let source = source_port();
    let target = target_port();

    assert_eq!(table.register(source), Ok(()));
    assert_eq!(table.register(source), Err(IpcError::DuplicatePort));
    assert_eq!(table.register(target), Ok(()));
    assert_eq!(table.len(), 2);

    let denied = PortOpenRequest::new(PortId::new(2), "task:runtime", IpcRights::CONNECT);
    assert_eq!(table.open(denied), Err(IpcError::AccessDenied));

    let opened = table
        .open(
            PortOpenRequest::new(
                PortId::new(2),
                "task:runtime",
                rights(IPC_RIGHT_CONNECT | IPC_RIGHT_SEND),
            )
            .with_trace(TraceContext::root(10, 20)),
        )
        .unwrap();
    assert_eq!(opened.kind, PortKind::Kernel);

    assert_eq!(table.set_state(PortId::new(2), PortState::Closed), Ok(()));
    assert_eq!(
        table.open(PortOpenRequest::new(
            PortId::new(2),
            "task:runtime",
            rights(IPC_RIGHT_CONNECT | IPC_RIGHT_SEND),
        )),
        Err(IpcError::Closed)
    );
}

#[test]
fn channel_envelopes_validate_payloads_and_capabilities() {
    let channel = channel();
    let envelope = message();
    let send_rights = rights(IPC_RIGHT_SEND | IPC_RIGHT_ROUTE);

    assert_eq!(envelope.validate(), Ok(()));
    assert_eq!(envelope.len(), 1);
    assert_eq!(envelope.header.payload_len, 32);
    assert_eq!(envelope.validate_for_channel(channel, send_rights), Ok(()));
    assert_eq!(
        envelope.validate_for_channel(channel.with_state(ChannelState::Closed), send_rights),
        Err(IpcError::Closed)
    );
    assert_eq!(
        envelope.validate_for_channel(channel, IpcRights::EMPTY),
        Err(IpcError::AccessDenied)
    );

    let sensitive = MessageHeader::new(101, PortId::new(1), PortId::new(2), MessageKind::Event)
        .with_payload(1, DataClass::Sensitive, RedactionState::Unredacted);
    assert_eq!(sensitive.validate(), Err(IpcError::SensitiveData));
}

#[test]
fn shared_memory_requires_sealing_before_grant() {
    let base = SharedMemoryRegion::new(
        SharedMemoryHandle::new(99),
        PortId::new(1),
        4096,
        MemoryAccess::ReadWrite,
    )
    .with_class(DataClass::Sensitive, RedactionState::SensitiveRedacted)
    .with_rights(rights(IPC_RIGHT_SHARE_MEMORY | IPC_RIGHT_SEAL));

    assert_eq!(base.validate_for_transfer(), Err(IpcError::NotSealed));
    let pinned = base.pin().unwrap();
    assert_eq!(pinned.state, SharedMemoryState::Pinned);
    let sealed = pinned.seal().unwrap();
    let grant = MemoryGrant::new(
        sealed,
        PortId::new(2),
        MemoryAccess::Read,
        MemoryMapIntent::Payload,
    )
    .with_trace(TraceContext::root(12, 1));

    assert_eq!(sealed.validate_for_transfer(), Ok(()));
    assert_eq!(grant.validate(sealed), Ok(()));
    assert_eq!(
        sealed.revoke().validate_for_transfer(),
        Err(IpcError::Revoked)
    );

    let read_only = SharedMemoryRegion::new(
        SharedMemoryHandle::new(100),
        PortId::new(1),
        128,
        MemoryAccess::Read,
    )
    .seal()
    .unwrap();
    let write_grant = MemoryGrant::new(
        read_only,
        PortId::new(2),
        MemoryAccess::Write,
        MemoryMapIntent::Response,
    );
    assert_eq!(write_grant.validate(read_only), Err(IpcError::AccessDenied));
}

#[test]
fn event_queues_report_overflow_and_drop_oldest_when_configured() {
    let event_one = IpcEvent::message(1, PortId::new(1), ChannelId::new(7), 100)
        .with_trace(TraceContext::root(1, 1));
    let event_two = IpcEvent::message(2, PortId::new(1), ChannelId::new(7), 101);
    let mut fail_closed = EventQueue::<1>::new();

    assert_eq!(fail_closed.push(event_one), Ok(()));
    assert_eq!(fail_closed.push(event_two), Err(IpcError::CapacityExceeded));
    assert_eq!(fail_closed.status().overflow_count, 1);
    assert_eq!(fail_closed.pop().unwrap().sequence, 1);
    assert!(fail_closed.is_empty());

    let mut drop_oldest = EventQueue::<1>::with_policy(QueuePolicy::DropOldest);
    assert_eq!(drop_oldest.push(event_one), Ok(()));
    assert_eq!(drop_oldest.push(event_two), Ok(()));
    assert_eq!(drop_oldest.status().overflow_count, 1);
    assert_eq!(drop_oldest.pop().unwrap().sequence, 2);
}

#[test]
fn router_resolves_routes_and_denies_missing_rights_or_disabled_rules() {
    let mut router = IpcRouter::<2>::new();
    let route = RouteRule::new(
        1,
        "runtime-kernel-control",
        PortId::new(1),
        PortId::new(2),
        ChannelId::new(7),
    )
    .with_kind(MessageKind::Request)
    .with_required_rights(rights(IPC_RIGHT_SEND | IPC_RIGHT_ROUTE));
    let channels = [channel()];

    assert_eq!(router.add_route(route), Ok(()));
    assert_eq!(router.add_route(route), Err(IpcError::DuplicateRoute));

    let decision = router
        .resolve(
            message(),
            source_port(),
            target_port(),
            &channels,
            rights(IPC_RIGHT_SEND | IPC_RIGHT_ROUTE | IPC_RIGHT_ADMIN),
        )
        .unwrap();
    assert_eq!(decision.validate(), Ok(()));
    assert!(decision.audit_required);

    assert_eq!(
        router.resolve(
            message(),
            source_port(),
            target_port(),
            &channels,
            IpcRights::SEND
        ),
        Err(IpcError::AccessDenied)
    );

    let mut disabled = IpcRouter::<1>::new();
    disabled
        .add_route(route.with_state(RouteState::Disabled))
        .unwrap();
    assert_eq!(
        disabled.resolve(
            message(),
            source_port(),
            target_port(),
            &channels,
            rights(IPC_RIGHT_SEND | IPC_RIGHT_ROUTE),
        ),
        Err(IpcError::InvalidRoute)
    );
}
