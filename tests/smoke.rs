#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_ipc::repository_name(), "alani-ipc");
    assert!(!alani_ipc::module_names().is_empty());
}
