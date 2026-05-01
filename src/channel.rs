//! `channel` module boundary.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelDescriptor<'a> {
    pub name: &'a str,
    pub version: u32,
}

impl<'a> ChannelDescriptor<'a> {
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
