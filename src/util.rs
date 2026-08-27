/// Lowercase hexadecimal encoding of a byte slice, one byte at a time.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
