//! Tests for file type detection and top-level analyze().

use mimic::{detect_file_type, FileType};

#[test]
fn detect_dng_little() {
    let data = [0x49u8, 0x49, 0x2A, 0x00, 0, 0, 0, 0];
    assert_eq!(detect_file_type(&data), FileType::Dng);
}

#[test]
fn detect_unknown() {
    let data = [0u8; 8];
    assert_eq!(detect_file_type(&data), FileType::Unknown);
}

#[test]
fn detect_rtf() {
    let data = b"{\\rtf1\\ansi";
    assert_eq!(detect_file_type(data), FileType::Rtf);
}

#[test]
fn detect_ttf() {
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    data[4..6].copy_from_slice(&5u16.to_be_bytes());
    assert_eq!(detect_file_type(&data), FileType::Ttf);
}

#[test]
fn detect_pdf() {
    let data = b"%PDF-1.4";
    assert_eq!(detect_file_type(data), FileType::Pdf);
}

#[test]
fn detect_rar() {
    let mut data = vec![0u8; 20];
    data[0..8].copy_from_slice(b"Rar!\x1A\x07\x01\x00");
    assert_eq!(detect_file_type(&data), FileType::Rar);
}
