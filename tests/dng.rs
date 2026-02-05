//! DNG analyzer, TIFF, and JPEG Lossless tests.

use mimic::{analyze_dng, Verdict};
use mimic::dng::{
    TIFF_MAGIC, IFD_ENTRY_LEN, TAG_SUB_IFD, TAG_IMAGE_WIDTH, TAG_IMAGE_HEIGHT,
    TAG_TILE_WIDTH, TAG_TILE_HEIGHT, TAG_TILE_OFFSETS, TAG_TILE_BYTE_COUNTS, TAG_OPCODE_LIST_1,
    TYPE_UNDEFINED, read_tiff_header, Endian, sof3_component_count,
};

fn put_u16_le(b: &mut [u8], v: u16) {
    b[0..2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32_le(b: &mut [u8], v: u32) {
    b[0..4].copy_from_slice(&v.to_le_bytes());
}
fn put_ifd_entry(b: &mut [u8], tag: u16, typ: u16, count: u32, val: u32) {
    put_u16_le(&mut b[0..2], tag);
    put_u16_le(&mut b[2..4], typ);
    put_u32_le(&mut b[4..8], count);
    put_u32_le(&mut b[8..12], val);
}

#[test]
fn tiff_header_little() {
    let data: Vec<u8> = vec![0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00];
    let (bo, ifd0) = read_tiff_header(&data).unwrap();
    assert!(matches!(bo, Endian::Little));
    assert_eq!(ifd0, 8);
}

#[test]
fn tiff_header_big() {
    let data: Vec<u8> = vec![0x4D, 0x4D, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08];
    let (bo, ifd0) = read_tiff_header(&data).unwrap();
    assert!(matches!(bo, Endian::Big));
    assert_eq!(ifd0, 8);
}

#[test]
fn sof3_found() {
    let data = [
        0x00, 0x00, 0xFF, 0xC3, 0x00, 0x08, 0x08, 0x00, 0x01, 0x00, 0x01, 0x02,
    ];
    let count = sof3_component_count(&data).unwrap();
    assert_eq!(count, 2);
}

#[test]
fn sof3_one_component() {
    let data = [
        0xFF, 0xC3, 0x00, 0x08, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01,
    ];
    let count = sof3_component_count(&data).unwrap();
    assert_eq!(count, 1);
}

#[test]
fn benign_dng_no_mismatch() {
    let sof3_2 = [0xFF, 0xC3, 0x00, 0x08, 0x08, 0x00, 0x01, 0x00, 0x01, 0x02];
    let subifd_off = 32u32;
    let jpeg_off = 100u32;
    let mut v = Vec::new();
    v.extend_from_slice(&[0x49u8, 0x49]);
    v.extend_from_slice(&TIFF_MAGIC.to_le_bytes());
    v.extend_from_slice(&8u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    let mut entry = [0u8; 12];
    put_ifd_entry(&mut entry, 0x014A, 4, 1, subifd_off);
    v.extend_from_slice(&entry);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.resize(subifd_off as usize + 2 + 4 * IFD_ENTRY_LEN + 4, 0);
    let base = subifd_off as usize + 2;
    put_u16_le(&mut v[subifd_off as usize..], 4);
    put_ifd_entry(&mut v[base..base + 12], 0x0103, 3, 1, 7);
    put_ifd_entry(&mut v[base + 12..base + 24], 0x0115, 3, 1, 2);
    put_ifd_entry(&mut v[base + 24..base + 36], 0x0201, 4, 1, jpeg_off);
    put_ifd_entry(&mut v[base + 36..base + 48], 0x0111, 4, 1, jpeg_off);
    v.resize(jpeg_off as usize + sof3_2.len(), 0);
    v[jpeg_off as usize..].copy_from_slice(&sof3_2);
    let r = analyze_dng(&v);
    assert_eq!(r.verdict, Verdict::Benign);
}

#[test]
fn malicious_cve_2025_43300() {
    let sof3_1 = [0xFF, 0xC3, 0x00, 0x08, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01];
    let subifd_off = 32u32;
    let jpeg_off = 90u32;
    let mut v = Vec::new();
    v.extend_from_slice(&[0x49u8, 0x49]);
    v.extend_from_slice(&TIFF_MAGIC.to_le_bytes());
    v.extend_from_slice(&8u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&[0x4A, 0x01, 4, 0, 1, 0, 0, 0]);
    v.extend_from_slice(&subifd_off.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.resize(subifd_off as usize + 2 + 4 * IFD_ENTRY_LEN + 4, 0);
    let base = subifd_off as usize + 2;
    put_u16_le(&mut v[subifd_off as usize..], 4);
    put_ifd_entry(&mut v[base..base + 12], 0x0103, 3, 1, 7);
    put_ifd_entry(&mut v[base + 12..base + 24], 0x0115, 3, 1, 2);
    put_ifd_entry(&mut v[base + 24..base + 36], 0x0201, 4, 1, jpeg_off);
    put_ifd_entry(&mut v[base + 36..base + 48], 0x0111, 4, 1, jpeg_off);
    v.resize(jpeg_off as usize + sof3_1.len(), 0);
    v[jpeg_off as usize..].copy_from_slice(&sof3_1);
    let r = analyze_dng(&v);
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(r.threats.iter().any(|t| t.id == "CVE-2025-43300"));
}

#[test]
fn crafted_sample_should_flag_structure_anomaly() {
    let bytes = include_bytes!("../testdata/dng/poc.jpeg");
    let r = analyze_dng(bytes);
    assert!(
        r.verdict == Verdict::Malicious || r.verdict == Verdict::Suspicious,
        "expected suspicious/malicious, got {:?} warnings={:?}",
        r.verdict,
        r.comprehension.warnings
    );
}

#[test]
fn malicious_cve_2025_21043_excessive_opcode_count() {
    let subifd_off = 64u32;
    let mut v = Vec::new();
    v.extend_from_slice(&[0x49u8, 0x49]);
    v.extend_from_slice(&TIFF_MAGIC.to_le_bytes());
    v.extend_from_slice(&8u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    let mut entry = [0u8; 12];
    put_ifd_entry(&mut entry, TAG_SUB_IFD, 4, 1, subifd_off);
    v.extend_from_slice(&entry);
    v.extend_from_slice(&[0x4A, 0x01, 4, 0, 1, 0, 0, 0]);
    v.extend_from_slice(&subifd_off.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.resize(subifd_off as usize + 2 + IFD_ENTRY_LEN + 4, 0);
    let base = subifd_off as usize + 2;
    put_u16_le(&mut v[subifd_off as usize..], 1);
    put_ifd_entry(
        &mut v[base..base + 12],
        TAG_OPCODE_LIST_1,
        TYPE_UNDEFINED,
        4,
        1_000_001u32.to_be(),
    );
    v.extend_from_slice(&0u32.to_le_bytes());
    let r = analyze_dng(&v);
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(r.threats.iter().any(|t| t.id == "CVE-2025-21043"));
}

#[test]
fn malicious_tile_config_mismatch() {
    let subifd_off = 80u32;
    let mut v = Vec::new();
    v.extend_from_slice(&[0x49u8, 0x49]);
    v.extend_from_slice(&TIFF_MAGIC.to_le_bytes());
    v.extend_from_slice(&8u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&[0x4A, 0x01, 4, 0, 1, 0, 0, 0]);
    v.extend_from_slice(&subifd_off.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.resize(subifd_off as usize + 2 + 6 * IFD_ENTRY_LEN + 4 + 32, 0);
    let base = subifd_off as usize + 2;
    put_u16_le(&mut v[subifd_off as usize..], 6);
    let mut off = base;
    put_ifd_entry(&mut v[off..off + 12], TAG_IMAGE_WIDTH, 4, 1, 100);
    off += 12;
    put_ifd_entry(&mut v[off..off + 12], TAG_IMAGE_HEIGHT, 4, 1, 100);
    off += 12;
    put_ifd_entry(&mut v[off..off + 12], TAG_TILE_WIDTH, 4, 1, 50);
    off += 12;
    put_ifd_entry(&mut v[off..off + 12], TAG_TILE_HEIGHT, 4, 1, 50);
    off += 12;
    let tile_offsets_at = (subifd_off as usize + 2 + 6 * 12 + 4) + 16;
    put_ifd_entry(&mut v[off..off + 12], TAG_TILE_OFFSETS, 4, 1, tile_offsets_at as u32);
    off += 12;
    put_ifd_entry(&mut v[off..off + 12], TAG_TILE_BYTE_COUNTS, 4, 2, tile_offsets_at as u32 + 4);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.resize(tile_offsets_at + 12, 0);
    put_u32_le(&mut v[tile_offsets_at..], 100);
    put_u32_le(&mut v[tile_offsets_at + 4..], 200);
    put_u32_le(&mut v[tile_offsets_at + 8..], 300);
    let r = analyze_dng(&v);
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(r.threats.iter().any(|t| t.id == "DNG-TILE-CONFIG"));
}
