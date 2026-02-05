//! TTF/OTF analyzer and parser tests.

use mimic::{analyze_ttf, Verdict};
use mimic::ttf::is_ttf;

#[test]
fn benign_ttf_no_adjust() {
    let mut v = vec![0u8; 256];
    v[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    v[4..6].copy_from_slice(&1u16.to_be_bytes());
    v[12..16].copy_from_slice(b"fpgm");
    v[24..28].copy_from_slice(&16u32.to_be_bytes());
    v[28..32].copy_from_slice(&4u32.to_be_bytes());
    v[32..36].copy_from_slice(&[0x40, 0x01, 0x00, 0x59]);
    let r = analyze_ttf(&v);
    assert_eq!(r.verdict, Verdict::Benign);
}

#[test]
fn malicious_ttf_adjust_in_fpgm() {
    let mut v = vec![0u8; 256];
    v[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    v[4..6].copy_from_slice(&1u16.to_be_bytes());
    v[12..16].copy_from_slice(b"fpgm");
    v[20..24].copy_from_slice(&32u32.to_be_bytes());
    v[24..28].copy_from_slice(&4u32.to_be_bytes());
    v[32] = 0x8F;
    let r = analyze_ttf(&v);
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(r.threats.iter().any(|t| t.id == "CVE-2023-41990"));
}

#[test]
fn malicious_ttf_gvar_negative_i16_cve_2025_27363() {
    let mut v = vec![0u8; 256];
    v[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    v[4..6].copy_from_slice(&2u16.to_be_bytes());
    v[12..16].copy_from_slice(b"gvar");
    v[20..24].copy_from_slice(&64u32.to_be_bytes());
    v[24..28].copy_from_slice(&48u32.to_be_bytes());
    v[28..32].copy_from_slice(&0u32.to_be_bytes());
    v[32..36].copy_from_slice(b"head");
    v[36..40].copy_from_slice(&112u32.to_be_bytes());
    v[40..44].copy_from_slice(&64u32.to_be_bytes());
    v[44..48].copy_from_slice(&6u32.to_be_bytes());
    v[64] = 0x80;
    v[65] = 0x00;
    let r = analyze_ttf(&v);
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(r.threats.iter().any(|t| t.id == "CVE-2025-27363"));
}

#[test]
fn ttf_magic() {
    let mut h = vec![0u8; 32];
    h[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    h[4..6].copy_from_slice(&5u16.to_be_bytes());
    assert!(is_ttf(&h));
}
