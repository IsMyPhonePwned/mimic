//! RAR analyzer and parser tests.

use mimic::{analyze_rar, Verdict};
use mimic::rar::{find_rar_signature, collect_file_names, is_rar, RarVersion};

#[test]
fn benign_rar_no_ads_no_traversal() {
    let mut v = vec![0u8; 256];
    v[0..8].copy_from_slice(b"Rar!\x1A\x07\x01\x00");
    let r = analyze_rar(&v);
    assert_eq!(r.verdict, Verdict::Benign);
}

#[test]
fn malicious_rar_ads_name() {
    let mut v = Vec::new();
    v.extend_from_slice(b"Rar!\x1A\x07\x01\x00");
    v.extend_from_slice(&[0u8; 4]);
    v.push(0x02);
    v.push(0x01);
    v.push(0x00);
    v.extend_from_slice(&[0u8; 4]);
    let name = b"doc.pdf:malicious.lnk";
    let header_size: u8 = 29;
    v.push(header_size);
    v.push(0x02);
    v.push(0x00);
    v.push(0x00);
    v.push(0x00);
    v.push(0x00);
    v.push(0x00);
    v.push(0x00);
    v.push(name.len() as u8);
    v.extend_from_slice(name);
    let names = collect_file_names(&v);
    assert!(
        names.iter().any(|n| n.contains(':')),
        "expected at least one name with ADS (':') in {:?}",
        names
    );
    let r = analyze_rar(&v);
    assert_eq!(r.verdict, Verdict::Malicious, "expected malicious: {:?}", r);
    assert!(r.threats.iter().any(|t| t.id == "CVE-2025-8088"));
}

#[test]
fn rar5_signature_found() {
    let mut v = vec![0u8; 20];
    v[10..18].copy_from_slice(b"Rar!\x1A\x07\x01\x00");
    let r = find_rar_signature(&v);
    assert!(r.is_some());
    let (ver, off) = r.unwrap();
    assert_eq!(ver, RarVersion::Rar5);
    assert_eq!(off, 18);
}

#[test]
fn rar4_signature_found() {
    let mut v = vec![0u8; 20];
    v[5..12].copy_from_slice(b"Rar!\x1A\x07\x00");
    let r = find_rar_signature(&v);
    assert!(r.is_some());
    let (ver, off) = r.unwrap();
    assert_eq!(ver, RarVersion::Rar4);
    assert_eq!(off, 12);
}

#[test]
fn not_rar() {
    assert!(!is_rar(b"PK\x03\x04"));
    assert!(!is_rar(b"Rar!\x1A\x06\x00"));
}
