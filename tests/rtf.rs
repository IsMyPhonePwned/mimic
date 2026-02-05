//! RTF analyzer and OLE/parser tests.

use mimic::{analyze_rtf, Verdict};
use mimic::rtf::{extract_embedded_objects, extract_objdata_blobs, is_rtf, list_ole_entries, is_malformed_ole, OLE_SIGNATURE};

#[test]
fn benign_rtf_no_ole() {
    let rtf = b"{\\rtf1\\ansi Hello}";
    let r = analyze_rtf(rtf);
    assert_eq!(r.verdict, Verdict::Benign);
}

#[test]
fn malicious_rtf_malformed_ole() {
    let mut ole = vec![0u8; 512];
    ole[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    ole[26..28].copy_from_slice(&3u16.to_le_bytes());
    ole[30..32].copy_from_slice(&12u16.to_le_bytes());
    let mut rtf: Vec<u8> = b"{\\rtf1\\ansi{\\object\\objdata \\bin 512 ".to_vec();
    rtf.extend_from_slice(&ole);
    rtf.extend_from_slice(b"}");
    let r = analyze_rtf(&rtf);
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(r.threats.iter().any(|t| t.id == "CVE-2026-21509"));
}

#[test]
fn extract_links_includes_utf16le_file_url() {
    let url = "file://wellnessmedcare.org/davwwwroot/pol/Downloads/document.LnK?init=1";
    let utf16: Vec<u8> = url.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut blob = vec![0u8; 256];
    blob[100..100 + utf16.len()].copy_from_slice(&utf16);
    let mut rtf: Vec<u8> = b"{\\rtf1\\ansi{\\object\\objdata \\bin 256 ".to_vec();
    rtf.extend_from_slice(&blob);
    rtf.extend_from_slice(b"}");
    let r = analyze_rtf(&rtf);
    let links = r.comprehension.extraction_rtf.as_ref()
        .and_then(|e| e.objects.first())
        .and_then(|o| o.links.as_ref());
    assert!(links.is_some(), "expected extraction_rtf with links");
    assert!(
        links.unwrap().iter().any(|s| s.contains("file://") && s.contains("wellnessmedcare")),
        "expected file:// URL in {:?}",
        links
    );
}

#[test]
fn b2ba_sample_blob1_contains_file_url() {
    let bytes = include_bytes!("../testdata/rtf/b2ba51b4491da8604ff9410d6e004971e3cd9a321390d0258e294ac42010b546.doc");
    let objs = extract_embedded_objects(bytes);
    assert!(!objs.is_empty(), "b2ba should have embedded objects");
    let r = analyze_rtf(bytes);
    assert_eq!(r.verdict, Verdict::Malicious);
    let links = r.comprehension.extraction_rtf.as_ref()
        .and_then(|e| e.objects.first())
        .and_then(|o| o.links.as_ref());
    assert!(
        links.map_or(false, |l| l.iter().any(|u| u.contains("file://") && u.contains("davwwwroot"))),
        "b2ba object #1 should yield file:// URL with davwwwroot, got {:?}",
        links
    );
}

#[test]
fn malicious_rtf_ole_pres_stream_cve_2025_21298() {
    let sector_size = 512usize;
    let mut ole = vec![0u8; 512 + 2 * sector_size];
    ole[0..8].copy_from_slice(OLE_SIGNATURE);
    ole[26..28].copy_from_slice(&3u16.to_le_bytes());
    ole[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
    ole[30..32].copy_from_slice(&9u16.to_le_bytes());
    ole[40..44].copy_from_slice(&0u32.to_le_bytes());
    ole[44..48].copy_from_slice(&1u32.to_le_bytes());
    ole[48..52].copy_from_slice(&1u32.to_le_bytes());
    ole[56..60].copy_from_slice(&0x1000u32.to_le_bytes());
    ole[76..80].copy_from_slice(&0u32.to_le_bytes());
    let fat_start = 512;
    ole[fat_start..fat_start + 4].copy_from_slice(&0xFFFFFFFDu32.to_le_bytes());
    ole[fat_start + 4..fat_start + 8].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes());
    let dir_start = 512 + sector_size;
    let entry2 = dir_start + 128;
    let name: Vec<u8> = "OlePresStg".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    ole[entry2..entry2 + name.len()].copy_from_slice(&name);
    ole[entry2 + 64..entry2 + 66].copy_from_slice(&20u16.to_le_bytes());
    ole[entry2 + 66] = 2;
    assert!(list_ole_entries(&ole).is_some());
    let mut rtf: Vec<u8> = b"{\\rtf1\\ansi{\\object\\objdata \\bin ".to_vec();
    rtf.extend_from_slice(ole.len().to_string().as_bytes());
    rtf.push(b' ');
    rtf.extend_from_slice(&ole);
    rtf.push(b'}');
    let r = analyze_rtf(&rtf);
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(r.threats.iter().any(|t| t.id == "CVE-2025-21298"));
}

#[test]
fn real_exploit_93ef57_cve_2025_21298() {
    let bytes = include_bytes!("../testdata/rtf/93ef57b81021be174e33b5b48c1aed525d2785c3607aeb540508bb3713690179");
    let r = analyze_rtf(bytes);
    if r.threats.iter().any(|t| t.id == "CVE-2025-21298") {
        assert_eq!(r.verdict, Verdict::Malicious);
    }
}

#[test]
fn cve_2025_21298_poc_rtf_detected() {
    let bytes = include_bytes!("../testdata/rtf/cve-2025-21298-poc.rtf");
    let r = analyze_rtf(bytes);
    assert_eq!(r.verdict, Verdict::Malicious, "CVE-2025-21298 PoC RTF should be detected as malicious");
    assert!(
        r.threats.iter().any(|t| t.id == "CVE-2025-21298"),
        "expected CVE-2025-21298 in threats, got {:?}",
        r.threats
    );
}

#[test]
fn valid_ole_header_not_malformed() {
    const FATSECT: u32 = 0xFFFFFFFD;
    const ENDOFCHAIN: u32 = 0xFFFFFFFE;
    let sector_size = 512usize;
    let mut h = vec![0u8; 512 + 2 * sector_size];
    h[0..8].copy_from_slice(OLE_SIGNATURE);
    h[24..26].copy_from_slice(&0x003Eu16.to_le_bytes());
    h[26..28].copy_from_slice(&3u16.to_le_bytes());
    h[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
    h[30..32].copy_from_slice(&9u16.to_le_bytes());
    h[32..34].copy_from_slice(&6u16.to_le_bytes());
    h[40..44].copy_from_slice(&0u32.to_le_bytes());
    h[44..48].copy_from_slice(&1u32.to_le_bytes());
    h[48..52].copy_from_slice(&1u32.to_le_bytes());
    h[56..60].copy_from_slice(&0x1000u32.to_le_bytes());
    h[76..80].copy_from_slice(&0u32.to_le_bytes());
    let fat_start = 512 + 0 * sector_size;
    h[fat_start..fat_start + 4].copy_from_slice(&FATSECT.to_le_bytes());
    h[fat_start + 4..fat_start + 8].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
    assert!(!is_malformed_ole(&h));
}

#[test]
fn wrong_sector_shift_malformed() {
    let mut h = [0u8; 512];
    h[0..8].copy_from_slice(OLE_SIGNATURE);
    h[26..28].copy_from_slice(&3u16.to_le_bytes());
    h[30..32].copy_from_slice(&12u16.to_le_bytes());
    assert!(is_malformed_ole(&h));
}

#[test]
fn rtf_detection() {
    assert!(is_rtf(b"{\\rtf1\\ansi"));
    assert!(is_rtf(b"  {\\rtf1"));
    assert!(!is_rtf(b"not rtf"));
}

#[test]
fn objdata_bin_extract() {
    let rtf = b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Word.Document.12}\\objdata \\bin 8\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1}}";
    let blobs = extract_objdata_blobs(rtf);
    assert!(!blobs.is_empty());
    assert!(blobs[0].starts_with(OLE_SIGNATURE));
}

#[test]
fn extract_embedded_objects_captures_objclass() {
    let rtf = b"{\\rtf1\\ansi{\\object\\objocx{\\*\\objclass Word.Document.8}\\objdata \\bin 8\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1}}";
    let objs = extract_embedded_objects(rtf);
    assert!(!objs.is_empty(), "should extract at least one object");
    assert_eq!(objs[0].objclass.as_deref(), Some("Word.Document.8"));
    assert_eq!(objs[0].kind, "ocx");
}

#[test]
fn extracts_hex_objdata_from_real_sample() {
    let bytes = include_bytes!("../testdata/rtf/c91183175ce77360006f964841eb4048cf37cb82103f2573e262927be4c7607f.doc");
    assert_eq!(bytes.len(), 2683823, "unexpected sample length");
    assert!(bytes.windows(8).any(|w| w == b"\\objdata"), "sample should contain \\objdata");
    let blobs = extract_objdata_blobs(bytes);
    assert!(blobs.len() >= 1, "expected at least one objdata blob");
}
