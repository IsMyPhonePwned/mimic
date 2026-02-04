//! RAR analyzer: CVE-2025-8088 (path traversal via Alternate Data Streams in WinRAR).

use crate::result::{AnalysisResult, FileComprehension, Threat, TrustLevel};
use crate::rar::parser::{collect_file_names, find_rar_signature, is_rar, RarVersion};

const CVE_2025_8088_ID: &str = "CVE-2025-8088";
const CVE_2025_8088_DESC: &str =
    "RAR path traversal via Alternate Data Streams (WinRAR; malicious files hidden in ADS, extracted to arbitrary paths)";
const CVE_2025_8088_REF: &str = "https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/";

/// Check if a file name indicates Alternate Data Stream (e.g. `doc.pdf:malicious.lnk`).
#[inline]
fn name_has_ads(name: &str) -> bool {
    name.contains(':')
}

/// Check if path contains directory traversal (`..`).
#[inline]
fn name_has_path_traversal(name: &str) -> bool {
    name.contains("..")
}

/// Analyze RAR data for CVE-2025-8088 (ADS + path traversal).
pub fn analyze_rar(data: &[u8]) -> AnalysisResult {
    let size = data.len();
    let mut comprehension = FileComprehension {
        format: "RAR".to_string(),
        details: Vec::new(),
        warnings: Vec::new(),
        extraction_rtf: None,
        extraction_dng_tile: None,
    };

    if !is_rar(data) {
        comprehension
            .details
            .push("Not a valid RAR archive (missing Rar! signature)".to_string());
        return AnalysisResult::benign(comprehension, Some(size));
    }

    let (version, first_block) = match find_rar_signature(data) {
        Some(x) => x,
        None => return AnalysisResult::benign(comprehension, Some(size)),
    };

    comprehension.details.push(format!(
        "RAR {} signature found, first block at offset {}",
        match version {
            RarVersion::Rar5 => "5.0",
            RarVersion::Rar4 => "4.x",
        },
        first_block
    ));

    let names = collect_file_names(data);
    comprehension
        .details
        .push(format!("File names in archive: {}", names.len()));

    let mut ads_names = Vec::<String>::new();
    let mut traversal_names = Vec::<String>::new();

    for name in &names {
        if name_has_ads(name) {
            ads_names.push(name.clone());
        }
        if name_has_path_traversal(name) {
            traversal_names.push(name.clone());
        }
    }

    if !ads_names.is_empty() || !traversal_names.is_empty() {
        if !ads_names.is_empty() {
            comprehension.warnings.push(format!(
                "CVE-2025-8088: Alternate Data Stream (ADS) names found: {}",
                ads_names.join(", ")
            ));
        }
        if !traversal_names.is_empty() {
            comprehension.warnings.push(format!(
                "CVE-2025-8088: Path traversal (..) in names: {}",
                traversal_names.join(", ")
            ));
        }
        let description = if !ads_names.is_empty() && !traversal_names.is_empty() {
            format!(
                "{} — ADS names (e.g. {}) and path traversal in names (e.g. {})",
                CVE_2025_8088_DESC,
                ads_names.first().map(|s| s.as_str()).unwrap_or(""),
                traversal_names.first().map(|s| s.as_str()).unwrap_or("")
            )
        } else if !ads_names.is_empty() {
            format!(
                "{} — ADS names: {}",
                CVE_2025_8088_DESC,
                ads_names.first().map(|s| s.as_str()).unwrap_or("")
            )
        } else {
            format!(
                "{} — Path traversal in names: {}",
                CVE_2025_8088_DESC,
                traversal_names.first().map(|s| s.as_str()).unwrap_or("")
            )
        };
        let threat = Threat {
            id: CVE_2025_8088_ID.to_string(),
            description,
            reference: Some(CVE_2025_8088_REF.to_string()),
            trust: TrustLevel::High,
        };
        return AnalysisResult::malicious(vec![threat], comprehension, Some(size));
    }

    AnalysisResult::benign(comprehension, Some(size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::Verdict;

    #[test]
    fn benign_rar_no_ads_no_traversal() {
        let mut v = vec![0u8; 256];
        v[0..8].copy_from_slice(b"Rar!\x1A\x07\x01\x00");
        let r = analyze_rar(&v);
        assert_eq!(r.verdict, Verdict::Benign);
    }

    #[test]
    fn malicious_rar_ads_name() {
        // Minimal RAR 5.0: signature + main header (type 1) + file header (type 2) with name "doc.pdf:malicious.lnk"
        // Header size (vint) = type(1)+flags(1)+file_flags(1)+unpacked(1)+attrs(1)+comp(1)+host_os(1)+name_len(1)+name(21) = 30
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
        let names = crate::rar::parser::collect_file_names(&v);
        assert!(
            names.iter().any(|n| n.contains(':')),
            "expected at least one name with ADS (':') in {:?}",
            names
        );
        let r = analyze_rar(&v);
        assert_eq!(r.verdict, Verdict::Malicious, "expected malicious: {:?}", r);
        assert!(
            r.threats.iter().any(|t| t.id == CVE_2025_8088_ID),
            "expected CVE-2025-8088 in {:?}",
            r.threats
        );
    }
}
