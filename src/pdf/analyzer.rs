//! PDF format detection and analysis stub.
//! Extend for PDF-specific CVE checks (e.g. triangulation PDF vectors) if needed.

use crate::result::{AnalysisResult, FileComprehension};

/// PDF magic: %PDF (first 4 bytes after optional whitespace).
const PDF_MAGIC: &[u8] = b"%PDF";

/// Check if data looks like a PDF.
#[inline]
pub fn is_pdf(data: &[u8]) -> bool {
    if data.len() < PDF_MAGIC.len() {
        return false;
    }
    data[0..PDF_MAGIC.len()] == *PDF_MAGIC
}

/// Analyze PDF. Currently benign; extend for CVE checks.
pub fn analyze_pdf(data: &[u8]) -> AnalysisResult {
    let size = data.len();
    let comprehension = FileComprehension {
        format: "PDF".to_string(),
        details: if is_pdf(data) {
            vec!["PDF document".to_string()]
        } else {
            vec!["Not a valid PDF (missing %PDF)".to_string()]
        },
        warnings: Vec::new(),
        extraction_rtf: None,
        extraction_dng_tile: None,
    };
    AnalysisResult::benign(comprehension, Some(size))
}
