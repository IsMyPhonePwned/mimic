//! PDF analysis stub. CVE-2023-41990 and Operation Triangulation are primarily
//! associated with TTF (iMessage font parsing). PDF parsing can be extended for
//! other CVEs or triangulation-related PDF vectors.

mod analyzer;

pub use analyzer::{analyze_pdf, is_pdf};
