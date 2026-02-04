//! DNG (Digital Negative) analysis for parsing exploit detection.
//!
//! Targets:
//! - **CVE-2025-43300**: Apple RawCamera.bundle heap overflow (SamplesPerPixel vs SOF3 component count mismatch).
//! - **Project Zero 442423708**: Android/Samsung Quram DNG in-the-wild exploit (detection heuristics extensible).

mod analyzer;
mod jpeg_lossless;
mod tiff;

pub use analyzer::analyze_dng;
pub use jpeg_lossless::{find_sof3, sof3_component_count, SOF3_MARKER};
pub use tiff::{
    read_tiff_header, read_ifd_entry, walk_ifd, read_sub_ifd_offsets, read_short_tag, read_long_tag,
    Endian, IfdEntry, TIFF_MAGIC, TAG_SUB_IFD, TAG_SAMPLES_PER_PIXEL, TAG_COMPRESSION,
    TAG_STRIP_OFFSETS, TAG_JPEG_INTERCHANGE_FORMAT, COMPRESSION_JPEG,
};
