pub mod cli;
pub mod engine;
pub mod hash;
pub mod scan;
pub mod signatures;
pub mod zip_detect;

pub use engine::{identify, Detection};
pub use scan::{scan, FileRow, ScanOptions};
pub use signatures::{merged, CompiledFormat};
