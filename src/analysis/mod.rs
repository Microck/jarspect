mod classfile_evidence;
mod evidence;

pub use classfile_evidence::extract_bytecode_evidence;
pub use evidence::{BytecodeEvidence, BytecodeEvidenceItem, Location, LocationMethod};
