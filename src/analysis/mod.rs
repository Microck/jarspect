pub mod archive;
mod byte_array_strings;
mod classfile_evidence;
mod evidence;
pub mod metadata;
pub mod yara;

pub use archive::{read_archive_entries_recursive, ArchiveEntry};
pub use classfile_evidence::extract_bytecode_evidence;
pub use evidence::{BytecodeEvidence, BytecodeEvidenceItem, Location, LocationMethod};
pub use metadata::{analyze_metadata, MetadataFinding};
pub use yara::{scan_yara_rulepacks, RulepackKind, YaraRulepack};
