pub mod archive;
mod byte_array_strings;
mod classfile_evidence;
mod evidence;
pub mod metadata;
pub mod yara;

pub use archive::{ArchiveEntry, read_archive_entries_recursive};
pub use classfile_evidence::extract_bytecode_evidence;
pub use evidence::{BytecodeEvidence, BytecodeEvidenceItem, Location, LocationMethod};
pub use metadata::{MetadataFinding, analyze_metadata};
pub use yara::{RulepackKind, YaraRulepack, scan_yara_rulepacks};
