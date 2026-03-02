use std::io::{Cursor, Read};

use anyhow::{Context, Result};
use tracing::debug;
use zip::ZipArchive;

const ZIP_MAGIC: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const MAX_RECURSION_DEPTH: usize = 3;
const MAX_TOTAL_ENTRIES: usize = 50_000;
const MAX_ENTRY_UNCOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_INFLATED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 256 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 1_000;

#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub path: String,
    pub bytes: Vec<u8>,
    pub text: Option<String>,
}

#[derive(Default)]
struct ArchiveBudgets {
    total_entries: usize,
    total_inflated_bytes: u64,
}

pub fn read_archive_entries_recursive(
    root_label: &str,
    jar_bytes: &[u8],
) -> Result<Vec<ArchiveEntry>> {
    let mut entries = Vec::new();
    let mut budgets = ArchiveBudgets::default();

    walk_archive(root_label, jar_bytes, 0, &mut budgets, &mut entries)
        .with_context(|| format!("Invalid .jar archive: {root_label}"))?;

    Ok(entries)
}

fn walk_archive(
    archive_path_prefix: &str,
    jar_bytes: &[u8],
    depth: usize,
    budgets: &mut ArchiveBudgets,
    entries: &mut Vec<ArchiveEntry>,
) -> Result<()> {
    let cursor = Cursor::new(jar_bytes.to_vec());
    let mut archive = ZipArchive::new(cursor)?;

    for index in 0..archive.len() {
        if budgets.total_entries >= MAX_TOTAL_ENTRIES {
            debug!(
                archive_path = %archive_path_prefix,
                max_total_entries = MAX_TOTAL_ENTRIES,
                "archive traversal stopped after reaching total entry budget"
            );
            break;
        }

        let mut file = archive.by_index(index)?;
        if file.is_dir() {
            continue;
        }

        let relative_path = normalize_entry_path(file.name());
        let full_path = format!("{archive_path_prefix}!/{relative_path}");
        let uncompressed_size = file.size();
        let compressed_size = file.compressed_size();

        if uncompressed_size > MAX_ENTRY_UNCOMPRESSED_BYTES {
            debug!(
                file_path = %full_path,
                uncompressed_size,
                max_entry_uncompressed_bytes = MAX_ENTRY_UNCOMPRESSED_BYTES,
                "skipping entry that exceeds uncompressed size limit"
            );
            continue;
        }

        if has_extreme_compression_ratio(uncompressed_size, compressed_size) {
            debug!(
                file_path = %full_path,
                uncompressed_size,
                compressed_size,
                max_compression_ratio = MAX_COMPRESSION_RATIO,
                "skipping entry that exceeds compression ratio guard"
            );
            continue;
        }

        let projected_total = budgets
            .total_inflated_bytes
            .saturating_add(uncompressed_size);
        if projected_total > MAX_TOTAL_INFLATED_BYTES {
            debug!(
                file_path = %full_path,
                total_inflated_bytes = budgets.total_inflated_bytes,
                entry_size = uncompressed_size,
                max_total_inflated_bytes = MAX_TOTAL_INFLATED_BYTES,
                "skipping entry that would exceed total inflated byte budget"
            );
            continue;
        }

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .with_context(|| format!("failed to read archive entry {full_path}"))?;

        budgets.total_entries += 1;
        budgets.total_inflated_bytes = projected_total;

        let text = if contents.len() <= MAX_TEXT_BYTES {
            Some(String::from_utf8_lossy(&contents).into_owned())
        } else {
            None
        };

        let is_nested_jar = is_embedded_jar(relative_path.as_str(), contents.as_slice());
        if is_nested_jar {
            if depth >= MAX_RECURSION_DEPTH {
                debug!(
                    file_path = %full_path,
                    depth,
                    max_depth = MAX_RECURSION_DEPTH,
                    "skipping embedded jar because recursion depth limit was reached"
                );
            } else if let Err(error) = walk_archive(
                full_path.as_str(),
                contents.as_slice(),
                depth + 1,
                budgets,
                entries,
            ) {
                debug!(
                    file_path = %full_path,
                    error = %error,
                    "skipping unreadable embedded jar"
                );
            }
        }

        entries.push(ArchiveEntry {
            path: full_path,
            bytes: contents,
            text,
        });
    }

    Ok(())
}

fn normalize_entry_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

fn has_extreme_compression_ratio(uncompressed_size: u64, compressed_size: u64) -> bool {
    if uncompressed_size == 0 {
        return false;
    }

    if compressed_size == 0 {
        return true;
    }

    uncompressed_size > compressed_size.saturating_mul(MAX_COMPRESSION_RATIO)
}

fn is_embedded_jar(entry_path: &str, contents: &[u8]) -> bool {
    entry_path.to_ascii_lowercase().ends_with(".jar") && contents.starts_with(&ZIP_MAGIC)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::read_archive_entries_recursive;

    #[test]
    fn recursive_archive_reader_renders_nested_jar_paths() {
        let inner_jar = build_jar(&[("payload.txt", b"c2.jarspect.example.invalid")]);
        let outer_jar = build_jar(&[
            ("META-INF/jars/inner-demo.jar", inner_jar.as_slice()),
            ("readme.txt", b"outer jar"),
        ]);

        let entries = read_archive_entries_recursive("upload.jar", outer_jar.as_slice())
            .expect("expected recursive reader to parse nested jar");

        let paths = entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();

        assert!(
            paths.contains(&"upload.jar!/META-INF/jars/inner-demo.jar"),
            "expected outer embedded jar entry"
        );
        assert!(
            paths.contains(&"upload.jar!/META-INF/jars/inner-demo.jar!/payload.txt"),
            "expected nested payload entry path"
        );
    }

    #[test]
    fn recursive_archive_reader_leaves_large_entries_textless() {
        let large_payload = vec![b'A'; 300 * 1024];
        let outer_jar = build_jar(&[("big.bin", large_payload.as_slice())]);

        let entries = read_archive_entries_recursive("upload.jar", outer_jar.as_slice())
            .expect("expected recursive reader to parse large entry");

        assert_eq!(entries.len(), 1);
        assert!(entries[0].text.is_none());
    }

    fn build_jar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o644);

        for (path, bytes) in entries {
            writer
                .start_file(path, options)
                .expect("failed to create zip entry");
            writer
                .write_all(bytes)
                .expect("failed to write zip entry bytes");
        }

        writer
            .finish()
            .expect("failed to finish zip writer")
            .into_inner()
    }
}
