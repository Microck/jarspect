use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        bail!("usage: build-regression-fixtures <classes-dir> <output-jar>");
    }

    let classes_dir = PathBuf::from(&args[1]);
    let output_jar = PathBuf::from(&args[2]);

    if !classes_dir.is_dir() {
        bail!(
            "classes directory does not exist: {}",
            classes_dir.display()
        );
    }

    if let Some(parent) = output_jar.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating output dir: {}", parent.display()))?;
    }

    let mut files = Vec::new();
    collect_files(classes_dir.as_path(), classes_dir.as_path(), &mut files)?;
    files.sort();

    let output = File::create(&output_jar)
        .with_context(|| format!("failed creating jar: {}", output_jar.display()))?;
    let mut writer = ZipWriter::new(output);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644);

    for relative_path in files {
        let source_path = classes_dir.join(&relative_path);
        let bytes = fs::read(&source_path)
            .with_context(|| format!("failed reading file: {}", source_path.display()))?;

        let archive_path = normalize_archive_path(&relative_path)?;
        writer
            .start_file(archive_path, options)
            .with_context(|| format!("failed adding file to jar: {}", source_path.display()))?;
        writer
            .write_all(&bytes)
            .with_context(|| format!("failed writing file to jar: {}", source_path.display()))?;
    }

    writer.finish().context("failed finalizing jar")?;
    Ok(())
}

fn collect_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(current)
        .with_context(|| format!("failed listing directory: {}", current.display()))?
    {
        let entry = entry
            .with_context(|| format!("failed reading directory entry: {}", current.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files)?;
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("failed stripping prefix for: {}", path.display()))?;
        files.push(relative.to_path_buf());
    }

    Ok(())
}

fn normalize_archive_path(path: &Path) -> Result<String> {
    let value = path
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    if value.is_empty() {
        bail!("empty archive path");
    }

    Ok(value)
}
