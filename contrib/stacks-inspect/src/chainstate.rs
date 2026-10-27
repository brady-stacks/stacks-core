// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Offline acquisition and publication. No database in the supplied source is opened.
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use stacks_common::types::chainstate::StacksBlockId;
use stackslib::chainstate::stacks::db::maintenance::{self, RecoveryBoundary};
use stackslib::config::Config;

static NEXT_COPY: AtomicU64 = AtomicU64::new(0);

fn fail(path: &Path, error: impl std::fmt::Display) -> String {
    format!("{}: {error}", path.display())
}

fn block_id(value: &str) -> Result<StacksBlockId, String> {
    StacksBlockId::from_hex(value).map_err(|e| format!("Invalid block ID {value}: {e}"))
}

fn configuration(config: Option<&Config>) -> Result<&Config, String> {
    config.ok_or_else(|| "Select --config or --network-config explicitly; recovery must use the node's actual network, PoX and epoch configuration".into())
}

fn report(boundary: &RecoveryBoundary, replay_to: Option<&StacksBlockId>) -> String {
    format!(
        "Target: {} (Stacks height {})\nBurn boundary: {} (height {}, sortition {})\nStorage checks: passed\n{}",
        boundary.target,
        boundary.stacks_height,
        boundary.burn_tip.burn_header_hash,
        boundary.burn_tip.block_height,
        boundary.burn_tip.sortition_id,
        match replay_to {
            Some(to) => format!(
                "Progression: verified {} -> {to} (committed and reopened)",
                boundary.target
            ),
            None => "Progression: not tested".into(),
        }
    )
}

pub fn rollback(
    source: &Path,
    target: &str,
    output: &Path,
    replay_to: Option<&str>,
    config: Option<&Config>,
) -> Result<String, String> {
    let config = configuration(config)?;
    let target = block_id(target)?;
    let replay_to = replay_to.map(block_id).transpose()?;
    let output = destination(source, output)?;
    let parent = output.parent().ok_or("Output has no parent")?;
    let candidate = PrivateCopy::acquire(source, parent, &config.burnchain.mode)?;
    checkpoint(&candidate.root)?;
    let boundary = maintenance::rollback(&candidate.network_dir, &target, config)?;
    if let Some(to) = &replay_to {
        let probe = PrivateCopy::acquire(&candidate.network_dir, parent, &config.burnchain.mode)?;
        maintenance::replay::replay(source, &probe.network_dir, &target, to, config)?;
    }
    candidate.publish(&output)?;
    Ok(format!(
        "{}\nPublished: {}",
        report(&boundary, replay_to.as_ref()),
        output.display()
    ))
}

pub fn verify(
    source: &Path,
    at_block: Option<&str>,
    replay_to: Option<&str>,
    config: Option<&Config>,
) -> Result<String, String> {
    let config = configuration(config)?;
    if replay_to.is_some() && at_block.is_none() {
        return Err("--replay-to requires --at-block".into());
    }
    let at_block = at_block.map(block_id).transpose()?;
    let replay_to = replay_to.map(block_id).transpose()?;
    let temporary = fs::canonicalize(std::env::temp_dir()).map_err(|e| e.to_string())?;
    let candidate = PrivateCopy::acquire(source, &temporary, &config.burnchain.mode)?;
    checkpoint(&candidate.root)?;
    let boundary = match at_block {
        Some(target) => maintenance::rollback(&candidate.network_dir, &target, config)?,
        None => maintenance::verify(&candidate.network_dir, config)?,
    };
    if let Some(to) = &replay_to {
        let probe =
            PrivateCopy::acquire(&candidate.network_dir, &temporary, &config.burnchain.mode)?;
        maintenance::replay::replay(source, &probe.network_dir, &boundary.target, to, config)?;
    }
    Ok(report(&boundary, replay_to.as_ref()))
}

/// An independent disposable working directory. Drop removes unpublished files;
/// abrupt process death can leave a `.stacks-recovery-partial-*` directory.
pub struct PrivateCopy {
    root: PathBuf,
    source: PathBuf,
    pub network_dir: PathBuf,
}

impl PrivateCopy {
    pub fn acquire(source: &Path, parent: &Path, network: &str) -> Result<Self, String> {
        if network.is_empty()
            || Path::new(network).components().count() != 1
            || !matches!(
                Path::new(network).components().next(),
                Some(Component::Normal(_))
            )
        {
            return Err("Invalid network directory name".into());
        }
        let source = checked_directory(source)?;
        let parent = checked_directory(parent)?;
        if parent.starts_with(&source) {
            return Err("Private copy must not be inside the source".into());
        }
        detect_live_source(&source)?;
        let before = inventory(&source)?;
        let bytes = before.iter().try_fold(0u64, |sum, entry| {
            sum.checked_add(entry.len)
                .ok_or("Required artifact size overflow")
        })?;
        let available = available_space(&parent)?;
        eprintln!("Consensus artifacts: {bytes} bytes; destination available: {available} bytes");
        if bytes > available {
            return Err(
                "Insufficient destination space for independent consensus-store copy".into(),
            );
        }
        let root = loop {
            let root = parent.join(format!(
                ".stacks-recovery-partial-{}-{}",
                std::process::id(),
                NEXT_COPY.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&root) {
                Ok(()) => break root,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(fail(&root, e)),
            }
        };
        let copy = Self {
            network_dir: root.join(network),
            root,
            source: source.clone(),
        };
        fs::create_dir(&copy.network_dir).map_err(|e| fail(&copy.network_dir, e))?;
        for directory in [
            "chainstate/vm/clarity",
            "chainstate/blocks",
            "burnchain/sortition",
        ] {
            let directory = copy.network_dir.join(directory);
            fs::create_dir_all(&directory).map_err(|e| fail(&directory, e))?;
        }
        for entry in &before {
            let from = source.join(&entry.relative);
            let to = copy.network_dir.join(&entry.relative);
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent).map_err(|e| fail(parent, e))?;
            }
            copy_file(&from, &to)?;
        }
        if before != inventory(&source)? {
            return Err("Source changed during acquisition; stop the node or use a coherent filesystem snapshot".into());
        }
        Ok(copy)
    }

    pub fn publish(self, output: &Path) -> Result<(), String> {
        let output = destination(&self.source, output)?;
        checkpoint(&self.root)?;
        sync_tree(&self.root)?;
        let parent = output.parent().ok_or("Output has no parent")?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| fail(parent, e))?;
        rename_exclusive(&self.root, &output).map_err(|e| fail(&output, e))?;
        if let Err(error) = File::open(parent).and_then(|f| f.sync_all()) {
            // Restore the unpublished name if the final directory entry could not be flushed.
            rename_exclusive(&output, &self.root).map_err(|e| {
                format!(
                    "Publication durability failed: {error}; cannot withdraw {}: {e}",
                    output.display()
                )
            })?;
            return Err(fail(parent, error));
        }
        Ok(())
    }
}

impl Drop for PrivateCopy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn checked_directory(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        if matches!(component, Component::ParentDir) {
            return Err(fail(path, "Parent-directory components are not supported"));
        }
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|e| fail(&current, e))?;
        if metadata.file_type().is_symlink() {
            return Err(fail(&current, "Symlink paths are not supported"));
        }
    }
    let canonical = fs::canonicalize(&absolute).map_err(|e| fail(path, e))?;
    if !canonical.is_dir() {
        return Err(fail(path, "Expected a directory"));
    }
    Ok(canonical)
}

fn destination(source: &Path, output: &Path) -> Result<PathBuf, String> {
    let source = checked_directory(source)?;
    let name = output
        .file_name()
        .ok_or("Output must name a new directory")?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let output = checked_directory(parent)?.join(name);
    match fs::symlink_metadata(&output) {
        Ok(_) => return Err(fail(&output, "Destination already exists")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(fail(&output, e)),
    }
    if output.starts_with(&source) || source.starts_with(&output) {
        return Err("Source and output must not alias or contain one another".into());
    }
    Ok(output)
}

#[derive(PartialEq, Eq)]
struct Artifact {
    relative: PathBuf,
    len: u64,
    modified: std::time::SystemTime,
}

fn inventory(source: &Path) -> Result<Vec<Artifact>, String> {
    let mut result = Vec::new();
    for directory in ["chainstate/vm", "chainstate/blocks", "burnchain/sortition"] {
        collect(source, &source.join(directory), &mut result)?;
    }
    for database in ["burnchain/burnchain.sqlite", "headers.sqlite"] {
        let base = source.join(database);
        for suffix in [
            "",
            "-wal",
            "-shm",
            "-journal",
            ".blobs",
            ".blobs-wal",
            ".blobs-shm",
            ".blobs-journal",
        ] {
            let path = PathBuf::from(format!("{}{suffix}", base.display()));
            match fs::symlink_metadata(&path) {
                Ok(_) => collect(source, &path, &mut result)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound && !suffix.is_empty() => {}
                Err(e) => return Err(fail(&path, e)),
            }
        }
    }
    for artifact in &result {
        if !known_artifact(&artifact.relative) {
            return Err(fail(
                &source.join(&artifact.relative),
                "Unclassified consensus-store file",
            ));
        }
    }
    result.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(result)
}

fn known_artifact(path: &Path) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    for base in [
        "chainstate/vm/index.sqlite",
        "chainstate/vm/clarity/marf.sqlite",
        "burnchain/sortition/marf.sqlite",
        "burnchain/burnchain.sqlite",
        "headers.sqlite",
        "chainstate/blocks/nakamoto.sqlite",
    ] {
        if let Some(suffix) = path.strip_prefix(base) {
            return [
                "",
                "-wal",
                "-shm",
                "-journal",
                ".blobs",
                ".blobs-wal",
                ".blobs-shm",
                ".blobs-journal",
            ]
            .contains(&suffix);
        }
    }
    let Some(block) = path.strip_prefix("chainstate/blocks/") else {
        return false;
    };
    let mut parts = block.split('/');
    let (Some(first), Some(second), Some(hash), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    first.len() == 4
        && second.len() == 4
        && hash.len() == 64
        && [first, second, hash]
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn collect(base: &Path, path: &Path, result: &mut Vec<Artifact>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| fail(path, e))?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| fail(path, e))? {
            collect(base, &entry.map_err(|e| fail(path, e))?.path(), result)?;
        }
    } else if metadata.is_file() {
        result.push(Artifact {
            relative: path
                .strip_prefix(base)
                .map_err(|e| fail(path, e))?
                .to_path_buf(),
            len: metadata.len(),
            modified: metadata.modified().map_err(|e| fail(path, e))?,
        });
    } else {
        return Err(fail(
            path,
            "Only ordinary files and directories are supported (no symlinks)",
        ));
    }
    Ok(())
}

fn copy_file(from: &Path, to: &Path) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut input = options.open(from).map_err(|e| fail(from, e))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .map_err(|e| fail(to, e))?;
    io::copy(&mut input, &mut output).map_err(|e| fail(to, e))?;
    Ok(())
}

fn detect_live_source(source: &Path) -> Result<(), String> {
    eprintln!(
        "Source must be a stopped node or coherent filesystem snapshot. Live-source detection is best-effort, not a lock."
    );
    match std::process::Command::new("lsof")
        .arg("-t")
        .arg("+D")
        .arg(source)
        .output()
    {
        Ok(result) if !result.stdout.is_empty() => Err(
            "Source has open files (lsof); stop the node and other users of this directory".into(),
        ),
        Ok(result) if result.status.code() == Some(1) && result.stderr.is_empty() => Ok(()),
        _ => {
            eprintln!(
                "Warning: unable to establish whether source files are open; operator must ensure source is frozen"
            );
            Ok(())
        }
    }
}

fn checkpoint(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|e| fail(root, e))? {
        let path = entry.map_err(|e| fail(root, e))?.path();
        if path.is_dir() {
            checkpoint(&path)?;
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "sqlite") {
            continue;
        }
        let mut header = [0u8; 16];
        File::open(&path)
            .and_then(|mut file| file.read_exact(&mut header))
            .map_err(|e| fail(&path, e))?;
        if &header != b"SQLite format 3\0" {
            return Err(fail(&path, "Not a SQLite database"));
        }
        let db = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .map_err(|e| fail(&path, e))?;
        let busy: i64 = db
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(|e| fail(&path, e))?;
        if busy != 0 {
            return Err(fail(&path, "SQLite checkpoint is busy"));
        }
        db.close().map_err(|(_, e)| fail(&path, e))?;
    }
    Ok(())
}

fn sync_tree(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|e| fail(root, e))? {
        let path = entry.map_err(|e| fail(root, e))?.path();
        if path.is_dir() {
            sync_tree(&path)?;
        } else {
            File::open(&path)
                .and_then(|f| f.sync_all())
                .map_err(|e| fail(&path, e))?;
        }
    }
    File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|e| fail(root, e))
}

#[cfg(unix)]
fn c_path(path: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

#[cfg(unix)]
fn available_space(path: &Path) -> Result<u64, String> {
    let path_c = c_path(path).map_err(|e| fail(path, e))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path_c is NUL-terminated and stats points to writable storage.
    if unsafe { libc::statvfs(path_c.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(fail(path, io::Error::last_os_error()));
    }
    // SAFETY: successful statvfs initialized stats.
    let stats = unsafe { stats.assume_init() };
    (stats.f_bavail as u64)
        .checked_mul(stats.f_frsize as u64)
        .ok_or_else(|| "Available disk space overflow".into())
}

#[cfg(not(unix))]
fn available_space(_: &Path) -> Result<u64, String> {
    Err("Recovery publication currently requires Linux or macOS".into())
}

fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let from = c_path(from)?;
        let to = c_path(to)?;
        // SAFETY: paths are valid NUL-terminated strings. Exclusive rename does not replace destinations.
        #[cfg(target_os = "linux")]
        let status = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let status = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (from, to);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Atomic no-clobber publication requires Linux or macOS",
        ))
    }
}
