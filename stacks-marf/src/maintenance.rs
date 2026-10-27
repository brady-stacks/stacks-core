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

//! Offline, identity-preserving maintenance of an independently copied MARF.
//! These operations must never be used against a running node or its source files.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use sha2::Digest;
use stacks_common::types::chainstate::TrieHash;

use crate::bits::read_nodetype_at_head;
use crate::marf::{
    BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, OWN_BLOCK_HEIGHT_KEY,
};
use crate::node::{is_backptr, TrieNodeID, TrieNodeType, TriePtr};
use crate::storage::{TrieFileStorage, TrieHashCalculationMode};
use crate::trie::Trie;
use crate::{
    blob_layout, trie_sql, Error, MARFOpenOpts, MARFValue, MarfTrieId, TrieHasher, MAX_PATCH_DEPTH,
};

fn corrupt(message: impl Into<String>) -> Error {
    Error::CorruptionError(message.into())
}

fn database(path: &Path, writable: bool) -> Result<Connection, Error> {
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let db = Connection::open_with_flags(path, flags)?;
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(corrupt(format!("MARF SQLite integrity: {integrity}")));
    }
    let versions = db
        .prepare("SELECT version FROM schema_version")?
        .query_map([], |row| row.get::<_, u64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if versions != [trie_sql::SQL_MARF_SCHEMA_VERSION] {
        return Err(corrupt(format!("Unsupported MARF schema: {versions:?}")));
    }
    if trie_sql::detect_partial_migration(&db)? {
        return Err(corrupt("Incomplete MARF blob migration"));
    }
    Ok(db)
}

struct Root<T> {
    id: u32,
    hash: T,
    offset: u64,
    length: u64,
}

struct Roots<T> {
    rows: Vec<Root<T>>,
    archival: Vec<(u32, T, TrieHash)>,
    squash: Option<trie_sql::SqlSquashInfo>,
}

fn roots<T: MarfTrieId>(db: &Connection, retained: &HashSet<T>) -> Result<Roots<T>, Error> {
    // Query known identities directly: decoding a discarded malformed hash
    // would unnecessarily make an otherwise readable prefix unrecoverable.
    let identities: HashSet<_> = retained
        .iter()
        .cloned()
        .chain(std::iter::once(T::sentinel()))
        .collect();
    let mut stmt = db.prepare("SELECT block_id, external_offset, external_length, length(data) FROM marf_data WHERE unconfirmed = 0 AND block_hash = ?1")?;
    let mut result = Vec::new();
    for hash in identities {
        let row = stmt
            .query_row([&hash], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })
            .optional()?;
        if let Some((id, offset, external_length, inline_length)) = row {
            result.push(Root {
                id,
                hash,
                offset,
                length: if external_length > 0 {
                    external_length
                } else {
                    inline_length
                },
            });
        }
    }
    let archival = trie_sql::bulk_read_squashed_blocks::<T>(db)?;
    let squash = trie_sql::read_squash_info(db)?;
    if let Some(info) = &squash {
        let floor = archival
            .iter()
            .find(|(height, _, _)| *height == info.squash_height)
            .ok_or_else(|| corrupt("Missing MARF squash floor identity"))?;
        if !retained.contains(&floor.1) || !result.iter().any(|root| root.hash == floor.1) {
            return Err(corrupt(format!(
                "Retained MARF history must include squash floor {} ({})",
                info.squash_height, floor.1
            )));
        }
        if floor.2 != info.archival_marf_root_hash {
            return Err(corrupt("Squash floor archival commitment mismatch"));
        }
        if archival.len() as u64 != u64::from(info.squash_height) + 1
            || archival
                .iter()
                .enumerate()
                .any(|(i, (height, _, _))| u64::from(*height) != i as u64)
        {
            return Err(corrupt("Incomplete squash archival commitments"));
        }
    } else if !archival.is_empty() {
        return Err(corrupt(
            "Squashed block commitments without squash metadata",
        ));
    }
    let represented: HashSet<_> = result
        .iter()
        .map(|root| &root.hash)
        .chain(archival.iter().map(|(_, hash, _)| hash))
        .collect();
    for hash in retained {
        if *hash != T::sentinel() && !represented.contains(hash) {
            return Err(corrupt(format!("Missing retained MARF root {hash}")));
        }
    }
    Ok(Roots {
        rows: result,
        archival,
        squash,
    })
}

/// Remove discarded roots and transient state, preserving every retained row ID,
/// blob offset, and byte. Call only on a private, offline maintenance copy.
/// Discarded extents are deliberately not read, compacted, or truncated.
pub fn retain_roots<T: MarfTrieId>(path: &Path, retained: &HashSet<T>) -> Result<(), Error> {
    let mut db = database(path, true)?;
    let retained_roots = roots(&db, retained)?;
    let tx = db.transaction()?;
    tx.execute_batch(
        "CREATE TEMP TABLE maintenance_retained_roots (block_id INTEGER PRIMARY KEY)",
    )?;
    for root in retained_roots.rows {
        tx.prepare_cached("INSERT INTO maintenance_retained_roots VALUES (?1)")?
            .execute([root.id])?;
    }
    tx.execute_batch("DELETE FROM marf_data WHERE unconfirmed != 0 OR block_id NOT IN (SELECT block_id FROM maintenance_retained_roots);
        DELETE FROM mined_blocks;
        DELETE FROM block_extension_locks;
        DROP TABLE maintenance_retained_roots;")?;
    tx.commit()?;
    drop(db);
    verify_roots(path, retained)?;
    Ok(())
}

// SQLite blobs and external files share the same bounded decoder. In particular,
// a corrupt node cannot read bytes belonging to another root's blob extent.
struct Region<'a, R> {
    reader: &'a mut R,
    start: u64,
    length: u64,
    position: u64,
}

impl<R: Read + Seek> Read for Region<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = (self.length - self.position).min(bytes.len() as u64) as usize;
        let read = self.reader.read(&mut bytes[..count])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for Region<'_, R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MARF node outside retained extent",
            ));
        }
        self.position = next as u64;
        self.reader.seek(SeekFrom::Start(
            self.start.checked_add(self.position).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "MARF offset overflow")
            })?,
        ))?;
        Ok(self.position)
    }
}

fn decode<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    length: u64,
    ptr: TriePtr,
) -> Result<(TrieNodeType, TrieHash), Error> {
    let mut region = Region {
        reader,
        start,
        length,
        position: 0,
    };
    region.seek(SeekFrom::Start(ptr.ptr()))?;
    read_nodetype_at_head(&mut region, ptr.id())
}

fn read_node<T: MarfTrieId>(
    db: &Connection,
    file: &mut Option<File>,
    rows: &HashMap<u32, &Root<T>>,
    mut id: u32,
    mut ptr: TriePtr,
) -> Result<(TrieNodeType, TrieHash), Error> {
    let origin = id;
    let mut patches = Vec::new();
    let mut original_hash = None;
    for _ in 0..=MAX_PATCH_DEPTH {
        let row = rows.get(&id).ok_or_else(|| {
            corrupt(format!(
                "MARF backpointer depends on discarded local ID {id}"
            ))
        })?;
        let decoded = if let Some(file) = file {
            decode(file, row.offset, row.length, ptr)
        } else {
            let mut blob = trie_sql::open_trie_blob_readonly(db, id)?;
            decode(&mut blob, 0, row.length, ptr)
        };
        match decoded {
            Ok((node, hash)) => {
                patches.reverse();
                let node = node
                    .apply_patches(&patches, origin)
                    .ok_or_else(|| corrupt("Invalid retained MARF patches"))?;
                return Ok((node, original_hash.unwrap_or(hash)));
            }
            Err(Error::Patch(hash, patch)) => {
                original_hash = original_hash.or(hash);
                let next = patch.ptr;
                patches.push((id, ptr, patch));
                id = next.back_block();
                ptr = next.from_backptr();
            }
            Err(error) => {
                return Err(corrupt(format!(
                    "Retained MARF node {}:{}: {error}",
                    row.hash,
                    ptr.ptr()
                )))
            }
        }
    }
    Err(corrupt("Retained MARF patch depth exceeded"))
}

// Maintenance lookups must not trust the ordinary cursor's assumptions about
// persisted paths. A hash path consumes at most 32 branch/path bytes.
fn lookup<T: MarfTrieId>(
    db: &Connection,
    file: &mut Option<File>,
    rows: &HashMap<u32, &Root<T>>,
    mut id: u32,
    key: &str,
) -> Result<MARFValue, Error> {
    let path = TrieHash::from_key(key);
    let mut position = 0usize;
    let mut ptr = TriePtr::new(
        TrieNodeID::Node256 as u8,
        0,
        blob_layout::ROOT_NODE_OFFSET as u64,
    );
    for _ in 0..=32 {
        let (node, _) = read_node(db, file, rows, id, ptr)?;
        let end = position
            .checked_add(node.path_bytes().len())
            .ok_or_else(|| corrupt("MARF path overflow"))?;
        if path.as_bytes().get(position..end) != Some(node.path_bytes().as_slice()) {
            return Err(corrupt(format!("Invalid retained MARF path for {key}")));
        }
        position = end;
        if let TrieNodeType::Leaf(leaf) = node {
            if position != 32 {
                return Err(corrupt("Invalid retained MARF leaf depth"));
            }
            return Ok(leaf.data);
        }
        let chr = *path
            .as_bytes()
            .get(position)
            .ok_or_else(|| corrupt("Retained MARF branch exceeds hash path"))?;
        let child = node
            .ptrs()
            .iter()
            .find(|child| child.id() != TrieNodeID::Empty as u8 && child.chr() == chr)
            .ok_or_else(|| corrupt(format!("Missing retained MARF bookkeeping key {key}")))?;
        if is_backptr(child.id()) {
            id = child.back_block();
        }
        ptr = child.from_backptr();
        position += 1;
    }
    Err(corrupt("Retained MARF lookup exceeds hash depth"))
}

fn parent_hash<T: MarfTrieId>(
    db: &Connection,
    file: &mut Option<File>,
    root: &Root<T>,
) -> Result<T, Error> {
    let mut bytes = [0; 32];
    if let Some(file) = file {
        file.seek(SeekFrom::Start(root.offset))?;
        file.read_exact(&mut bytes)?;
    } else {
        trie_sql::open_trie_blob_readonly(db, root.id)?.read_exact(&mut bytes)?;
    }
    Ok(T::from_bytes(bytes))
}

/// Verify retained trie contents, backpointer closure, and ancestor commitments.
/// Returns distinct reachable application values, excluding MARF bookkeeping by
/// exact key path (never by a value's shape or existence in side storage).
pub fn verify_roots<T: MarfTrieId>(
    path: &Path,
    retained: &HashSet<T>,
) -> Result<Vec<MARFValue>, Error> {
    let db = database(path, false)?;
    let Roots {
        rows: root_rows,
        archival,
        squash,
    } = roots(&db, retained)?;
    let path_str = path.to_str().ok_or_else(|| corrupt("Non-UTF8 MARF path"))?;
    let external = crate::file::TrieFile::exists(path_str)?;
    let mut file = if external {
        Some(File::open(format!("{path_str}.blobs"))?)
    } else {
        None
    };
    let file_length = file
        .as_ref()
        .map(|f| f.metadata().map(|m| m.len()))
        .transpose()?;
    for root in &root_rows {
        if root.length < blob_layout::READER_PREFIX_LEN as u64
            || file_length.is_some_and(|length| {
                root.offset
                    .checked_add(root.length)
                    .is_none_or(|end| end > length)
            })
        {
            return Err(corrupt(format!(
                "Retained MARF root {} has invalid blob extent",
                root.hash
            )));
        }
    }
    let rows: HashMap<_, _> = root_rows.iter().map(|row| (row.id, row)).collect();
    let archived: HashMap<_, _> = archival
        .iter()
        .map(|(height, hash, _)| (hash.clone(), *height))
        .collect();
    let mut storage = TrieFileStorage::<T>::open_readonly(
        path_str,
        MARFOpenOpts::new(TrieHashCalculationMode::Immediate, external),
    )?;
    let mut conn = storage.connection();
    let mut internal = HashMap::from([(TrieHash::from_key(OWN_BLOCK_HEIGHT_KEY), 4usize)]);
    let mut max_height = 0;
    let history_size = root_rows
        .iter()
        .map(|root| &root.hash)
        .chain(archival.iter().map(|(_, hash, _)| hash))
        .collect::<HashSet<_>>()
        .len();
    let mut by_height: HashMap<_, _> = archival
        .iter()
        .map(|(height, hash, _)| (*height, hash.clone()))
        .collect();
    let mut heights = HashMap::new();
    for root in &root_rows {
        // Read untrusted bookkeeping only through the bounded maintenance cursor.
        let height = if let Some(height) = archived.get(&root.hash) {
            *height
        } else {
            let value = lookup(&db, &mut file, &rows, root.id, OWN_BLOCK_HEIGHT_KEY)?;
            if value.0[4..].iter().any(|byte| *byte != 0) {
                return Err(corrupt("Invalid retained MARF height encoding"));
            }
            u32::from_le_bytes(
                value.0[..4]
                    .try_into()
                    .map_err(|_| corrupt("Invalid MARF height"))?,
            )
        };
        if u64::from(height) >= history_size as u64 {
            return Err(corrupt(format!(
                "MARF height {height} exceeds retained history ({history_size} roots)"
            )));
        }
        if by_height
            .insert(height, root.hash.clone())
            .is_some_and(|previous| previous != root.hash)
        {
            return Err(corrupt(format!(
                "Conflicting retained MARF identities at height {height}"
            )));
        }
        heights.insert(root.id, height);
        max_height = max_height.max(height);
        internal.insert(
            TrieHash::from_key(&format!(
                "{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{}",
                root.hash
            )),
            4,
        );
        if !squash
            .as_ref()
            .is_some_and(|info| height < info.squash_height)
        {
            // commit_to preserves the provisional identity used by begin().
            // Its hash-to-height entry remains in the committed trie.
            let value = lookup(
                &db,
                &mut file,
                &rows,
                root.id,
                &format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{height}"),
            )?;
            if value.0[32..].iter().any(|byte| *byte != 0) {
                return Err(corrupt("Invalid provisional MARF identity encoding"));
            }
            let provisional = T::from(value);
            internal.insert(
                TrieHash::from_key(&format!(
                    "{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{provisional}"
                )),
                4,
            );
        }
    }
    if by_height.len() as u64 != u64::from(max_height) + 1 {
        return Err(corrupt("Retained MARF history has missing heights"));
    }
    // Establish the parent/height lineage before using any height as a range
    // bound. Shared squash blobs have only the floor's materialized parent.
    for root in &root_rows {
        let height = heights[&root.id];
        if squash
            .as_ref()
            .is_some_and(|info| height <= info.squash_height)
        {
            continue;
        }
        let parent = parent_hash(&db, &mut file, root)?;
        let expected = if height == 0 {
            T::sentinel()
        } else {
            by_height
                .get(&(height - 1))
                .cloned()
                .ok_or_else(|| corrupt("Missing retained MARF parent height"))?
        };
        if parent != expected {
            return Err(corrupt(format!(
                "Retained MARF parent/height mismatch: {}",
                root.hash
            )));
        }
    }
    for (_, hash, _) in &archival {
        internal.insert(
            TrieHash::from_key(&format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{hash}")),
            4,
        );
    }
    for height in by_height.keys() {
        internal.insert(
            TrieHash::from_key(&format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{height}")),
            32,
        );
    }
    let mut seen = HashMap::new();
    let mut values = HashSet::new();
    let mut root_commitments = Vec::new();
    for root in &root_rows {
        if squash.as_ref().is_some_and(|info| {
            archived
                .get(&root.hash)
                .is_some_and(|height| *height < info.squash_height)
        }) {
            continue;
        }
        let mut stack = vec![(
            root.id,
            TriePtr::new(
                TrieNodeID::Node256 as u8,
                0,
                blob_layout::ROOT_NODE_OFFSET as u64,
            ),
            Vec::new(),
        )];
        while let Some((id, ptr, mut prefix)) = stack.pop() {
            let row = rows.get(&id).ok_or_else(|| {
                corrupt(format!(
                    "MARF backpointer depends on discarded local ID {id}"
                ))
            })?;
            let physical = (if external { row.offset } else { u64::from(id) }, ptr.ptr());
            if let Some(previous) = seen.get(&physical) {
                if previous != &prefix {
                    return Err(corrupt(
                        "Retained MARF node has conflicting paths or a cycle",
                    ));
                }
                continue;
            }
            seen.insert(physical, prefix.clone());
            let (node, stored_hash) = read_node(&db, &mut file, &rows, id, ptr.from_backptr())?;
            prefix.extend_from_slice(node.path_bytes());
            if prefix.len() > 32 {
                return Err(corrupt("Retained MARF path exceeds hash length"));
            }
            let content = if let TrieNodeType::Leaf(leaf) = &node {
                crate::bits::get_leaf_hash(leaf)
            } else {
                // Consensus serialization assumes every backpointer is valid
                // and panics otherwise; recovery must reject corrupt input.
                for child in node.ptrs() {
                    if is_backptr(child.id()) && !rows.contains_key(&child.back_block()) {
                        return Err(corrupt(format!(
                            "MARF backpointer depends on discarded local ID {}",
                            child.back_block()
                        )));
                    }
                }
                conn.open_block_known_id(&row.hash, id)?;
                let mut hasher = TrieHasher::new();
                node.write_consensus_bytes(&mut conn, &mut hasher)?;
                for child in node.ptrs() {
                    if child.id() == TrieNodeID::Empty as u8 {
                        hasher.update(TrieHash::EMPTY.as_bytes());
                        continue;
                    }
                    let child_id = if is_backptr(child.id()) {
                        child.back_block()
                    } else {
                        id
                    };
                    let child_row = rows.get(&child_id).ok_or_else(|| {
                        corrupt(format!(
                            "MARF backpointer depends on discarded local ID {child_id}"
                        ))
                    })?;
                    if is_backptr(child.id()) {
                        hasher.update(child_row.hash.as_bytes());
                    } else {
                        let (_, hash) =
                            read_node(&db, &mut file, &rows, child_id, child.from_backptr())?;
                        hasher.update(hash.as_bytes());
                    }
                    let mut child_path = prefix.clone();
                    child_path.push(child.chr());
                    stack.push((child_id, child.from_backptr(), child_path));
                }
                TrieHash(hasher.finalize().into())
            };
            let expected = if ptr.ptr() == blob_layout::ROOT_NODE_OFFSET as u64 {
                if let Some(info) = squash
                    .as_ref()
                    .filter(|info| archived.get(&row.hash) == Some(&info.squash_height))
                {
                    if content != info.squash_root_node_hash {
                        return Err(corrupt("Squash root content hash mismatch"));
                    }
                    content
                } else {
                    root_commitments.push((row.hash.clone(), id, content, stored_hash));
                    stored_hash
                }
            } else {
                content
            };
            if expected != stored_hash {
                return Err(corrupt(format!(
                    "Retained MARF node hash mismatch: {}:{}",
                    row.hash,
                    ptr.ptr()
                )));
            }
            if let TrieNodeType::Leaf(leaf) = node {
                let path = TrieHash::from_bytes(&prefix)
                    .ok_or_else(|| corrupt("Invalid retained leaf path"))?;
                if let Some(length) = internal.get(&path) {
                    if leaf.data.0[*length..].iter().any(|byte| *byte != 0) {
                        return Err(corrupt("Invalid retained MARF bookkeeping encoding"));
                    }
                } else {
                    values.insert(leaf.data);
                }
            }
        }
    }
    // Only use the ordinary ancestor lookup after validating every retained
    // node and its bookkeeping encodings (ordinary conversions assume validity).
    for (hash, id, content, stored) in root_commitments {
        let height = heights[&id];
        let own_height = lookup(&db, &mut file, &rows, id, OWN_BLOCK_HEIGHT_KEY)?;
        if own_height != MARFValue::from(height) {
            return Err(corrupt(format!(
                "Retained MARF height mapping mismatch: {hash}"
            )));
        }
        for depth in 0..32 {
            let distance = 1u32 << depth;
            if distance > height {
                break;
            }
            let ancestor_height = height - distance;
            let expected = by_height
                .get(&ancestor_height)
                .ok_or_else(|| corrupt("Missing retained MARF ancestor"))?;
            let value = lookup(
                &db,
                &mut file,
                &rows,
                id,
                &format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{ancestor_height}"),
            )?;
            if value.0[32..].iter().any(|byte| *byte != 0) || &value.0[..32] != expected.as_bytes()
            {
                return Err(corrupt(format!(
                    "Retained MARF ancestor mapping mismatch: {hash} at height {ancestor_height}"
                )));
            }
        }
        conn.open_block_known_id(&hash, id)?;
        if Trie::get_trie_root_hash(&mut conn, &content)? != stored {
            return Err(corrupt(format!(
                "Retained MARF ancestor commitment mismatch: {hash}"
            )));
        }
    }
    Ok(values.into_iter().collect())
}

/// Read the commitments used by headers/snapshots. Squashed history returns its
/// archival commitments, not the materialized squash trie's content hash.
/// Call `verify_roots` first to establish the underlying storage integrity.
pub fn root_hashes<T: MarfTrieId>(
    path: &Path,
    retained: &HashSet<T>,
) -> Result<HashMap<T, TrieHash>, Error> {
    let db = database(path, false)?;
    let Roots { rows, archival, .. } = roots(&db, retained)?;
    let path_str = path.to_str().ok_or_else(|| corrupt("Non-UTF8 MARF path"))?;
    let mut file = if crate::file::TrieFile::exists(path_str)? {
        Some(File::open(format!("{path_str}.blobs"))?)
    } else {
        None
    };
    let row_map = rows.iter().map(|row| (row.id, row)).collect();
    let mut hashes = HashMap::new();
    for row in &rows {
        let (_, hash) = read_node(
            &db,
            &mut file,
            &row_map,
            row.id,
            TriePtr::new(
                TrieNodeID::Node256 as u8,
                0,
                blob_layout::ROOT_NODE_OFFSET as u64,
            ),
        )?;
        hashes.insert(row.hash.clone(), hash);
    }
    for (_, hash, root) in archival {
        if retained.contains(&hash) {
            hashes.insert(hash, root);
        }
    }
    Ok(hashes)
}
