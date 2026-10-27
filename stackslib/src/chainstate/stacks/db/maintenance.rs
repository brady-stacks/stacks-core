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

//! Offline maintenance of an independent chainstate copy. Never pass a live node's directory.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use stacks_common::types::chainstate::{ConsensusHash, SortitionId, StacksBlockId};
use stacks_marf::{trie_sql, MarfTrieId};

use super::{
    snapshot, StacksBlockHeaderTypes, StacksChainState, StacksHeaderInfo, CHAINSTATE_VERSION,
};
use crate::burnchains::bitcoin::spv::SPV_DB_VERSION;
use crate::burnchains::db::BurnchainDB;
use crate::chainstate::burn::db::sortdb::{SortitionDB, SORTITION_DB_VERSION};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::staging_blocks::NAKAMOTO_STAGING_DB_SCHEMA_LATEST;
use crate::config::Config;
use crate::core::FIRST_STACKS_BLOCK_ID;
use crate::util_lib::db::FromRow;

pub mod replay;
mod retention;
mod verification;

pub const INDEX: &str = "chainstate/vm/index.sqlite";
pub const CLARITY: &str = "chainstate/vm/clarity/marf.sqlite";
pub const SORTITION: &str = "burnchain/sortition/marf.sqlite";
pub const BURNCHAIN: &str = "burnchain/burnchain.sqlite";
pub const SPV: &str = "headers.sqlite";
pub const NAKAMOTO: &str = "chainstate/blocks/nakamoto.sqlite";

/// Exact parent-linked retained history, newest first. Heights never select a fork.
#[derive(Debug)]
pub struct RecoveryBoundary {
    pub target: StacksBlockId,
    pub stacks_height: u64,
    pub burn_tip: BlockSnapshot,
    pub stacks_blocks: Vec<StacksHeaderInfo>,
    pub sortitions: Vec<BlockSnapshot>,
}

fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn open(path: &Path, writable: bool) -> Result<Connection, String> {
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    Connection::open_with_flags(path, flags).map_err(|e| format!("{}: {e}", path.display()))
}

fn integrity(conn: &Connection, label: &str) -> Result<(), String> {
    let mut stmt = conn.prepare("PRAGMA integrity_check").map_err(error)?;
    let mut rows = stmt.query([]).map_err(error)?;
    while let Some(row) = rows.next().map_err(error)? {
        let result: String = row.get(0).map_err(error)?;
        if result != "ok" {
            return Err(format!("{label}: {result}"));
        }
    }
    Ok(())
}

fn schema(conn: &Connection, label: &str, expected: &str) -> Result<(), String> {
    let versions = conn
        .prepare("SELECT version FROM db_config")
        .map_err(error)?
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    let latest = versions
        .iter()
        .try_fold(None, |latest, version| {
            version
                .parse::<u64>()
                .map(|version| Some(latest.unwrap_or(0).max(version)))
        })
        .map_err(|e| format!("{label}: invalid schema version: {e}"))?;
    if latest != Some(expected.parse::<u64>().map_err(error)?) {
        return Err(format!(
            "{label}: unsupported schema {versions:?}; expected {expected}"
        ));
    }
    Ok(())
}

/// Read headers without opening the MARF or trusting any current-tip memo.
pub(super) fn read_stacks_ancestry(
    index: &Connection,
    target: &StacksBlockId,
) -> Result<Vec<StacksHeaderInfo>, String> {
    let mut blocks: Vec<StacksHeaderInfo> = Vec::new();
    let mut seen = HashSet::new();
    let mut id = target.clone();
    loop {
        if !seen.insert(id.clone()) {
            return Err(format!("Stacks ancestry cycle at {id}"));
        }
        let mut found = None;
        for table in ["nakamoto_block_headers", "block_headers"] {
            let mut stmt = index
                .prepare_cached(&format!(
                    "SELECT * FROM {table} WHERE index_block_hash = ?1"
                ))
                .map_err(error)?;
            let mut rows = stmt.query([&id]).map_err(error)?;
            if let Some(row) = rows.next().map_err(error)? {
                if found.is_some() {
                    return Err(format!("Conflicting header representations for {id}"));
                }
                // Legacy FromRow assumes these types; check them before calling it on recovery input.
                let _: String = row.get("block_size").map_err(error)?;
                let _: u32 = row.get("burn_header_height").map_err(error)?;
                if table == "block_headers" {
                    let _: u8 = row.get("version").map_err(error)?;
                    let _: String = row.get("total_burn").map_err(error)?;
                    let _: String = row.get("total_work").map_err(error)?;
                    let _: u16 = row.get("parent_microblock_sequence").map_err(error)?;
                }
                let header =
                    StacksHeaderInfo::from_row(row).map_err(|e| format!("Header {id}: {e}"))?;
                let parent: StacksBlockId = row.get("parent_block_id").map_err(error)?;
                if rows.next().map_err(error)?.is_some() {
                    return Err(format!("Duplicate header {id}"));
                }
                found = Some((header, parent));
            }
        }
        let (header, parent) = found.ok_or_else(|| format!("Missing retained header {id}"))?;
        if id != *FIRST_STACKS_BLOCK_ID && header.index_block_hash() != id {
            return Err(format!("Header identity mismatch for {id}"));
        }
        if let Some(child) = blocks.last() {
            if header.stacks_block_height.checked_add(1) != Some(child.stacks_block_height) {
                return Err(format!("Nonconsecutive Stacks ancestry at {id}"));
            }
            match &child.anchored_header {
                StacksBlockHeaderTypes::Nakamoto(h) if h.parent_block_id != id => {
                    return Err(format!("Parent mismatch at {}", child.index_block_hash()))
                }
                StacksBlockHeaderTypes::Epoch2(h)
                    if id != *FIRST_STACKS_BLOCK_ID
                        && h.parent_block != header.anchored_header.block_hash() =>
                {
                    return Err(format!(
                        "Parent hash mismatch at {}",
                        child.index_block_hash()
                    ))
                }
                _ => {}
            }
        }
        let height = header.stacks_block_height;
        blocks.push(header);
        if id == *FIRST_STACKS_BLOCK_ID {
            if height != 0 {
                return Err("Bootstrap header has nonzero height".into());
            }
            break;
        }
        id = parent;
    }
    Ok(blocks)
}

fn read_snapshot(
    conn: &Connection,
    column: &str,
    id: &dyn rusqlite::ToSql,
) -> Result<BlockSnapshot, String> {
    let mut stmt = conn
        .prepare_cached(&format!("SELECT * FROM snapshots WHERE {column} = ?1"))
        .map_err(error)?;
    let mut rows = stmt.query([id]).map_err(error)?;
    let row = rows
        .next()
        .map_err(error)?
        .ok_or_else(|| format!("Missing retained sortition ({column})"))?;
    let _: String = row.get("total_burn").map_err(error)?;
    for name in ["sortition", "stacks_block_accepted", "pox_valid"] {
        let _: bool = row.get(name).map_err(error)?;
    }
    row.get::<_, String>("accumulated_coinbase_ustx")
        .map_err(error)?
        .parse::<u128>()
        .map_err(error)?;
    let snapshot = BlockSnapshot::from_row(row).map_err(error)?;
    if rows.next().map_err(error)?.is_some() {
        return Err("Ambiguous retained sortition".into());
    }
    Ok(snapshot)
}

fn check_roots<T: MarfTrieId>(
    path: &Path,
    retained: &HashSet<T>,
    target: &T,
) -> Result<(), String> {
    let conn = open(path, false)?;
    let floor = trie_sql::read_squash_info(&conn).map_err(error)?;
    let historical = trie_sql::bulk_read_squashed_blocks::<T>(&conn).map_err(error)?;
    let historical_ids: HashSet<_> = historical.iter().map(|(_, id, _)| id).collect();
    eprintln!(
        "{}: history floor {}",
        path.display(),
        floor.as_ref().map_or(0, |info| info.squash_height)
    );
    if let Some(floor) = floor {
        let floor_id = historical
            .iter()
            .find(|(height, _, _)| *height == floor.squash_height)
            .map(|(_, id, _)| id)
            .ok_or("Missing squash boundary identity")?;
        if !retained.contains(floor_id) || (historical_ids.contains(target) && target != floor_id) {
            return Err(format!(
                "{}: target precedes available history floor {}",
                path.display(),
                floor.squash_height
            ));
        }
    }
    let mut stmt = conn
        .prepare("SELECT EXISTS(SELECT 1 FROM marf_data WHERE block_hash = ?1 AND unconfirmed = 0)")
        .map_err(error)?;
    for id in retained {
        if historical_ids.contains(id) {
            continue;
        }
        if !stmt
            .query_row([id], |row| row.get::<_, bool>(0))
            .map_err(error)?
        {
            return Err(format!(
                "{}: missing retained MARF root {id}",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Resolve a boundary on a private copy, without opening a writable database or current MARF tip.
pub fn resolve(
    network_dir: &Path,
    target: &StacksBlockId,
    config: &Config,
) -> Result<RecoveryBoundary, String> {
    resolve_with_burn_tip(network_dir, target, config, None)
}

fn resolve_with_burn_tip(
    network_dir: &Path,
    target: &StacksBlockId,
    config: &Config,
    current_burn_view: Option<ConsensusHash>,
) -> Result<RecoveryBoundary, String> {
    let index = open(&network_dir.join(INDEX), false)?;
    integrity(&index, INDEX)?;
    schema(&index, INDEX, CHAINSTATE_VERSION)?;
    snapshot::index::assert_source_tables_classified(&index).map_err(error)?;
    let (mainnet, chain_id): (bool, u32) = index
        .query_row("SELECT mainnet, chain_id FROM db_config", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(error)?;
    if mainnet != config.is_mainnet() || chain_id != config.burnchain.chain_id {
        return Err("Source network/chain ID does not match the selected configuration".into());
    }
    schema(&open(&network_dir.join(SPV), false)?, SPV, SPV_DB_VERSION)?;
    let burn_db = open(&network_dir.join(BURNCHAIN), false)?;
    let versions = burn_db
        .prepare("SELECT version FROM db_config")
        .map_err(error)?
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    let versions = versions
        .iter()
        .map(|v| v.parse::<u32>().map_err(error))
        .collect::<Result<Vec<_>, _>>()?;
    if versions.iter().max() != Some(&BurnchainDB::SCHEMA_VERSION) {
        return Err(format!(
            "{BURNCHAIN}: unsupported schema history {versions:?}"
        ));
    }
    let staging_version = StacksChainState::get_nakamoto_staging_blocks_db_version(&open(
        &network_dir.join(NAKAMOTO),
        false,
    )?)
    .map_err(error)?;
    if staging_version != NAKAMOTO_STAGING_DB_SCHEMA_LATEST {
        return Err(format!("{NAKAMOTO}: unsupported schema {staging_version}; expected {NAKAMOTO_STAGING_DB_SCHEMA_LATEST}"));
    }
    let stacks_blocks = read_stacks_ancestry(&index, target)?;
    let header = &stacks_blocks[0];
    let stacks_height = header.stacks_block_height;
    let sortdb = open(&network_dir.join(SORTITION), false)?;
    integrity(&sortdb, SORTITION)?;
    schema(&sortdb, SORTITION, &SORTITION_DB_VERSION.to_string())?;
    snapshot::sortition::assert_source_tables_classified(&sortdb).map_err(error)?;
    eprintln!("Schemas: chainstate {CHAINSTATE_VERSION}, sortition {SORTITION_DB_VERSION}");
    let burn_view = current_burn_view
        .as_ref()
        .unwrap_or_else(|| header.burn_view.as_ref().unwrap_or(&header.consensus_hash));
    let burn_tip = read_snapshot(&sortdb, "consensus_hash", burn_view)?;
    let mut current = burn_tip.clone();
    let mut sortitions = Vec::new();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current.sortition_id.clone()) {
            return Err(format!(
                "Sortition ancestry cycle at {}",
                current.sortition_id
            ));
        }
        if current.is_initial() {
            sortitions.push(current);
            break;
        }
        let parent = read_snapshot(&sortdb, "sortition_id", &current.parent_sortition_id)?;
        if parent.block_height.checked_add(1) != Some(current.block_height)
            || parent.burn_header_hash != current.parent_burn_header_hash
        {
            return Err(format!("Broken burn ancestry at {}", current.sortition_id));
        }
        sortitions.push(current);
        current = parent;
    }
    let burnchain = config.get_burnchain();
    let first = sortitions.last().ok_or("Empty burn ancestry")?;
    if first.block_height != burnchain.first_block_height
        || first.burn_header_hash != burnchain.first_block_hash
    {
        return Err("Source burnchain genesis does not match the selected configuration".into());
    }
    let snapshots: HashMap<_, _> = sortitions.iter().map(|s| (&s.consensus_hash, s)).collect();
    for header in &stacks_blocks {
        if header.stacks_block_height == 0 {
            continue;
        }
        let elected = snapshots.get(&header.consensus_hash).ok_or_else(|| {
            format!(
                "Missing election sortition for {}",
                header.index_block_hash()
            )
        })?;
        let view = snapshots
            .get(header.burn_view.as_ref().unwrap_or(&header.consensus_hash))
            .ok_or("Block burn view is outside retained ancestry")?;
        if elected.burn_header_hash != header.burn_header_hash
            || elected.block_height != u64::from(header.burn_header_height)
            || elected.block_height > view.block_height
        {
            return Err(format!(
                "Header burn identity mismatch at {}",
                header.index_block_hash()
            ));
        }
    }
    let stacks_ids = stacks_blocks
        .iter()
        .map(|h| {
            if h.stacks_block_height == 0 {
                FIRST_STACKS_BLOCK_ID.clone()
            } else {
                h.index_block_hash()
            }
        })
        .collect();
    check_roots(&network_dir.join(INDEX), &stacks_ids, target)?;
    check_roots(&network_dir.join(CLARITY), &stacks_ids, target)?;
    let sortition_ids = sortitions.iter().map(|s| s.sortition_id.clone()).collect();
    check_roots(
        &network_dir.join(SORTITION),
        &sortition_ids,
        &burn_tip.sortition_id,
    )?;
    Ok(RecoveryBoundary {
        target: target.clone(),
        stacks_height,
        burn_tip,
        stacks_blocks,
        sortitions,
    })
}

/// Rewind an independent private copy; the caller owns copy acquisition and atomic publication.
pub fn rollback(
    network_dir: &Path,
    target: &StacksBlockId,
    config: &Config,
) -> Result<RecoveryBoundary, String> {
    let boundary = resolve(network_dir, target, config)?;
    retention::rewind(network_dir, &boundary, config)?;
    verification::verify_boundary(network_dir, &boundary, config)?;
    Ok(boundary)
}

/// Verify a private copy's current canonical boundary, without changing its selected chain.
pub fn verify(network_dir: &Path, config: &Config) -> Result<RecoveryBoundary, String> {
    let sortdb = open(&network_dir.join(SORTITION), false)?;
    integrity(&sortdb, SORTITION)?;
    schema(&sortdb, SORTITION, &SORTITION_DB_VERSION.to_string())?;
    let canonical_id: SortitionId = sortdb.query_row(
        "SELECT sortition_id FROM snapshots WHERE pox_valid = 1 ORDER BY block_height DESC, burn_header_hash ASC LIMIT 1",
        [], |row| row.get(0)).optional().map_err(error)?.ok_or("Missing canonical burn tip")?;
    let burn_tip = read_snapshot(&sortdb, "sortition_id", &canonical_id)?;
    SortitionDB::get_stacks_epoch(&sortdb, burn_tip.block_height)
        .map_err(error)?
        .ok_or_else(|| {
            format!(
                "Missing epoch definition for canonical burn height {}",
                burn_tip.block_height
            )
        })?;
    let (ch, bh) = SortitionDB::get_canonical_stacks_chain_tip_hash(&sortdb).map_err(error)?;
    // Empty sortitions after the last Stacks block are valid in an ordinary snapshot.
    let boundary = resolve_with_burn_tip(
        network_dir,
        &StacksBlockId::new(&ch, &bh),
        config,
        Some(burn_tip.consensus_hash),
    )?;
    verification::verify_committed_headers(network_dir)?;
    verification::verify_boundary(network_dir, &boundary, config)?;
    Ok(boundary)
}
