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

use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksPublicKey};
use stacks_common::util::hash::MerkleHashFunc;
use stacks_marf::maintenance::retain_roots;

use super::*;
use crate::burnchains::bitcoin::spv::num_complete_chain_work_intervals;
use crate::chainstate::stacks::StacksMicroblock;
use crate::core::EMPTY_MICROBLOCK_PARENT_HASH;

pub(super) fn retained_blocks(boundary: &RecoveryBoundary) -> HashSet<StacksBlockId> {
    boundary
        .stacks_blocks
        .iter()
        .map(|h| {
            if h.stacks_block_height == 0 {
                FIRST_STACKS_BLOCK_ID.clone()
            } else {
                h.index_block_hash()
            }
        })
        .collect()
}

fn block_set(conn: &Connection, boundary: &RecoveryBoundary) -> Result<(), String> {
    conn.execute_batch("CREATE TEMP TABLE retained_blocks (id TEXT PRIMARY KEY)")
        .map_err(error)?;
    let mut insert = conn
        .prepare("INSERT INTO retained_blocks VALUES (?1)")
        .map_err(error)?;
    for id in retained_blocks(boundary) {
        insert.execute([id]).map_err(error)?;
    }
    Ok(())
}

fn burn_sets(conn: &Connection, boundary: &RecoveryBoundary) -> Result<(), String> {
    conn.execute_batch("CREATE TEMP TABLE retained_sortitions (id TEXT PRIMARY KEY); CREATE TEMP TABLE retained_burn (hash TEXT PRIMARY KEY)").map_err(error)?;
    let mut sortition = conn
        .prepare("INSERT INTO retained_sortitions VALUES (?1)")
        .map_err(error)?;
    let mut burn = conn
        .prepare("INSERT INTO retained_burn VALUES (?1)")
        .map_err(error)?;
    for snapshot in &boundary.sortitions {
        sortition.execute([&snapshot.sortition_id]).map_err(error)?;
        burn.execute([&snapshot.burn_header_hash]).map_err(error)?;
    }
    Ok(())
}

/// Only fixed table/column names from the store inventory reach this helper.
fn retain(conn: &Connection, table: &str, column: &str, set: &str) -> Result<(), String> {
    conn.execute(
        &format!("DELETE FROM {table} WHERE {column} NOT IN (SELECT * FROM {set})"),
        [],
    )
    .map_err(error)?;
    Ok(())
}

pub(super) fn check_epochs(
    conn: &Connection,
    boundary: &RecoveryBoundary,
    config: &Config,
) -> Result<(), String> {
    let stored = SortitionDB::get_stacks_epochs(conn).map_err(error)?;
    let configured = config.burnchain.get_epoch_list();
    for epoch in stored
        .iter()
        .filter(|e| e.start_height <= boundary.burn_tip.block_height)
    {
        let mut actual = epoch.clone();
        let expected = configured
            .iter()
            .find(|e| e.epoch_id == epoch.epoch_id)
            .ok_or_else(|| {
                format!(
                    "Epoch schedule diverges at {}; choose an earlier target",
                    epoch.start_height
                )
            })?;
        actual.end_height = actual
            .end_height
            .min(boundary.burn_tip.block_height.saturating_add(1));
        let mut expected = expected.clone();
        expected.end_height = expected
            .end_height
            .min(boundary.burn_tip.block_height.saturating_add(1));
        if actual != expected {
            return Err(format!(
                "Epoch schedule diverges at {}; choose an earlier target",
                epoch.start_height
            ));
        }
    }
    Ok(())
}

/// Confirm exact microblock ancestry from payloads, not just sequence counts.
pub(super) fn confirmed_microblocks(
    index: &Connection,
    boundary: &RecoveryBoundary,
) -> Result<HashSet<BlockHeaderHash>, String> {
    let mut keep = HashSet::new();
    for pair in boundary.stacks_blocks.windows(2) {
        let StacksBlockHeaderTypes::Epoch2(child) = &pair[0].anchored_header else {
            continue;
        };
        if child.parent_microblock == EMPTY_MICROBLOCK_PARENT_HASH
            && child.parent_microblock_sequence == 0
        {
            continue;
        }
        let parent = &pair[1];
        let parent_id = parent.index_block_hash();
        let mut hash = child.parent_microblock.clone();
        for sequence in (0..=child.parent_microblock_sequence).rev() {
            let bytes: Vec<u8> = index.query_row(
                "SELECT d.block_data FROM staging_microblocks_data d JOIN staging_microblocks s ON s.microblock_hash = d.block_hash WHERE s.index_block_hash = ?1 AND s.microblock_hash = ?2 AND s.sequence = ?3",
                params![parent_id, hash, sequence], |r| r.get(0)).optional().map_err(error)?
                .ok_or_else(|| format!("Missing confirmed microblock {hash} for {}", pair[0].index_block_hash()))?;
            let mut bytes = bytes.as_slice();
            let block = StacksMicroblock::consensus_deserialize(&mut bytes).map_err(error)?;
            if !bytes.is_empty() || block.block_hash() != hash || block.header.sequence != sequence
            {
                return Err(format!("Invalid confirmed microblock {hash}"));
            }
            keep.insert(hash);
            hash = block.header.prev_block;
        }
        if hash != parent.anchored_header.block_hash() {
            return Err(format!(
                "Confirmed microblock stream has wrong parent {parent_id}"
            ));
        }
    }
    Ok(keep)
}

fn rewind_index(path: &Path, boundary: &RecoveryBoundary, config: &Config) -> Result<(), String> {
    let mut conn = open(path, true)?;
    let microblocks = confirmed_microblocks(&conn, boundary)?;
    let tx = conn.transaction().map_err(error)?;
    tx.pragma_update(None, "defer_foreign_keys", true)
        .map_err(error)?;
    block_set(&tx, boundary)?;
    for table in [
        "block_headers",
        "nakamoto_block_headers",
        "payments",
        "transactions",
        "nakamoto_reward_sets",
        "burnchain_txids",
        "staging_blocks",
    ] {
        retain(&tx, table, "index_block_hash", "retained_blocks")?;
    }
    retain(&tx, "nakamoto_tenure_events", "block_id", "retained_blocks")?;
    retain(
        &tx,
        "matured_rewards",
        "child_index_block_hash",
        "retained_blocks",
    )?;
    retain(&tx, "epoch_transitions", "block_id", "retained_blocks")?;
    tx.execute_batch("CREATE TEMP TABLE retained_microblocks (hash TEXT PRIMARY KEY)")
        .map_err(error)?;
    for hash in microblocks {
        tx.prepare_cached("INSERT INTO retained_microblocks VALUES (?1)")
            .map_err(error)?
            .execute([hash])
            .map_err(error)?;
    }
    retain(
        &tx,
        "staging_microblocks",
        "microblock_hash",
        "retained_microblocks",
    )?;
    retain(
        &tx,
        "staging_microblocks",
        "index_block_hash",
        "retained_blocks",
    )?;
    retain(
        &tx,
        "staging_microblocks_data",
        "block_hash",
        "retained_microblocks",
    )?;
    tx.execute_batch("DELETE FROM invalidated_microblocks_data; DELETE FROM user_supporters; DELETE FROM signer_stats; UPDATE staging_blocks SET processed = 1, orphaned = 0; UPDATE staging_microblocks SET processed = 1, orphaned = 0;").map_err(error)?;
    let burnchain = config.get_burnchain();
    let mut insert = tx.prepare("INSERT INTO signer_stats(public_key,reward_cycle) VALUES(?1,?2) ON CONFLICT(public_key,reward_cycle) DO UPDATE SET blocks_signed=blocks_signed+1").map_err(error)?;
    for info in &boundary.stacks_blocks {
        let StacksBlockHeaderTypes::Nakamoto(header) = &info.anchored_header else {
            continue;
        };
        // append_block attributes signer statistics to the tenure's election height,
        // even when a tenure extension moves the Clarity burn view into another cycle.
        let cycle = burnchain
            .block_height_to_reward_cycle(u64::from(info.burn_header_height))
            .ok_or("Signer election predates reward cycles")?;
        let sighash = header.signer_signature_hash();
        for signature in &header.signer_signature {
            let key = StacksPublicKey::recover_to_pubkey_without_validating_low_s(
                sighash.bits(),
                signature,
            )
            .map_err(error)?;
            insert
                .execute(params![key.to_hex(), cycle])
                .map_err(error)?;
        }
    }
    drop(insert);
    tx.commit().map_err(error)
}

fn rewind_sortitions(
    path: &Path,
    boundary: &RecoveryBoundary,
    config: &Config,
) -> Result<(), String> {
    let sortition_dir = path.parent().ok_or("Missing sortition directory")?;
    let db = SortitionDB::open(
        sortition_dir.to_str().ok_or("Non-UTF8 sortition path")?,
        false,
        config.get_burnchain().pox_constants,
        None,
    )
    .map_err(error)?;
    // New roots record SQL's monotonically increasing global arrival maximum.
    // Older archival roots below a squash floor need not (and cannot) be read.
    let arrival_watermark = db
        .index_handle(&boundary.burn_tip.sortition_id)
        .get_stacks_block_max_arrival_index()
        .map_err(error)?;
    drop(db);
    let mut conn = open(path, true)?;
    let tx = conn.transaction().map_err(error)?;
    tx.pragma_update(None, "defer_foreign_keys", true)
        .map_err(error)?;
    burn_sets(&tx, boundary)?;
    for (table, column) in [
        ("snapshots", "sortition_id"),
        ("leader_keys", "sortition_id"),
        ("block_commits", "sortition_id"),
        ("block_commit_parents", "block_commit_sortition_id"),
        ("snapshot_transition_ops", "sortition_id"),
        ("preprocessed_reward_sets", "sortition_id"),
        ("missed_commits", "intended_sortition_id"),
    ] {
        retain(&tx, table, column, "retained_sortitions")?;
    }
    for table in [
        "stack_stx",
        "transfer_stx",
        "delegate_stx",
        "vote_for_aggregate_key",
    ] {
        retain(&tx, table, "burn_header_hash", "retained_burn")?;
    }
    let has_test_table: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'snapshot_burn_distributions')",
            [],
            |r| r.get(0),
        )
        .map_err(error)?;
    if has_test_table {
        tx.execute("DELETE FROM snapshot_burn_distributions", [])
            .map_err(error)?;
    }
    tx.execute_batch("DELETE FROM stacks_chain_tips; DELETE FROM stacks_chain_tips_by_burn_view;")
        .map_err(error)?;
    let headers: HashMap<_, _> = boundary
        .stacks_blocks
        .iter()
        .map(|h| ((&h.consensus_hash, h.anchored_header.block_hash()), h))
        .collect();
    let genesis = boundary
        .stacks_blocks
        .last()
        .ok_or("Missing genesis header")?;
    let mut epoch2 = boundary
        .stacks_blocks
        .iter()
        .rev()
        .filter(|h| matches!(h.anchored_header, StacksBlockHeaderTypes::Epoch2(_)))
        .peekable();
    let mut best = genesis;
    let mut arrival_carrier = None;
    for snapshot in boundary.sortitions.iter().rev() {
        let accepted = headers
            .get(&(
                &snapshot.consensus_hash,
                snapshot.winning_stacks_block_hash.clone(),
            ))
            .filter(|h| matches!(h.anchored_header, StacksBlockHeaderTypes::Epoch2(_)));
        if let Some(header) = accepted {
            if arrival_carrier
                .as_ref()
                .map_or(true, |(_, height)| header.stacks_block_height > *height)
            {
                arrival_carrier = Some((&snapshot.sortition_id, header.stacks_block_height));
            }
        }
        while epoch2
            .peek()
            .is_some_and(|h| u64::from(h.burn_header_height) <= snapshot.block_height)
        {
            best = epoch2.next().ok_or("Missing epoch-2 ancestor")?;
        }
        tx.prepare_cached("UPDATE snapshots SET stacks_block_accepted=?1, stacks_block_height=?2, arrival_index=?3, canonical_stacks_tip_height=?4, canonical_stacks_tip_hash=?5, canonical_stacks_tip_consensus_hash=?6 WHERE sortition_id=?7")
            .map_err(error)?
            .execute(params![
                accepted.is_some(),
                accepted.map_or(0, |h| h.stacks_block_height),
                if accepted.is_some() { snapshot.arrival_index } else { 0 },
                best.stacks_block_height,
                best.anchored_header.block_hash(),
                best.consensus_hash,
                snapshot.sortition_id,
            ])
            .map_err(error)?;
    }
    // SQL allocates the next arrival from MAX(arrival_index), whereas retained
    // immutable roots begin scanning at their committed watermark. Keep that
    // sequence above every retained root without rewriting any MARF commitment.
    if let Some((id, _)) = arrival_carrier {
        tx.execute("UPDATE snapshots SET arrival_index=?1 WHERE sortition_id=?2 AND ?1 > (SELECT MAX(arrival_index) FROM snapshots)", params![arrival_watermark, id]).map_err(error)?;
    } else {
        // A genesis-only recovery has no accepted epoch-2 arrival to carry a
        // sequence. Its initial root has no watermark (the reader defaults to 1).
        // Do not silently continue if the retained history violates this case.
        if arrival_watermark > 1 {
            return Err("Retained arrival watermark has no accepted epoch-2 snapshot".into());
        }
    }
    let snapshots: HashMap<_, _> = boundary
        .sortitions
        .iter()
        .map(|s| (&s.consensus_hash, s))
        .collect();
    for header in boundary.stacks_blocks.iter().rev() {
        let view = header.burn_view.as_ref().unwrap_or(&header.consensus_hash);
        let snapshot = snapshots
            .get(&view)
            .ok_or("Missing retained memo burn view")?;
        let election = snapshots
            .get(&header.consensus_hash)
            .ok_or("Missing retained memo election")?;
        let hash = header.anchored_header.block_hash();
        tx.prepare_cached("INSERT OR REPLACE INTO stacks_chain_tips VALUES (?1,?2,?3,?4)")
            .map_err(error)?
            .execute(params![
                election.sortition_id,
                header.consensus_hash,
                hash,
                header.stacks_block_height
            ])
            .map_err(error)?;
        tx.prepare_cached(
            "INSERT OR REPLACE INTO stacks_chain_tips_by_burn_view VALUES (?1,?2,?3,?4,?5)",
        )
        .map_err(error)?
        .execute(params![
            snapshot.sortition_id,
            header.consensus_hash,
            view,
            hash,
            header.stacks_block_height
        ])
        .map_err(error)?;
    }
    tx.commit().map_err(error)
}

fn rewind_block_files(directory: &Path, retained: &HashSet<StacksBlockId>) -> Result<(), String> {
    for first in std::fs::read_dir(directory).map_err(error)? {
        let first = first.map_err(error)?;
        if !first.file_type().map_err(error)?.is_dir() {
            continue;
        }
        for second in std::fs::read_dir(first.path()).map_err(error)? {
            let second = second.map_err(error)?;
            for block in std::fs::read_dir(second.path()).map_err(error)? {
                let path = block.map_err(error)?.path();
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("Invalid block filename")?;
                let id = StacksBlockId::from_hex(name).map_err(error)?;
                if path != directory.join(StacksChainState::index_block_hash_to_rel_path(&id)) {
                    return Err(format!("Unexpected block path {}", path.display()));
                }
                if !retained.contains(&id) {
                    std::fs::remove_file(&path).map_err(error)?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn rewind(
    network_dir: &Path,
    boundary: &RecoveryBoundary,
    config: &Config,
) -> Result<(), String> {
    let conn = open(&network_dir.join(SORTITION), false)?;
    check_epochs(&conn, boundary, config)?;
    drop(conn);
    let ids = retained_blocks(boundary);
    retain_roots(&network_dir.join(INDEX), &ids).map_err(error)?;
    retain_roots(&network_dir.join(CLARITY), &ids).map_err(error)?;
    let sortition_ids: HashSet<SortitionId> = boundary
        .sortitions
        .iter()
        .map(|s| s.sortition_id.clone())
        .collect();
    retain_roots(&network_dir.join(SORTITION), &sortition_ids).map_err(error)?;
    rewind_index(&network_dir.join(INDEX), boundary, config)?;
    {
        let mut conn = open(&network_dir.join(CLARITY), true)?;
        snapshot::clarity::assert_source_tables_classified(&conn).map_err(error)?;
        let tx = conn.transaction().map_err(error)?;
        block_set(&tx, boundary)?;
        retain(&tx, "metadata_table", "blockhash", "retained_blocks")?;
        tx.commit().map_err(error)?;
    }
    {
        let mut conn = open(&network_dir.join(NAKAMOTO), true)?;
        snapshot::blocks::assert_source_tables_classified(&conn).map_err(error)?;
        let tx = conn.transaction().map_err(error)?;
        block_set(&tx, boundary)?;
        retain(
            &tx,
            "nakamoto_staging_blocks",
            "index_block_hash",
            "retained_blocks",
        )?;
        tx.execute(
            "UPDATE nakamoto_staging_blocks SET processed = 1, orphaned = 0",
            [],
        )
        .map_err(error)?;
        tx.commit().map_err(error)?;
    }
    rewind_block_files(&network_dir.join("chainstate/blocks"), &ids)?;
    rewind_sortitions(&network_dir.join(SORTITION), boundary, config)?;
    {
        let mut conn = open(&network_dir.join(BURNCHAIN), true)?;
        snapshot::burnchain::assert_source_tables_classified(&conn).map_err(error)?;
        let tx = conn.transaction().map_err(error)?;
        tx.pragma_update(None, "defer_foreign_keys", true)
            .map_err(error)?;
        burn_sets(&tx, boundary)?;
        retain(
            &tx,
            "burnchain_db_block_headers",
            "block_hash",
            "retained_burn",
        )?;
        retain(&tx, "burnchain_db_block_ops", "block_hash", "retained_burn")?;
        retain(
            &tx,
            "block_commit_metadata",
            "burn_block_hash",
            "retained_burn",
        )?;
        tx.execute_batch("DELETE FROM anchor_blocks WHERE reward_cycle NOT IN (SELECT anchor_block FROM block_commit_metadata WHERE anchor_block IS NOT NULL); DELETE FROM overrides;").map_err(error)?;
        tx.commit().map_err(error)?;
    }
    {
        let mut conn = open(&network_dir.join(SPV), true)?;
        snapshot::spv::assert_source_tables_classified(&conn).map_err(error)?;
        let tx = conn.transaction().map_err(error)?;
        tx.execute(
            "DELETE FROM headers WHERE height > ?1",
            [boundary.burn_tip.block_height],
        )
        .map_err(error)?;
        tx.execute(
            "DELETE FROM chain_work WHERE interval >= ?1",
            [num_complete_chain_work_intervals(
                boundary.burn_tip.block_height,
            )],
        )
        .map_err(error)?;
        tx.commit().map_err(error)?;
    }
    let first = boundary
        .sortitions
        .last()
        .ok_or("Missing first sortition")?;
    let burnchain = config.get_burnchain();
    SortitionDB::connect(
        network_dir
            .join("burnchain/sortition")
            .to_str()
            .ok_or("Non-UTF8 sortition path")?,
        first.block_height,
        &first.burn_header_hash,
        first.burn_header_timestamp,
        &config.burnchain.get_epoch_list(),
        burnchain.pox_constants,
        None,
        true,
        Some(config.node.get_marf_opts()),
    )
    .map_err(error)?;
    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
