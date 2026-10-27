# stacks-inspect

A multifunction inspection CLI for Stacks chain data and networking.

## Build

```bash
cargo build -p stacks-inspect
```

## Global Options

```
--config <CONFIG_FILE>       Path to stacks-node configuration file
--network-config <NETWORK>   Use a predefined network (mainnet, xenon)
--version                    Show version information
--help                       Show help
```

## Commands

### Offline chainstate recovery

```bash
stacks-inspect --config node.toml rollback-chainstate \
  --source /snapshot/mainnet --to-block <64-hex-block-id> \
  --output /recovery/new-working-dir [--replay-to <successor-block-id>]

stacks-inspect --config node.toml verify-chainstate --source /snapshot/mainnet

stacks-inspect --config node.toml verify-chainstate \
  --source /snapshot/mainnet --at-block <64-hex-block-id> \
  --replay-to <successor-block-id>
```

`--source` is the **network directory**, containing `chainstate/`,
`burnchain/`, and `headers.sqlite`, not the node working directory above it.
`--output` names a **new working directory**; its parent must already exist.
For example, with mainnet configuration, recovered files are placed at
`/recovery/new-working-dir/mainnet/`. Point the normal node's `working_dir` at
`/recovery/new-working-dir`, not its `mainnet` child.

Explicit `--config` or `--network-config` selection is required. Use the intended
node binary's actual network, PoX, and epoch configuration. To recover from a
missed hard fork, select a boundary **before** the first divergent burn block;
changing the epoch schedule does not repair already-evaluated consensus results.
The tool does not downgrade persisted schemas to impersonate an older binary.
Unsupported schemas, missing required history, and targets below a required
MARF history floor are errors, not permission to choose a different target.

**Stop the source node first, or use a coherent filesystem snapshot.**
Live copying is unsupported. An `lsof` check rejects detected open files when
available, and file-size/modification-time checks detect some changes during
copying. Neither is cross-process locking or proof of a coherent snapshot.
The operator must keep the source frozen for the entire operation, including
optional replay. All database opens, recovery, and writes take place on private
copies; the acquisition layer only reads source files.

Acquisition copies independent bytes for the Clarity/index stores under
`chainstate/vm/`, block payloads and Nakamoto staging under `chainstate/blocks/`,
the sortition store, `burnchain/burnchain.sqlite`, and `headers.sqlite`, including
their WAL, journal, shared-memory, and blob companions when present.
Unclassified files within consensus-store directories are rejected. Mempool,
peer, fee-estimator, Atlas, StackerDB, and signer-local state are not copied.
Signer safety databases and external consumers are **not rewound or reset**.
Normal startup is responsible for creating its optional local stores.

The command reports artifact bytes and available destination space before
copying. Allow room for a full independent copy, SQLite recovery and writes;
optional replay requires a second disposable copy. Verification-only copies
use the system temporary directory. There are no hard-link shortcuts or
automatic downloads.

Storage-only success explicitly reports **“Progression: not tested.”**
`--at-block` checks a projected recovered prefix; it does not establish that the
source's current tips were consistent. `--replay-to` requires an explicit
`--at-block` for verification and must have every required successor payload
and burnchain input available in the frozen source. Requested replay runs on a
second disposable copy, must commit through the exact endpoint and reopen
successfully, and gates rollback publication. The published candidate remains
at `--to-block`, not the replay endpoint. Missing inputs or any requested check
failure return nonzero. Neither storage consistency nor a finite replay range
authenticates a snapshot or guarantees future live-network liveness.

On Linux and macOS, publication checkpoints SQLite, flushes candidate files and
directories, then uses a same-filesystem atomic **no-clobber** directory rename.
Existing destinations, source/output nesting, symlink paths, and symlink
artifacts are rejected. The output is never an automatic replacement for an
active node directory. Ordinary failures remove unpublished copies; abrupt
termination can leave clearly named `.stacks-recovery-partial-*` directories,
which are not resumable outputs. Remove such abandoned copies only after
confirming that no recovery process is using them. Atomic publication on other
platforms is unsupported.

Catch-up can emit duplicate events. Coordinate indexer/event-consumer recovery
separately and preserve signer safety state according to its own operational
requirements. A successful offline check is not a claim that an actual node
restart and live catch-up have already been exercised.

The bitcoind-backed recovery regression uses the test coinbase-maturity rules.
Build its CLI with `cargo build -p stacks-inspect --features stackslib/testing`,
then run `BITCOIND_TEST=1 cargo test -p stacks-node follower_chainstate_cli_recovery -- --ignored`
with `bitcoind` on `PATH`. Do not use that test-feature binary for production recovery.

### Decode Commands

Decode and inspect Bitcoin/Stacks primitives.

```
decode-bitcoin-header <BLOCK_HEIGHT> <HEADERS_PATH> [-t|--testnet] [-r|--regtest]
    Decode a Bitcoin block header from SPV data

decode-tx <TX_HEX> [--file]
    Decode and print a Stacks transaction
    Use --file to read from file path (use "-" for stdin)

decode-block <BLOCK_PATH>
    Decode and print a Stacks block (epoch 2.x)
    Use "-" for stdin

decode-nakamoto-block <BLOCK_HEX> [--file]
    Decode and print a Nakamoto block
    Use --file to read from file path (use "-" for stdin)

decode-net-message <MESSAGE_DATA> [--file]
    Decode and print a Stacks network message
    Input is JSON byte array; use --file to read from file (use "-" for stdin)

decode-microblocks <MICROBLOCKS_PATH>
    Decode and print a microblock stream
    Use "-" for stdin
```

### MARF/Database Commands

Query and inspect MARF and Clarity databases.

```
header-indexed-get <BLOCK_ID_HASH> <KEY> [--state-dir <DIR> | --marf-path <PATH> --data-db-path <PATH>]
    Query header-indexed MARF data
    Provide --state-dir to auto-derive paths, or both --marf-path and --data-db-path

marf-get <MARF_PATH> <TIP_HASH> <CONSENSUS_HASH> <KEY>
    Get a value from the MARF database

deserialize-db <DB_PATH> <BYTE_PREFIX>
    Deserialize values from Clarity database filtered by byte prefix

check-deser-data <CHECK_FILE>
    Verify deserialized data from file

get-ancestors <DB_PATH> <BLOCK_HASH> <CONSENSUS_HASH>
    Trace block ancestry through staging database
```

### Nakamoto Commands

Nakamoto-specific chain inspection and peer queries.

```
get-nakamoto-tip <CHAINSTATE_DIR> <NETWORK>
    Get the Nakamoto chain tip

get-account <CHAINSTATE_DIR> <NETWORK> <ADDRESS> [CHAIN_TIP]
    Get account state at a chain tip

getnakamotoinv <PEER_ADDR> <DATA_PORT> <CONSENSUS_HASH>
    Get Nakamoto inventory from a peer
    PEER_ADDR format: HOST:PORT
```

### Mining Commands

Mining simulation and replay tools.

```
try-mine <CHAINSTATE_PATH> [--min-fee <FEE>] [--max-time <MS>]
    Simulate mining an anchored block

tip-mine <WORKING_DIR> <EVENT_LOG> <MINE_TIP_HEIGHT> <MAX_TXNS>
    Mine a block at tip height using event log

replay-mock-mining <CHAINSTATE_PATH> <MOCK_MINING_OUTPUT_PATH>
    Replay mock-mined blocks from JSON files
```

### Validation Commands

Block validation and integrity checks.

```
validate-block <DATABASE_PATH> [--early-exit] [--ignore-costs] [MODE]
    Validate Stacks blocks (Epoch2 and Nakamoto) from chainstate database
    --early-exit: Stop on first error (default: collect all errors)
    --ignore-costs: Don't fail a block whose only mismatch is its execution cost.
        The mismatch is logged and the block counts as valid.

    MODE options:
      prefix <HASH_PREFIX>           Validate blocks matching hash prefix
      last <COUNT>                   Validate last N blocks by height
      range <START> <END>            Validate blocks in height range (inclusive)
      index-range [START] [END]      Validate Epoch2 blocks by index (omit args to show count)
      naka-index-range [START] [END] Validate Nakamoto blocks by index (omit args to show count)
```

### Chain State Commands

Chain state queries and replay.

```
get-tenure <CHAIN_STATE_DIR> <BLOCK_HASH>
    Get block tenure information

get-block-inventory <WORKING_DIR>
    Get block inventory (2100 headers)

can-download-microblock <WORKING_DIR>
    Check if microblocks can be downloaded

replay-chainstate <OLD_CHAINSTATE> <OLD_SORTITION> <OLD_BURNCHAIN> <NEW_CHAINSTATE> <NEW_BURNCHAIN>
    Replay chainstate from old to new database
```

### PoX/Sortition Commands

PoX anchor evaluation and sortition analysis.

```
evaluate-pox-anchor <SORTITION_DB_PATH> <START_HEIGHT> [END_HEIGHT]
    Evaluate PoX anchor selection at a block height
    END_HEIGHT defaults to START_HEIGHT if omitted

analyze-sortition-mev <BURNCHAIN_DB> <SORTITION_DB> <CHAINSTATE> <START> <END> [MINER BURN...]
    Analyze sortition MEV across epochs
    MINER BURN pairs specify miner advantages
```

### Utility Commands

General utilities and documentation generation.

```
peer-pub-key <LOCAL_PEER_SEED>
    Generate peer public key from seed (hex)

post-stackerdb <SLOT_ID> <SLOT_VERSION> <PRIVATE_KEY> <DATA>
    Create a signed StackerDB chunk
    DATA: raw string, file path, or "-" for stdin

contract-hash <CONTRACT_SOURCE>
    Compute contract hash from source file (use "-" for stdin)

dump-consts
    Output blockchain constants as JSON

docgen
    Generate Clarity API reference as JSON

docgen-boot
    Generate boot contracts reference as JSON

exec-program <PROGRAM_FILE>
    Execute a Clarity program file
```

## Examples

```bash
# Show version
cargo run -p stacks-inspect -- --version

# Decode a Bitcoin header from SPV file
cargo run -p stacks-inspect -- decode-bitcoin-header 800000 /path/to/headers.dat

# Decode a transaction from hex
cargo run -p stacks-inspect -- decode-tx 0x00000001...

# Decode a transaction from file
cargo run -p stacks-inspect -- decode-tx --file /path/to/tx.hex

# Get account balance at current tip
cargo run -p stacks-inspect -- get-account /path/to/chainstate mainnet SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7

# Validate last 100 blocks
cargo run -p stacks-inspect -- validate-block /path/to/chainstate last 100

# Analyze sortition MEV behavior
cargo run -p stacks-inspect -- analyze-sortition-mev /path/to/burnchain.db /path/to/sortition.db /path/to/chainstate 800000 800100

# Generate Clarity API docs
cargo run -p stacks-inspect -- docgen > clarity-api.json
```

## Notes

- Some commands expect mainnet data paths by default and may require specific network contexts.
- Operations that write data are destructive—use copies of data directories when experimenting.
- Use `--help` on any command for detailed argument information: `cargo run -p stacks-inspect -- <command> --help`
