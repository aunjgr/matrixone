# PR #30251 current-cutover qualification

Target MO: `ac6a9ec1ea234bca1ffabbaf59127536a7c5d978`.
Matched main: `17a6200f59e764729e5544908fffd5480ae88279`.
Native target: `06400cf48073e51955067bfd75c5c4defe955a72`.
SDK SHA-256: `878c0ec8b2d27f8efbac9325159903fb5ba87d5448692ab95938f10cb18077bc`.

This directory addresses the native/GPU and campaign-evidence review on
[PR #30251](https://github.com/matrixorigin/matrixone/pull/30251#discussion_r4280016763).
It is appended to the existing evidence branch. The older #30021 archives and
the production PR head remain unchanged.

## Replay

Download this entire directory at the immutable evidence commit linked from the
PR, then run:

```bash
python3 -B verify.py
```

The replay uses Python's standard library and needs no GPU, MatrixOne binary,
database, credentials, Nsight installation, or paths on the author's machine.
Allow at least 8 GiB of scratch space. `--scratch /path/to/free-space` selects
the temporary directory. Raw exports are reconstructed one profile at a time.

To download the directory without cloning the repository, retrieve
`tools/download.py` from the same immutable evidence commit and run:

```bash
python3 -B download.py --commit EVIDENCE_COMMIT_SHA --output cutover-30251
python3 -B cutover-30251/verify.py
```

The downloader retrieves only checksum-listed files at that exact commit and
verifies every file. `checksums.json` covers all published files except itself.
Profile archives are split into chunks of at most 32 MiB. The qualification
manifest records their order and complete-archive hashes.

## Evidence map

`cutover-core.tar.gz` contains these relative paths:

| Requirement | Evidence |
| --- | --- |
| Source/base, SDK, binaries and configuration | `provenance/`, `configuration/`, and frozen controller sources in `source/` |
| Ordinary build, UT, coverage, SCA and BVT | Exact-head successful CI job links in `provenance/pr-ci-snapshot.json` |
| Sirius-only/combined builds, Go bridge, public SQL and cuVS coexistence | `retained-logs/native-gpu-validation.log`, release build logs and individual binary build-information files |
| Matched all-22 SF1/SF10 streams 1/2/4 timing | `baseline-timing/` and `timing/`: 744 retained executions each, with complete records and distinct query IDs |
| Physical resource/shutdown proof | `resource/`, `allocations.json`, `profile-receipts/`, and the six external raw profile archives |
| Native lifecycle and result ownership | Ten cases in `lifecycle.json`, tied to fresh command receipts, logs and exact barrier source in `proof-sources/` |
| Writer failure and cancellation | Fresh exact-head public-runner race tests in `receipts/public-runner-race.*` |
| Native numeric regression | `numeric-baselines.json` and nine interleaved raw CSV command outputs in `receipts/numeric-*.log` |
| CUDA sanitizer controls | `sanitizer.json` and four raw sanitizer logs/receipts |
| Artifact-capture/replay negatives | Launcher, checksum/chunk/path, identity and incomplete-profile tests in `tools/` and `receipts/` |

## Captured, reused and newly executed

The 744 E timing executions and 744 main executions are retained byte for byte.
Their measured binaries differ by the intended cutover; their SDK, native
source, hardware, datasets, SQL, configuration, runner and toolchain match.
Each side is summarized using its recorded controller revision.

The original successful 264-run resource campaign is preserved under
`original-resource/`. Its controller removed successful raw profiling
workspaces. A new 264-run campaign on the same final binary, SDK, controller and
configuration supplies all six raw profiles in this directory. Old and new
observations are separate captures with their original query identities.

The evidence-only Nsight launcher forwards normal commands unchanged. After an
export succeeds and CN has stopped, it archives the complete `.nsys-rep`,
SQLite export and native log before returning to the unchanged controller.
Only then may normal phase cleanup delete the workspace. Export/archive
failure fails the phase. No archival work enters a timing measurement.

Retained Go bridge/public-SQL/coexistence logs use the explicitly identified
earlier E binary. The selected production and fixture sources are byte-identical
to the final head; `provenance/identity-audit.json` records this check. Final-head
combined execution also has its own binary identity and fresh resource capture.
Retained logs are labelled as logs, without invented historical command exits.

Native controls, sanitizer checks and numeric measurements have fresh receipts.
The retained native GPU executables were originally built at `0cc6e484`; the
native CPU-control executable was built at `b99fc7ae`. Full production native
source trees are identical to `06400cf4`; the CPU-control source and embedding
test trees are also identical. The sole `0cc6e484..06400cf4` change corrects a
CPU execution-statistics test fixture. Actual build revisions and binary hashes
remain recorded. Newly generated numeric cases qualify the production target
`06400cf4`; `candidate_build_revision` and executable identities retain the
original build revision. Historical native reports remain unchanged under
`historical-native/`.

An initial sanitizer preparation command used a nonexistent system executable
and exited 127. Its failure receipt remains present and is excluded from passing
proofs. The subsequent checks use the pinned Pixi Compute Sanitizer.

## Acceptance

The replay checks file/chunk hashes, reconstructs the six raw exports and uses
the frozen `sirius_resource` parser to recompute physical allocations, query
spans and shutdown state. It independently repeats host-pool reconciliation,
checks raw sanitizer counts and numeric CSV samples, then invokes the unchanged
current `sirius_acceptance.validate` function.

Limits remain: matched suite medians and summed query medians at most 1.05 of
main; native numeric controls at most 1.10; six complete resource profiles with
zero unexplained growth. Raw sanitizer status 99 remains 99, with the exact
matched CUB diagnostic and cuDF process-global pinned-pool controls preserved.
Additional errors/leaks cannot pass those reconciliations.

The resulting JSON is the reproducible local qualification verdict. Reviewer
approval remains external. No production runtime/API, collector fingerprint,
native dependency, performance limit or #30021 archive is changed here.
