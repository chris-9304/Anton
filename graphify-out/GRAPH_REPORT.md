# Graph Report - /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft  (2026-04-19)

## Corpus Check
- 21 files · ~11,179 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 181 nodes · 328 edges · 12 communities detected
- Extraction: 69% EXTRACTED · 31% INFERRED · 0% AMBIGUOUS · INFERRED: 101 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]

## God Nodes (most connected - your core abstractions)
1. `run_watcher_with_callback()` - 18 edges
2. `run_desktop()` - 16 edges
3. `run_desktop()` - 13 edges
4. `CryptoEngine` - 12 edges
5. `run_demo()` - 12 edges
6. `run_cli()` - 10 edges
7. `FrequencyAnalyzer` - 9 edges
8. `RecoveryEngine` - 8 edges
9. `main()` - 7 edges
10. `AiEngine` - 6 edges

## Surprising Connections (you probably didn't know these)
- `file_event_to_op()` --calls--> `event_type_to_file_op()`  [INFERRED]
  /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/detectors.rs → /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/behavior_engine.rs
- `run_watcher_with_callback()` --calls--> `log_detection()`  [INFERRED]
  /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/watcher.rs → /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/demo_log.rs
- `run_watcher_with_callback()` --calls--> `log_remediation()`  [INFERRED]
  /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/watcher.rs → /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/demo_log.rs
- `run_demo()` --calls--> `demo_log_path()`  [INFERRED]
  /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/main.rs → /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/demo_log.rs
- `run_demo()` --calls--> `close_and_flush()`  [INFERRED]
  /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/main.rs → /mnt/c/Users/CJ/Desktop/Projects/dev/wsl/Code Craft/src/demo_log.rs

## Communities

### Community 0 - "Community 0"
Cohesion: 0.08
Nodes (7): AiEngine, EntropyAnalyzer, ExtensionAnalyzer, file_event_to_op(), FrequencyAnalyzer, NetworkAnalyzer, on_file_event()

### Community 1 - "Community 1"
Cohesion: 0.1
Nodes (7): CryptoEngine, RaptorQEncoder, append_log_file(), is_sandbox_path(), main(), run_sandboxed(), RecoveryEngine

### Community 2 - "Community 2"
Cohesion: 0.14
Nodes (13): main(), CanaryManager, AnalysisConfig, DetectionResult, DetectionSignals, EventType, FileEvent, ScanRecord (+5 more)

### Community 3 - "Community 3"
Cohesion: 0.13
Nodes (6): AiToggleRequest, AppState, full_scan(), MonitoringToggleRequest, quick_scan(), BehaviorAnalyzer

### Community 4 - "Community 4"
Cohesion: 0.21
Nodes (6): ActivityEntry, BehaviorEngine, event_type_to_file_op(), FamilyScore, FileOp, ProcessFamily

### Community 5 - "Community 5"
Cohesion: 0.21
Nodes (8): AppSettings, load_protected_folders(), main(), protected_folders_path(), push_activity(), run_desktop(), save_protected_folders(), main()

### Community 6 - "Community 6"
Cohesion: 0.22
Nodes (7): Config, load_protected_folders(), protected_folders_path(), push_activity(), run_desktop(), save_protected_folders(), check_file_suspicious()

### Community 7 - "Community 7"
Cohesion: 0.29
Nodes (8): close_and_flush(), demo_log_path(), DemoLogger, log_detection(), log_phase(), log_ransomware_action(), log_remediation(), run_demo()

### Community 8 - "Community 8"
Cohesion: 0.35
Nodes (11): run_cli(), backup_test_run(), cleanup_and_reset_after_ransomware(), copy_dir_all(), is_encrypted_ext(), reset_test_run_files(), revert_demo(), run_modern_ransomware_demo() (+3 more)

### Community 9 - "Community 9"
Cohesion: 0.44
Nodes (9): cleanup_sandbox(), run_cordyceps_mimic(), run_fast_rust_mimic(), run_self_test(), run_traverser_mimic(), sandbox_path(), schedule_cleanup_timeout(), SelfTestResult (+1 more)

### Community 10 - "Community 10"
Cohesion: 1.0
Nodes (0): 

### Community 11 - "Community 11"
Cohesion: 1.0
Nodes (0): 

## Knowledge Gaps
- **13 isolated node(s):** `AppState`, `AiToggleRequest`, `MonitoringToggleRequest`, `FileOp`, `ActivityEntry` (+8 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 10`** (2 nodes): `main()`, `build.rs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 11`** (1 nodes): `deploy_shortcut.ps1`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run_watcher_with_callback()` connect `Community 2` to `Community 0`, `Community 1`, `Community 5`, `Community 6`, `Community 7`, `Community 8`?**
  _High betweenness centrality (0.235) - this node is a cross-community bridge._
- **Why does `run_desktop()` connect `Community 5` to `Community 1`, `Community 2`, `Community 3`, `Community 6`, `Community 8`, `Community 9`?**
  _High betweenness centrality (0.138) - this node is a cross-community bridge._
- **Why does `main()` connect `Community 2` to `Community 1`, `Community 3`, `Community 6`?**
  _High betweenness centrality (0.106) - this node is a cross-community bridge._
- **Are the 15 inferred relationships involving `run_watcher_with_callback()` (e.g. with `main()` and `run_desktop()`) actually correct?**
  _`run_watcher_with_callback()` has 15 INFERRED edges - model-reasoned connections that need verification._
- **Are the 11 inferred relationships involving `run_desktop()` (e.g. with `.new()` and `.default()`) actually correct?**
  _`run_desktop()` has 11 INFERRED edges - model-reasoned connections that need verification._
- **Are the 9 inferred relationships involving `run_desktop()` (e.g. with `.new()` and `.default()`) actually correct?**
  _`run_desktop()` has 9 INFERRED edges - model-reasoned connections that need verification._
- **Are the 10 inferred relationships involving `run_demo()` (e.g. with `.for_test_run()` and `demo_log_path()`) actually correct?**
  _`run_demo()` has 10 INFERRED edges - model-reasoned connections that need verification._