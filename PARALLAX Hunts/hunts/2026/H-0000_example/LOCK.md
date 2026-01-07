---
hunt_id: H-0000_example
title: "RCE-style anomaly baseline via process + network telemetry"
status: in_progress          # draft | in_progress | completed | retired
owner: "Apramey 'Apps' Shurpali"
created: 2025-12-26
last_updated: 2025-12-26

lock_level_authorized:
  manual: [L1, L2]
  agent:  [L3, L4]

environment:
  siem: "Cortex XSIAM"
  query_language: "XQL"
  platforms: ["windows","linux"]

telemetry_sources:
  - process_execution
  - network_connection
  - file_metadata
  - signature_status

timebox:
  lookback: "30d"
  timezone: "America/New_York"

tags: ["anomaly", "rce", "xsiam", "notebook", "baseline"]
---

# LOCK Hunt — RCE-style anomaly sweep

## L — Learn

### Why this hunt exists
Recent hunts and external writeups show RCE activity often blends in as:
- short-lived scripting chains
- odd parent-child execution
- rapid outbound connections to low-prevalence destinations

Traditional signature hunting underperforms here. Anomaly-based baselining is better suited.

### Prior knowledge
- Command-line rarity and robust z-scoring (MAD) have proven effective.
- RCE chains often pivot through:
  - `w3wp.exe`
  - `java.exe`
  - `rundll32.exe`
  - scripting hosts

### Known constraints
- DNS visibility incomplete for some sites
- Module load telemetry not guaranteed on all endpoints
- Some IT automation looks “weird” but is benign

---

## O — Observe

### Hypothesis
RCE activity will surface as **high-deviation process executions** with at least one of:
- rare command-line structure
- uncommon parent-child relationships
- low-prevalence binary hashes
- short time-to-network behavior with rare destinations

### Supporting evidence would include
- High anomaly_score from robust z (MAD)
- Unsigned or weakly signed binaries
- Execution from user-writable or web-root paths
- Rare (process_sha256, dest_domain) pairings

### Refuting evidence
- Strong signer + known vendor
- High historical prevalence
- Clear IT or patching lineage

---

## C — Check

### Check 1 — Primary anomaly notebook run

**Execution artifact**
- type: Jupyter Notebook
- path: `hunter/notebooks/rce_anomaly_v3.ipynb`

**Purpose**
Generate ranked anomaly candidates using robust statistics and rarity scoring across process + network telemetry.

---

### Data input

**XQL source**
- query: `hunter/queries/xsiam/process_network_baseline_30d.xql`

**Expected fields**
- agent_hostname
- action_process_image_name
- action_process_image_path
- action_process_image_sha256
- action_process_image_command_line
- actor_process_image_name
- action_file_signature_status
- action_process_signature_vendor
- dest_domain
- dest_ip
- event_timestamp

---

### Notebook parameters (approved + bounded)

```yaml
timeframe_days: 30
z_method: robust_mad
mad_threshold: 3.5
rarity_scope: env_wide
features:
  - cmd_len
  - token_count
  - cmd_rarity
  - parent_child_rarity
  - sha256_prevalence
winsorize: true
winsor_limits: [0.01, 0.99]
max_rows: 1000000
