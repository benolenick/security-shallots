# Threat Correlation Engine + ML - Design Document

**Status:** IMPLEMENTED AND DEPLOYED
**Date:** 2026-03-07 (designed) → 2026-03-08 (implemented + deployed)
**Deployed to:** host03 (192.168.0.224:8844)
**Footprint budget:** <1 GB RAM, no new containers, no new services

---

## Overview

Extend the existing correlator (`shallots/ai/correlator.py`) into a full behavioral threat intelligence engine. Three new modules, all running in-process as async tasks inside the existing daemon.

---

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │              daemon.py                       │
                    │                                              │
  alert_queue ──►   │  pipeline ──► store ──► [NEW] behavioral    │
                    │                              │               │
                    │  correlator ◄─────────────────┤               │
                    │      │                        │               │
                    │  [NEW] graph_engine ◄─────────┤               │
                    │      │                        │               │
                    │  [NEW] ml_detector ◄──────────┘               │
                    │      │                                       │
                    │  incidents ◄──── narrative (Ollama) ──►  UI  │
                    └──────────────────────────────────────────────┘
```

No new ports. No new processes. Everything hooks into the existing daemon lifecycle.

---

## Module 1: Behavioral Baselines (`shallots/ai/baselines.py`)

**What it does:** Learns what "normal" looks like for each device on your network, then flags deviations.

### Data Model

```python
@dataclass
class DeviceProfile:
    ip: str
    asset_name: str | None
    first_seen: str          # ISO timestamp
    last_seen: str
    # Behavioral stats (rolling 7-day windows)
    hourly_alert_counts: dict[int, float]    # hour_of_day → avg count
    common_dst_ports: dict[int, int]         # port → frequency
    common_dst_ips: set[str]                 # normal destinations
    common_categories: dict[str, int]        # alert category → count
    dns_domains: set[str]                    # domains this device queries
    protocols: dict[str, int]               # proto → count
    avg_daily_bytes_out: float              # if available from Suricata flow
    # Computed
    baseline_updated: str                    # last recalc timestamp
```

### Schema Addition

```sql
CREATE TABLE IF NOT EXISTS device_baselines (
    ip TEXT PRIMARY KEY,
    asset_name TEXT,
    first_seen TEXT,
    last_seen TEXT,
    profile_json TEXT,          -- serialized DeviceProfile
    baseline_updated TEXT,
    created_at TEXT,
    updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_baselines_updated ON device_baselines(baseline_updated);
```

### Behavior

- **Baseline rebuild:** Every 6 hours, query last 7 days of alerts grouped by src_ip. Compute rolling averages.
- **Deviation check:** Every correlation cycle (5 min), compare current window against baselines.
- **Anomaly flags** (injected as synthetic alerts or correlation metadata):
  - Device talking to a never-before-seen external IP
  - Device using a port it's never used before
  - Alert volume 3σ above device's hourly norm
  - New DNS domain for a device class (e.g., IoT camera querying .ru)
  - Protocol change (device that only does DNS suddenly doing HTTP)

### Footprint

- ~50-100 KB per device profile
- 100 devices = ~10 MB in SQLite
- In-memory cache of active profiles: ~5 MB
- Baseline rebuild: one SQL query every 6 hours

---

## Module 2: Network Graph Engine (`shallots/ai/graph_engine.py`)

**What it does:** Maintains a live graph of network relationships. Enables multi-hop pivot queries ("show me everything connected to this compromised host").

### Implementation

```python
import networkx as nx

class NetworkGraph:
    """In-memory directed graph of network entities and their relationships."""

    def __init__(self):
        self.G = nx.DiGraph()
        # Node types: 'device', 'external_ip', 'domain', 'port', 'signature'
        # Edge types: 'connects_to', 'resolves_to', 'triggers', 'scans'

    def ingest_alert(self, alert: dict) -> None:
        """Add/update graph from a single alert."""
        # Add src node (device or external)
        # Add dst node
        # Add edge with metadata (timestamp, alert_id, category)
        # Update edge weight (frequency)

    def rebuild_from_db(self, db: AlertDB, hours: int = 24) -> None:
        """Full rebuild from last N hours of alerts."""

    def pivot(self, entity: str, depth: int = 2) -> dict:
        """Return all entities within N hops of the given entity."""

    def find_paths(self, src: str, dst: str) -> list[list[str]]:
        """Find attack paths between two entities."""

    def detect_communities(self) -> list[set[str]]:
        """Find clusters of tightly-connected entities (potential campaigns)."""

    def score_entity(self, entity: str) -> float:
        """Risk score based on degree centrality, edge types, and reputation."""
```

### Graph Update Strategy

- **On each alert:** `ingest_alert()` - O(1) graph update
- **Every hour:** Prune edges older than 48h (configurable)
- **On demand:** `pivot()` for investigation console, `find_paths()` for kill chain detection

### Schema Addition

```sql
-- Persist graph state for restart recovery (rebuild is fast but this avoids cold start)
CREATE TABLE IF NOT EXISTS graph_edges (
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    weight INTEGER DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT,
    sample_alert_id TEXT,
    PRIMARY KEY (src, dst, edge_type)
);

CREATE INDEX IF NOT EXISTS idx_graph_src ON graph_edges(src);
CREATE INDEX IF NOT EXISTS idx_graph_dst ON graph_edges(dst);
```

### API Endpoints (add to `web/api.py`)

```
GET /api/graph/pivot?entity=192.168.0.50&depth=2
GET /api/graph/paths?src=192.168.0.50&dst=45.33.32.156
GET /api/graph/communities
GET /api/graph/entity-score?entity=192.168.0.50
GET /api/graph/stats
```

### Footprint

- NetworkX DiGraph: ~200 bytes per node, ~100 bytes per edge
- 500 nodes × 2000 edges = ~300 KB in memory
- SQLite persistence: negligible
- networkx is pure Python, ~10 MB installed

---

## Module 3: ML Anomaly Detector (`shallots/ai/ml_detector.py`)

**What it does:** Trains lightweight ML models on your alert history to detect anomalies that rules miss.

### Models (all scikit-learn, no GPU needed)

#### 1. Isolation Forest - Global Anomaly Detection
```python
from sklearn.ensemble import IsolationForest

class AlertAnomalyDetector:
    """Detects alerts that are statistically unusual compared to history."""

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,  # expect ~5% anomalies
            random_state=42,
        )
        self.feature_names: list[str] = []
        self.fitted = False

    def extract_features(self, alert: dict) -> np.ndarray:
        """Convert alert to feature vector."""
        # Features:
        # - hour_of_day (0-23, cyclical encoding: sin + cos)
        # - day_of_week (0-6, cyclical encoding)
        # - src_port (bucketed: ephemeral, well-known, registered)
        # - dst_port (bucketed)
        # - is_internal_src (0/1)
        # - is_internal_dst (0/1)
        # - severity_num (1-4)
        # - source_encoded (one-hot: suricata, wazuh, argus, etc.)
        # - category_hash (feature hashing, 8 buckets)
        # - alert_rate_src_ip_last_hour (from baselines)
        # - baseline_deviation_score (from Module 1)

    def train(self, alerts: list[dict]) -> None:
        """Train on last 7 days of alert history."""

    def predict(self, alert: dict) -> tuple[bool, float]:
        """Returns (is_anomaly, anomaly_score)."""
```

#### 2. Time-Series Anomaly - Alert Volume Spikes
```python
class VolumeAnomalyDetector:
    """Detects unusual spikes in alert volume per source."""

    # Simple approach: rolling mean + 3σ threshold
    # Per-source-IP and global
    # Checked every correlation cycle
    # No sklearn needed - just numpy
```

#### 3. Behavioral Clustering - Device Type Classification
```python
from sklearn.cluster import DBSCAN

class DeviceClassifier:
    """Groups devices by behavior to detect when one starts acting differently."""

    # Features per device (from baselines):
    # - top 5 dst_ports (frequency encoded)
    # - alert volume per hour pattern
    # - protocol mix
    # - DNS query diversity
    #
    # DBSCAN finds natural clusters (servers, workstations, IoT, phones)
    # When a device moves clusters → flag for investigation
```

### Training Schedule

| Model | Retrain Frequency | Training Data | Train Time (est.) |
|-------|-------------------|---------------|-------------------|
| Isolation Forest | Every 6 hours | Last 7 days alerts | ~2 sec (10K alerts) |
| Volume Anomaly | Continuous (rolling stats) | Last 24 hours | N/A (streaming) |
| Device Classifier | Daily | Last 7 days baselines | ~1 sec (100 devices) |

### Schema Addition

```sql
CREATE TABLE IF NOT EXISTS ml_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT REFERENCES alerts(id),
    model TEXT NOT NULL,           -- 'isolation_forest', 'volume_spike', 'device_drift'
    is_anomaly INTEGER DEFAULT 0,
    anomaly_score REAL,
    explanation TEXT,              -- human-readable reason
    created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ml_alert ON ml_predictions(alert_id);
CREATE INDEX IF NOT EXISTS idx_ml_model ON ml_predictions(model);

-- Model artifacts storage (pickled sklearn models)
CREATE TABLE IF NOT EXISTS ml_models (
    name TEXT PRIMARY KEY,
    version INTEGER DEFAULT 1,
    model_blob BLOB,              -- pickled model
    metadata_json TEXT,           -- training stats, feature names, accuracy
    trained_at TEXT,
    alert_count INTEGER           -- training set size
);
```

### Integration with Correlator

The ML detector doesn't replace the rule-based correlator - it supplements it:

```python
# In correlator._correlate():
async def _correlate(self):
    alerts = await self._fetch_recent_alerts()

    # Existing: rule-based grouping
    groups = _group_alerts(alerts)

    # NEW: ML anomaly scoring
    for alert in alerts:
        is_anomaly, score = self.ml_detector.predict(alert)
        if is_anomaly:
            alert['_ml_anomaly'] = True
            alert['_ml_score'] = score

    # NEW: Add anomaly clusters to groups
    anomalies = [a for a in alerts if a.get('_ml_anomaly')]
    if anomalies:
        groups['ml_anomaly:batch'] = anomalies

    # NEW: Baseline deviation check
    deviations = self.baselines.check_deviations(alerts)
    for dev in deviations:
        groups[f'baseline_deviation:{dev.ip}'] = dev.alerts

    # Existing: AI correlation or rule-based fallback
    # ... (unchanged)
```

### Footprint

- scikit-learn: ~30 MB installed
- numpy: already needed by sklearn
- Model in memory: ~5 MB (Isolation Forest with 100 trees on 10K samples)
- Prediction: <1ms per alert
- Training: ~2 sec every 6 hours
- **No GPU needed** - CPU-only sklearn

---

## Module 4: Kill Chain Detector (`shallots/ai/killchain.py`)

**What it does:** Detects multi-stage attacks by mapping alert sequences to the Cyber Kill Chain / MITRE ATT&CK.

### Kill Chain Stages

```python
KILL_CHAIN = {
    'reconnaissance':    {'patterns': ['port_scan', 'recon'], 'mitre': ['TA0043']},
    'weaponization':     {'patterns': [], 'mitre': ['TA0042']},  # rarely seen in network data
    'delivery':          {'patterns': ['phishing', 'malware_download'], 'mitre': ['TA0001']},
    'exploitation':      {'patterns': ['exploit_attempt'], 'mitre': ['TA0002']},
    'installation':      {'patterns': ['persistence_detected', 'malware'], 'mitre': ['TA0003']},
    'command_control':   {'patterns': ['c2_beacon', 'dns_tunnel'], 'mitre': ['TA0011']},
    'actions_on_obj':    {'patterns': ['data_exfil', 'lateral_movement', 'privilege_escalation'], 'mitre': ['TA0040']},
}

class KillChainDetector:
    """Detects multi-stage attacks by tracking progression through kill chain phases."""

    def __init__(self):
        self.active_chains: dict[str, KillChainTracker] = {}  # keyed by src_ip or campaign_id

    def evaluate(self, correlation: Correlation) -> KillChainMatch | None:
        """Check if a new correlation advances any active kill chain."""
        # If src_ip has prior correlations in earlier stages → advance chain
        # If chain reaches 3+ stages → generate critical incident

    def get_active_chains(self) -> list[dict]:
        """Return all active multi-stage attack progressions."""
```

### Footprint

- Pure Python, no new dependencies
- ~1 KB per active chain tracker
- Runs inside correlator cycle

---

## Narrative Generation (Enhancement to `ai/incidents.py`)

When the graph, baselines, or ML detector flag something interesting, generate a human-readable narrative using Ollama (already running):

```
"At 14:32, your security camera (192.168.0.45) made its first-ever DNS query
to update.sinkhole.ru - a domain not in its 30-day baseline. This happened
3 minutes after a port scan from 45.33.32.156 hit 23 ports on your network.
The camera has never communicated with any .ru domain before. This matches
stages 1 (reconnaissance) and 6 (C2) of a potential kill chain targeting
IoT devices."
```

### New Prompt Template (add to `prompts.py`)

```python
NARRATIVE_SYSTEM = """You are a security narrator for a home network operator.
You turn raw detection data into clear, contextual stories. Always reference:
- What happened (specific IPs, ports, times)
- Why it's unusual (baseline deviations, first-time behaviors)
- How confident you are (ML score, rule match, graph connections)
- What kill chain stage this represents (if applicable)
Keep it to 2-4 sentences. No jargon. Make it feel like a smart security camera
narrating what it sees."""

NARRATIVE_TEMPLATE = """Generate a threat narrative from this detection:

Detection type: {detection_type}
Entities involved: {entities_json}
Baseline context: {baseline_context}
Graph context: {graph_context}
ML anomaly score: {ml_score}
Kill chain stage: {killchain_stage}
Related alerts: {alerts_summary}

Write a clear, contextual narrative (2-4 sentences)."""
```

---

## Dashboard Integration

### New UI Components

1. **Network Graph Visualization** - Interactive D3.js force-directed graph
   - Nodes = devices/IPs, edges = connections
   - Color by risk score, size by alert volume
   - Click to pivot
   - Endpoint: `GET /api/graph/pivot`

2. **Device Baseline Cards** - Per-device profile showing:
   - Normal behavior summary
   - Current deviations (highlighted red)
   - Historical behavior sparklines
   - Endpoint: `GET /api/baselines/{ip}`

3. **Kill Chain Timeline** - Horizontal timeline showing attack progression
   - Each stage as a node, filled if detected
   - Click stage to see contributing alerts
   - Endpoint: `GET /api/killchain/active`

4. **ML Insights Panel** - Shows:
   - Recent anomalies with scores
   - Model health (last trained, accuracy, drift)
   - Top anomalous devices today
   - Endpoint: `GET /api/ml/anomalies`, `GET /api/ml/health`

---

## New API Endpoints Summary

```
# Baselines
GET  /api/baselines                   - all device profiles
GET  /api/baselines/{ip}              - single device profile
POST /api/baselines/rebuild           - force baseline rebuild

# Graph
GET  /api/graph/pivot                 - entity neighborhood
GET  /api/graph/paths                 - attack paths between entities
GET  /api/graph/communities           - entity clusters
GET  /api/graph/entity-score          - risk score
GET  /api/graph/stats                 - graph size/health

# ML
GET  /api/ml/anomalies                - recent ML-flagged anomalies
GET  /api/ml/health                   - model status and stats
POST /api/ml/retrain                  - force model retrain
GET  /api/ml/predictions/{alert_id}   - ML predictions for an alert

# Kill Chain
GET  /api/killchain/active            - active multi-stage progressions
GET  /api/killchain/history           - completed/dismissed chains
```

---

## Dependencies to Add

```
# requirements.txt additions
scikit-learn>=1.4       # ~30 MB - Isolation Forest, DBSCAN
networkx>=3.2           # ~10 MB - graph engine (pure Python)
# numpy comes with scikit-learn
```

No new system packages. No new containers. No GPU needed for ML (CPU sklearn).

---

## Implementation Order

### Phase 1 - Baselines (foundation for everything else)
1. Add `device_baselines` table to schema
2. Build `baselines.py` - DeviceProfile, baseline builder, deviation checker
3. Wire into daemon lifecycle (start/stop)
4. Add `/api/baselines` endpoints
5. Add baseline deviation injection into correlator

### Phase 2 - Network Graph
1. Add `graph_edges` table to schema
2. Build `graph_engine.py` - NetworkGraph with ingest, pivot, paths, communities
3. Hook `ingest_alert()` into pipeline (after store)
4. Add `/api/graph/*` endpoints
5. Build D3.js graph visualization in frontend

### Phase 3 - ML Anomaly Detection
1. Add `ml_predictions` and `ml_models` tables
2. Build `ml_detector.py` - IsolationForest, VolumeAnomaly, DeviceClassifier
3. Wire training schedule into daemon
4. Inject anomaly scores into correlator
5. Add `/api/ml/*` endpoints and UI panel

### Phase 4 - Kill Chain + Narratives
1. Build `killchain.py` - stage mapping, chain tracker
2. Add narrative prompt template
3. Wire kill chain into incident generation
4. Build timeline UI component
5. End-to-end test: simulate multi-stage attack

---

## Total Footprint Impact

| Component | RAM | Disk | CPU | GPU |
|-----------|-----|------|-----|-----|
| Baselines | ~5 MB | ~10 MB | negligible | none |
| Graph | ~1-5 MB | ~5 MB | negligible | none |
| ML Models | ~50 MB | ~30 MB (sklearn) | 2 sec/6hr train | none |
| Kill Chain | ~1 MB | negligible | negligible | none |
| Narratives | 0 (uses existing Ollama) | 0 | 0 | piggyback |
| **Total** | **~60 MB** | **~45 MB** | **trivial** | **none** |

Current stack footprint: ~2 GB RAM, 1.1 GB disk
After this: ~2.06 GB RAM, 1.15 GB disk
**< 3% increase.**

---

## Files to Create

```
shallots/ai/baselines.py      - Module 1: behavioral baselines
shallots/ai/graph_engine.py    - Module 2: network graph
shallots/ai/ml_detector.py     - Module 3: ML anomaly detection
shallots/ai/killchain.py       - Module 4: kill chain detector
shallots/web/static/js/graph.js - D3.js graph visualization
```

## Files to Modify

```
shallots/store/db.py           - new tables (device_baselines, graph_edges, ml_predictions, ml_models)
shallots/store/models.py       - new dataclasses (DeviceProfile, GraphEdge, MLPrediction)
shallots/daemon.py             - wire new modules into lifecycle
shallots/ai/correlator.py      - inject ML scores + baseline deviations
shallots/ai/prompts.py         - narrative template
shallots/ai/incidents.py       - kill chain integration
shallots/web/api.py            - new endpoints
shallots/web/static/index.html - new dashboard panels
shallots/config.py             - ML/graph config options
```

---

## Implementation Status (2026-03-08)

### Deployed and Running

| Module | File | Status | Notes |
|--------|------|--------|-------|
| Baselines | `shallots/ai/baselines.py` (404 lines) | ✅ Running | 22 device profiles rebuilt, 5 deviation types |
| Graph Engine | `shallots/ai/graph_engine.py` | ✅ Running | 32 nodes, 35 edges, full topology API |
| ML Detector | `shallots/ai/ml_detector.py` (634 lines) | ✅ Running | Isolation Forest trained (200 samples), sklearn 1.8.0 |
| Kill Chain | `shallots/ai/killchain.py` (339 lines) | ✅ Running | 7-stage tracking, MITRE ATT&CK mapping |
| Correlator fixes | `shallots/ai/correlator.py` | ✅ Running | Infra IP exclusion, raised thresholds, 2h dedup |
| Topology UI | `shallots/web/static/topology.html` (~924 lines) | ✅ Deployed | D3.js force graph, live WebSocket updates |
| ML Dashboard | `shallots/web/static/ml.html` (~766 lines) | ✅ Deployed | Anomaly scatter, clustering, kill chain viz |
| Test Pipeline | `POST /api/test-detection` | ✅ Deployed | 6-stage synthetic alert validation |

### Key Architecture Decisions

1. **Independent module startup**: Each threat engine module starts in its own try/except in `daemon.py`. One module failing doesn't kill the others.
2. **No GPU usage**: All ML runs on CPU (scikit-learn). The 2x RTX 3090s are reserved for future deep learning.
3. **In-process async**: No new containers or services. Everything runs as async tasks inside shallotd.
4. **DB schema additions**: Tables `device_baselines`, `graph_edges`, `ml_predictions`, `ml_models` created manually (no auto-migration yet).

### API Endpoints Added

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/topology` | GET | Yes | Full network graph (nodes + edges + risk scores) |
| `/api/ml/health` | GET | Yes | ML model training status |
| `/api/ml/anomalies` | GET | Yes | Isolation Forest anomalies |
| `/api/ml/retrain` | POST | Yes | Trigger model retraining |
| `/api/ml/clusters` | GET | Yes | DBSCAN device clusters |
| `/api/baselines` | GET | Yes | Per-device behavioral profiles |
| `/api/baselines/rebuild` | POST | Yes | Force baseline rebuild |
| `/api/baselines/deviations` | GET | Yes | Current behavioral deviations |
| `/api/killchain/active` | GET | Yes | Active kill chain progressions |
| `/api/test-detection` | POST | Yes | Synthetic pipeline health test |
| `/topology` | GET | Yes | Topology visualization page |
| `/ml` | GET | Yes | ML insights dashboard page |

### Correlator Fixes Applied

1. **Infrastructure IP exclusion**: Known IPs (pfSense, Security Onion, host03, etc.) excluded from lateral movement, port scan, C2, and brute force detection
2. **Threshold increases**: Beacon 4→12, brute force 5→15
3. **Lateral movement fix**: Removed broken `or external_srcs` condition, requires 10+ alerts from non-infra host
4. **2-hour deduplication**: Same correlation type+key won't fire twice within 2 hours

### Dependencies Installed on host03

```
scikit-learn==1.8.0 (in .venv)
numpy==2.4.2
scipy==1.17.1
joblib==1.5.3
threadpoolctl==3.6.0
```
