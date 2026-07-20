"""ML-based anomaly detection for Security Shallots.

Uses lightweight scikit-learn models trained on alert history to detect
anomalies that rule-based correlation misses. Falls back gracefully
if sklearn is not installed.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import math
import pickle
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.store.db import AlertDB
    from shallots.ai.baselines import BaselineEngine

from shallots.store.models import now_iso

log = logging.getLogger(__name__)

# Check for sklearn availability
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    log.warning("scikit-learn not installed - ML anomaly detection will use heuristic fallback")

_RETRAIN_INTERVAL_SEC = 6 * 3600  # 6 hours
_TRAINING_WINDOW_DAYS = 7
_CONTAMINATION = 0.05  # expect ~5% anomalies
_MIN_TRAINING_SAMPLES = 50


@dataclass
class MLPrediction:
    """Result of an ML anomaly prediction."""
    alert_id: str
    model: str          # isolation_forest, volume_spike, device_drift
    is_anomaly: bool
    anomaly_score: float  # 0.0-1.0 (1.0 = most anomalous)
    explanation: str
    created_at: str = ""


# ── Feature extraction ────────────────────────────────────────

# Known sources for one-hot encoding
_SOURCES = ["suricata", "wazuh", "argus", "crowdsec", "pfsense", "pihole", "syslog"]
_SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _extract_features(alert: dict[str, Any]) -> list[float]:
    """Convert an alert dict into a fixed-size feature vector."""
    features: list[float] = []

    # 1-2: Hour of day (cyclical encoding)
    ts = alert.get("timestamp") or ""
    hour = 12  # default
    day_of_week = 3
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        hour = dt.hour
        day_of_week = dt.weekday()
    except (ValueError, TypeError):
        pass
    features.append(math.sin(2 * math.pi * hour / 24))
    features.append(math.cos(2 * math.pi * hour / 24))

    # 3-4: Day of week (cyclical encoding)
    features.append(math.sin(2 * math.pi * day_of_week / 7))
    features.append(math.cos(2 * math.pi * day_of_week / 7))

    # 5: Destination port bucket (0=none, 1=well-known <1024, 2=registered 1024-49151, 3=ephemeral)
    dst_port = alert.get("dst_port") or 0
    if dst_port == 0:
        features.append(0)
    elif dst_port < 1024:
        features.append(1)
    elif dst_port < 49152:
        features.append(2)
    else:
        features.append(3)

    # 6: Source port bucket
    src_port = alert.get("src_port") or 0
    if src_port == 0:
        features.append(0)
    elif src_port < 1024:
        features.append(1)
    elif src_port < 49152:
        features.append(2)
    else:
        features.append(3)

    # 7: Is internal source (0/1)
    features.append(1.0 if _is_rfc1918(alert.get("src_ip", "")) else 0.0)

    # 8: Is internal destination (0/1)
    features.append(1.0 if _is_rfc1918(alert.get("dst_ip", "")) else 0.0)

    # 9: Severity as number
    features.append(_SEVERITIES.get(alert.get("severity", "medium"), 2))

    # 10-16: Source one-hot encoding
    source = alert.get("source", "")
    for s in _SOURCES:
        features.append(1.0 if source == s else 0.0)

    # 17-24: Category hash (feature hashing into 8 buckets)
    category = alert.get("category") or ""
    cat_hash = int(hashlib.md5(category.encode()).hexdigest(), 16) % 8
    for i in range(8):
        features.append(1.0 if cat_hash == i else 0.0)

    # 25: Signature ID bucketed (log scale)
    sig_id = alert.get("signature_id") or 0
    features.append(math.log1p(sig_id) / 15.0)  # normalize roughly

    return features


_FEATURE_COUNT = 25  # must match _extract_features output length


class AlertAnomalyDetector:
    """Isolation Forest model for detecting unusual alerts."""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.fitted = False
        self.training_count = 0
        self.trained_at = ""

    def train(self, alerts: list[dict[str, Any]]) -> bool:
        """Train on alert history. Returns True if successful."""
        if not HAS_SKLEARN:
            return False
        if len(alerts) < _MIN_TRAINING_SAMPLES:
            log.info("ML: not enough samples to train (%d < %d)", len(alerts), _MIN_TRAINING_SAMPLES)
            return False

        features = []
        for alert in alerts:
            try:
                f = _extract_features(alert)
                features.append(f)
            except Exception:
                continue

        if len(features) < _MIN_TRAINING_SAMPLES:
            return False

        X = np.array(features, dtype=np.float64)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=_CONTAMINATION,
            random_state=42,
            n_jobs=1,  # single-threaded to keep CPU impact low
        )
        self.model.fit(X_scaled)
        self.fitted = True
        self.training_count = len(features)
        self.trained_at = now_iso()

        log.info("ML: Isolation Forest trained on %d alerts", len(features))
        return True

    def predict(self, alert: dict[str, Any]) -> MLPrediction:
        """Predict whether an alert is anomalous."""
        alert_id = alert.get("id", "")

        if not self.fitted or not HAS_SKLEARN:
            return MLPrediction(
                alert_id=alert_id, model="isolation_forest",
                is_anomaly=False, anomaly_score=0.0,
                explanation="Model not trained", created_at=now_iso(),
            )

        try:
            features = _extract_features(alert)
            X = np.array([features], dtype=np.float64)
            X_scaled = self.scaler.transform(X)

            # score_samples returns negative values; more negative = more anomalous
            raw_score = self.model.score_samples(X_scaled)[0]
            prediction = self.model.predict(X_scaled)[0]  # 1 = normal, -1 = anomaly

            # Normalize score to 0-1 range (higher = more anomalous)
            # Typical range is roughly -0.5 to 0.0
            anomaly_score = max(0.0, min(1.0, -raw_score * 2))

            is_anomaly = prediction == -1

            explanation = ""
            if is_anomaly:
                explanation = self._explain(alert, anomaly_score)

            return MLPrediction(
                alert_id=alert_id, model="isolation_forest",
                is_anomaly=is_anomaly, anomaly_score=round(anomaly_score, 3),
                explanation=explanation, created_at=now_iso(),
            )
        except Exception as e:
            log.debug("ML: prediction failed for alert %s: %s", alert_id, e)
            return MLPrediction(
                alert_id=alert_id, model="isolation_forest",
                is_anomaly=False, anomaly_score=0.0,
                explanation=f"Prediction error: {e}", created_at=now_iso(),
            )

    def _explain(self, alert: dict, score: float) -> str:
        """Generate a simple explanation for why this alert is anomalous."""
        parts = []
        ts = alert.get("timestamp") or ""
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.hour < 5 or dt.hour > 23:
                parts.append(f"unusual time ({dt.hour}:00)")
        except (ValueError, TypeError):
            pass

        severity = alert.get("severity", "medium")
        if severity in ("high", "critical"):
            parts.append(f"{severity} severity")

        src = alert.get("src_ip", "")
        dst = alert.get("dst_ip", "")
        if src and not _is_rfc1918(src) and dst and _is_rfc1918(dst):
            parts.append("external→internal")

        if not parts:
            parts.append(f"statistical outlier (score={score:.2f})")

        return "ML anomaly: " + ", ".join(parts)

    def serialize(self) -> bytes | None:
        """Serialize model to bytes for DB storage."""
        if not self.fitted or not HAS_SKLEARN:
            return None
        buf = io.BytesIO()
        pickle.dump({"model": self.model, "scaler": self.scaler}, buf)
        return buf.getvalue()

    def deserialize(self, data: bytes) -> bool:
        """Load model from bytes."""
        if not HAS_SKLEARN:
            return False
        try:
            buf = io.BytesIO(data)
            state = pickle.load(buf)
            self.model = state["model"]
            self.scaler = state["scaler"]
            self.fitted = True
            return True
        except Exception as e:
            log.warning("ML: failed to deserialize model: %s", e)
            return False


class DeviceClassifier:
    """Clusters devices by behavioral patterns to detect when one changes class."""

    def __init__(self):
        self.labels: dict[str, int] = {}  # ip → cluster label
        self.fitted = False
        self.trained_at = ""

    def train(self, profiles: dict[str, Any]) -> bool:
        """Train DBSCAN on device profiles from BaselineEngine."""
        if not HAS_SKLEARN or len(profiles) < 5:
            return False

        ips = []
        features = []

        for ip, profile in profiles.items():
            try:
                f = self._profile_features(profile)
                features.append(f)
                ips.append(ip)
            except Exception:
                continue

        if len(features) < 5:
            return False

        X = np.array(features, dtype=np.float64)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        db = DBSCAN(eps=1.5, min_samples=2)
        labels = db.fit_predict(X_scaled)

        self.labels = {ip: int(label) for ip, label in zip(ips, labels)}
        self.fitted = True
        self.trained_at = now_iso()

        n_clusters = len(set(labels) - {-1})
        n_noise = sum(1 for l in labels if l == -1)
        log.info("ML: DeviceClassifier found %d clusters, %d noise points from %d devices",
                 n_clusters, n_noise, len(ips))
        return True

    def check_drift(self, ip: str, current_profile: Any) -> str | None:
        """Check if a device has drifted from its cluster. Returns description or None."""
        if not self.fitted or ip not in self.labels:
            return None
        # A device in the noise cluster (-1) is already flagged
        if self.labels[ip] == -1:
            return f"Device {ip} doesn't fit any behavioral cluster (noise point)"
        return None

    def _profile_features(self, profile) -> list[float]:
        """Extract features from a DeviceProfile for clustering."""
        features = []
        # Total alert volume (log scale)
        features.append(math.log1p(getattr(profile, 'total_alerts', 0)))
        # Port diversity
        ports = getattr(profile, 'common_dst_ports', {})
        features.append(len(ports))
        # Destination diversity
        features.append(len(getattr(profile, 'common_dst_ips', [])))
        # Category diversity
        features.append(len(getattr(profile, 'common_categories', {})))
        # Protocol count
        features.append(len(getattr(profile, 'protocols', {})))
        # DNS domain count
        features.append(len(getattr(profile, 'dns_domains', [])))
        # Peak hour activity (which hour has most alerts)
        hourly = getattr(profile, 'hourly_alert_counts', {})
        if hourly:
            peak_hour = max(hourly, key=lambda h: hourly.get(h, 0))
            features.append(int(peak_hour))
        else:
            features.append(12)
        return features


class VolumeAnomalyDetector:
    """Detects unusual spikes in alert volume (no sklearn needed)."""

    def __init__(self):
        # Rolling counts: {src_ip: [count_per_interval]}
        self._history: dict[str, list[int]] = defaultdict(list)
        self._window = 24  # keep 24 intervals (2 hours at 5-min intervals)

    def update_and_check(self, alerts: list[dict[str, Any]]) -> list[MLPrediction]:
        """Update volume stats and return spike detections."""
        predictions = []

        # Count per src_ip
        counts: dict[str, int] = defaultdict(int)
        ip_alerts: dict[str, list[str]] = defaultdict(list)
        for a in alerts:
            src = a.get("src_ip") or ""
            if src:
                counts[src] += 1
                if a.get("id"):
                    ip_alerts[src].append(a["id"])

        # Global count
        total = len(alerts)
        self._history["__global__"].append(total)
        if len(self._history["__global__"]) > self._window:
            self._history["__global__"] = self._history["__global__"][-self._window:]

        # Check global spike
        gh = self._history["__global__"]
        if len(gh) >= 6:
            avg = sum(gh[:-1]) / len(gh[:-1])
            std = (sum((x - avg) ** 2 for x in gh[:-1]) / len(gh[:-1])) ** 0.5
            if std > 0 and total > avg + 3 * std:
                z = (total - avg) / std
                predictions.append(MLPrediction(
                    alert_id="", model="volume_spike",
                    is_anomaly=True,
                    anomaly_score=min(z / 10, 1.0),
                    explanation=f"Global alert volume spike: {total} alerts (avg={avg:.0f}, z={z:.1f})",
                    created_at=now_iso(),
                ))

        # Bound the history map: under memory pressure (e.g. scan traffic with
        # unlimited distinct source IPs) drop src_ips absent from this batch,
        # so the dict can't leak one permanent key per IP for the process life.
        if len(self._history) > 50000:
            _live = set(counts) | {"__global__"}
            for _ip in [k for k in self._history if k not in _live]:
                del self._history[_ip]
        # Per-IP checks
        for ip, count in counts.items():
            self._history[ip].append(count)
            if len(self._history[ip]) > self._window:
                self._history[ip] = self._history[ip][-self._window:]

            h = self._history[ip]
            if len(h) >= 6:
                avg = sum(h[:-1]) / len(h[:-1])
                std = (sum((x - avg) ** 2 for x in h[:-1]) / len(h[:-1])) ** 0.5
                if std > 0 and count > avg + 3 * std:
                    z = (count - avg) / std
                    predictions.append(MLPrediction(
                        alert_id=ip_alerts.get(ip, [""])[0],
                        model="volume_spike",
                        is_anomaly=True,
                        anomaly_score=min(z / 10, 1.0),
                        explanation=f"Volume spike from {ip}: {count} alerts (avg={avg:.0f}, z={z:.1f})",
                        created_at=now_iso(),
                    ))

        return predictions


class MLDetectorEngine:
    """Orchestrates all ML detection models."""

    def __init__(self, db: AlertDB, baselines: Any = None,
                 retrain_interval_sec: int = 0, training_samples: int = 0):
        self._db = db
        self._baselines = baselines
        self._running = False
        self._task: asyncio.Task | None = None
        self._retrain_interval = retrain_interval_sec or _RETRAIN_INTERVAL_SEC
        self._training_samples = training_samples or _MIN_TRAINING_SAMPLES

        self.anomaly_detector = AlertAnomalyDetector()
        self.device_classifier = DeviceClassifier()
        self.volume_detector = VolumeAnomalyDetector()

    # ── Lifecycle ─────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        # Try to load cached model from DB
        await self._load_model()
        self._task = asyncio.create_task(self._train_loop(), name="ml_detector")
        log.info("ML detector started (sklearn=%s, fitted=%s)",
                 HAS_SKLEARN, self.anomaly_detector.fitted)

    async def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("ML detector stopped")

    # ── Training loop ─────────────────────────────────────────

    async def _train_loop(self) -> None:
        # Initial training
        try:
            await self.retrain()
        except Exception:
            log.exception("ML: initial training failed")

        while self._running:
            try:
                await asyncio.sleep(self._retrain_interval)
            except asyncio.CancelledError:
                return
            try:
                await self.retrain()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("ML: retrain failed")

    async def retrain(self) -> dict[str, Any]:
        """Retrain all models. Returns training stats."""
        stats: dict[str, Any] = {"timestamp": now_iso()}

        # 1. Isolation Forest
        rows = await self._db.execute_sql(
            """SELECT id, timestamp, source, severity, title, description,
                      src_ip, src_port, dst_ip, dst_port, proto, category,
                      signature_id
               FROM alerts
               WHERE datetime(timestamp) >= datetime('now', ?)
               ORDER BY timestamp ASC
               LIMIT 50000""",
            (f"-{_TRAINING_WINDOW_DAYS} days",),
        )

        alerts = [dict(r) for r in rows]
        # sklearn fit is CPU-bound (up to 50k x 25 features); run it off the
        # event loop so HTTP/WS/triage workers don't freeze during retrain.
        loop = asyncio.get_running_loop()
        if await loop.run_in_executor(None, self.anomaly_detector.train, alerts):
            stats["isolation_forest"] = {
                "trained": True,
                "samples": self.anomaly_detector.training_count,
            }
            # Persist model
            await self._save_model()
        else:
            stats["isolation_forest"] = {"trained": False, "reason": "not enough data"}

        # 2. Device classifier (needs baselines)
        if self._baselines:
            profiles = self._baselines.get_all_profiles()
            if await loop.run_in_executor(None, self.device_classifier.train, profiles):
                stats["device_classifier"] = {
                    "trained": True,
                    "devices": len(profiles),
                    "clusters": len(set(self.device_classifier.labels.values()) - {-1}),
                }
            else:
                stats["device_classifier"] = {"trained": False}
        else:
            stats["device_classifier"] = {"trained": False, "reason": "no baselines"}

        log.info("ML: retrain complete - %s", json.dumps(stats))
        return stats

    # ── Prediction ────────────────────────────────────────────

    def predict_alert(self, alert: dict[str, Any]) -> MLPrediction:
        """Run Isolation Forest on a single alert."""
        return self.anomaly_detector.predict(alert)

    def predict_batch(self, alerts: list[dict[str, Any]]) -> list[MLPrediction]:
        """Run all detectors on a batch of alerts. Returns anomalies only."""
        predictions: list[MLPrediction] = []

        # Volume spike detection
        predictions.extend(self.volume_detector.update_and_check(alerts))

        # Isolation Forest on each alert
        for alert in alerts:
            pred = self.anomaly_detector.predict(alert)
            if pred.is_anomaly:
                predictions.append(pred)

        return predictions

    async def store_predictions(self, predictions: list[MLPrediction]) -> None:
        """Store ML predictions in the database."""
        for pred in predictions:
            try:
                await self._db.execute_sql(
                    """INSERT INTO ml_predictions
                       (alert_id, model, is_anomaly, anomaly_score, explanation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (pred.alert_id, pred.model, 1 if pred.is_anomaly else 0,
                     pred.anomaly_score, pred.explanation, pred.created_at),
                    commit=True,
                )
            except Exception:
                pass  # duplicate or missing FK

    def get_health(self) -> dict[str, Any]:
        """Return ML model health stats."""
        return {
            "sklearn_available": HAS_SKLEARN,
            "isolation_forest": {
                "fitted": self.anomaly_detector.fitted,
                "training_count": self.anomaly_detector.training_count,
                "trained_at": self.anomaly_detector.trained_at,
            },
            "device_classifier": {
                "fitted": self.device_classifier.fitted,
                "clusters": len(set(self.device_classifier.labels.values()) - {-1}) if self.device_classifier.labels else 0,
                "devices": len(self.device_classifier.labels),
                "trained_at": self.device_classifier.trained_at,
            },
            "volume_detector": {
                "tracked_ips": len(self.volume_detector._history),
            },
        }

    # ── Persistence ───────────────────────────────────────────

    async def _save_model(self) -> None:
        """Save trained model to DB."""
        data = self.anomaly_detector.serialize()
        if not data:
            return
        try:
            await self._db.execute_sql(
                """INSERT OR REPLACE INTO ml_models
                   (name, version, model_blob, metadata_json, trained_at, alert_count)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    "isolation_forest",
                    1,
                    data,
                    json.dumps({"training_count": self.anomaly_detector.training_count}),
                    self.anomaly_detector.trained_at,
                    self.anomaly_detector.training_count,
                ),
                commit=True,
            )
            log.debug("ML: saved model to DB (%d bytes)", len(data))
        except Exception:
            log.exception("ML: failed to save model")

    async def _load_model(self) -> None:
        """Load cached model from DB."""
        try:
            rows = await self._db.execute_sql(
                "SELECT model_blob, trained_at, alert_count FROM ml_models WHERE name = 'isolation_forest'"
            )
            if rows:
                row = rows[0]
                if self.anomaly_detector.deserialize(row["model_blob"]):
                    self.anomaly_detector.trained_at = row["trained_at"]
                    self.anomaly_detector.training_count = row["alert_count"]
                    log.info("ML: loaded cached model (trained %s, %d samples)",
                             row["trained_at"], row["alert_count"])
        except Exception:
            log.debug("ML: no cached model found")


def _is_rfc1918(ip: str) -> bool:
    if not ip:
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    except (ValueError, IndexError):
        return False
