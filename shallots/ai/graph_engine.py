"""Network graph engine for entity relationship tracking.

Maintains an in-memory directed graph of network entities (devices, external
IPs, domains) and their connections. Enables pivot queries, attack path finding,
community detection, and entity risk scoring.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.store.db import AlertDB

from shallots.store.models import now_iso

log = logging.getLogger(__name__)

_PRUNE_INTERVAL_SEC = 3600  # 1 hour
_EDGE_TTL_HOURS = 48        # prune edges older than this
_MAX_NODES = 5000           # cap graph size
_MAX_EDGES = 20000


@dataclass
class GraphEdge:
    """An edge in the network graph."""
    src: str
    dst: str
    edge_type: str  # connects_to, resolves_to, triggers, scans
    weight: int = 1
    first_seen: str = ""
    last_seen: str = ""
    sample_alert_id: str = ""


class NetworkGraph:
    """In-memory directed graph of network entities and relationships.

    Uses adjacency lists instead of networkx to avoid the dependency.
    If networkx is available, uses it for community detection and centrality.
    """

    def __init__(self, db: AlertDB, max_nodes: int = 300):
        self._db = db
        self._running = False
        self._task: asyncio.Task | None = None
        self._max_nodes = max_nodes

        # Adjacency lists: src → {dst → {edge_type → GraphEdge}}
        self._edges: dict[str, dict[str, dict[str, GraphEdge]]] = defaultdict(
            lambda: defaultdict(dict)
        )
        # Reverse index: dst → {src}
        self._reverse: dict[str, set[str]] = defaultdict(set)
        # Node metadata
        self._nodes: dict[str, dict[str, Any]] = {}
        # Stats
        self._edge_count = 0

    # ── Lifecycle ─────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        await self._load_from_db()
        self._task = asyncio.create_task(self._prune_loop(), name="graph_prune")
        log.info("Network graph started (%d nodes, %d edges)",
                 len(self._nodes), self._edge_count)

    async def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._persist()
        log.info("Network graph stopped")

    # ── Alert ingestion ───────────────────────────────────────

    def ingest_alert(self, alert: dict[str, Any]) -> None:
        """Update graph from a single alert. Called from pipeline."""
        src_ip = alert.get("src_ip") or ""
        dst_ip = alert.get("dst_ip") or ""
        alert_id = alert.get("id") or ""
        ts = alert.get("timestamp") or now_iso()
        category = alert.get("category") or ""

        if not src_ip:
            return

        # Add/update src node
        self._ensure_node(src_ip, alert)

        if dst_ip:
            # Add/update dst node
            self._ensure_node(dst_ip, alert, is_dst=True)

            # Determine edge type
            if "scan" in category.lower():
                edge_type = "scans"
            else:
                edge_type = "connects_to"

            self._add_edge(src_ip, dst_ip, edge_type, ts, alert_id)

        # DNS relationships
        for dns_field, ip_field in [("src_dns", "src_ip"), ("dst_dns", "dst_ip")]:
            dns = alert.get(dns_field) or ""
            ip = alert.get(ip_field) or ""
            if dns and ip and "." in dns:
                self._ensure_node(dns, {"_type": "domain"})
                self._add_edge(ip, dns, "resolves_to", ts, alert_id)

        # Cap graph size
        if len(self._nodes) > _MAX_NODES:
            self._prune_oldest(keep=int(_MAX_NODES * 0.8))

    def _ensure_node(self, entity: str, alert: dict, is_dst: bool = False) -> None:
        if entity in self._nodes:
            self._nodes[entity]["last_seen"] = alert.get("timestamp") or now_iso()
            self._nodes[entity]["alert_count"] = self._nodes[entity].get("alert_count", 0) + 1
            return

        node_type = "unknown"
        if alert.get("_type") == "domain":
            node_type = "domain"
        elif _is_rfc1918(entity):
            node_type = "device"
        elif "." in entity and not entity.replace(".", "").isdigit():
            node_type = "domain"
        else:
            node_type = "external_ip"

        self._nodes[entity] = {
            "type": node_type,
            "first_seen": alert.get("timestamp") or now_iso(),
            "last_seen": alert.get("timestamp") or now_iso(),
            "alert_count": 1,
            "geo": alert.get("dst_geo" if is_dst else "src_geo") or "",
            "asset": alert.get("dst_asset" if is_dst else "src_asset") or "",
        }

    def _add_edge(self, src: str, dst: str, edge_type: str, ts: str, alert_id: str) -> None:
        existing = self._edges[src][dst].get(edge_type)
        if existing:
            existing.weight += 1
            existing.last_seen = ts
            existing.sample_alert_id = alert_id
        else:
            self._edges[src][dst][edge_type] = GraphEdge(
                src=src, dst=dst, edge_type=edge_type,
                weight=1, first_seen=ts, last_seen=ts,
                sample_alert_id=alert_id,
            )
            self._reverse[dst].add(src)
            self._edge_count += 1

    # ── Queries ───────────────────────────────────────────────

    def pivot(self, entity: str, depth: int = 2) -> dict[str, Any]:
        """Return all entities within N hops of the given entity."""
        visited: set[str] = set()
        nodes: list[dict] = []
        edges: list[dict] = []

        queue = [(entity, 0)]
        while queue:
            current, d = queue.pop(0)
            if current in visited or d > depth:
                continue
            visited.add(current)

            node_meta = self._nodes.get(current, {})
            nodes.append({
                "id": current,
                "type": node_meta.get("type", "unknown"),
                "alert_count": node_meta.get("alert_count", 0),
                "geo": node_meta.get("geo", ""),
                "asset": node_meta.get("asset", ""),
            })

            # Forward edges
            for dst, type_map in self._edges.get(current, {}).items():
                for etype, edge in type_map.items():
                    edges.append({
                        "src": current, "dst": dst, "type": etype,
                        "weight": edge.weight,
                        "first_seen": edge.first_seen,
                        "last_seen": edge.last_seen,
                    })
                    if dst not in visited and d + 1 <= depth:
                        queue.append((dst, d + 1))

            # Reverse edges
            for src in self._reverse.get(current, set()):
                for etype, edge in self._edges.get(src, {}).get(current, {}).items():
                    edges.append({
                        "src": src, "dst": current, "type": etype,
                        "weight": edge.weight,
                        "first_seen": edge.first_seen,
                        "last_seen": edge.last_seen,
                    })
                    if src not in visited and d + 1 <= depth:
                        queue.append((src, d + 1))

        # Deduplicate edges
        seen_edges: set[tuple] = set()
        unique_edges = []
        for e in edges:
            key = (e["src"], e["dst"], e["type"])
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(e)

        return {"nodes": nodes, "edges": unique_edges, "center": entity}

    def find_paths(self, src: str, dst: str, max_depth: int = 5) -> list[list[str]]:
        """Find all paths between two entities (BFS, capped at max_depth)."""
        if src == dst:
            return [[src]]
        paths: list[list[str]] = []
        queue: list[list[str]] = [[src]]

        while queue and len(paths) < 10:
            path = queue.pop(0)
            if len(path) > max_depth:
                continue
            current = path[-1]
            for neighbor in self._edges.get(current, {}):
                if neighbor in path:
                    continue  # no cycles
                new_path = path + [neighbor]
                if neighbor == dst:
                    paths.append(new_path)
                else:
                    queue.append(new_path)

        return paths

    def detect_communities(self) -> list[list[str]]:
        """Find clusters of tightly-connected entities using simple label propagation."""
        if not self._nodes:
            return []

        # Label each node with its own ID initially
        labels: dict[str, str] = {n: n for n in self._nodes}

        # Iterate: adopt most common neighbor label
        for _ in range(10):
            changed = False
            for node in list(self._nodes):
                neighbor_labels: dict[str, int] = defaultdict(int)

                # Forward neighbors
                for dst in self._edges.get(node, {}):
                    neighbor_labels[labels.get(dst, dst)] += 1

                # Reverse neighbors
                for src in self._reverse.get(node, set()):
                    neighbor_labels[labels.get(src, src)] += 1

                if neighbor_labels:
                    best = max(neighbor_labels, key=neighbor_labels.get)
                    if best != labels[node]:
                        labels[node] = best
                        changed = True

            if not changed:
                break

        # Group by label
        communities: dict[str, list[str]] = defaultdict(list)
        for node, label in labels.items():
            communities[label].append(node)

        # Return communities with 2+ members, sorted by size
        result = [sorted(members) for members in communities.values() if len(members) >= 2]
        result.sort(key=len, reverse=True)
        return result[:20]  # cap at top 20

    def score_entity(self, entity: str) -> dict[str, Any]:
        """Risk score based on connections, alert volume, and relationship types."""
        if entity not in self._nodes:
            return {"entity": entity, "score": 0, "factors": []}

        node = self._nodes[entity]
        factors: list[str] = []
        score = 0.0

        # Degree centrality
        out_degree = sum(len(types) for types in self._edges.get(entity, {}).values())
        in_degree = len(self._reverse.get(entity, set()))
        total_degree = out_degree + in_degree

        if total_degree > 20:
            score += 0.3
            factors.append(f"High connectivity: {total_degree} connections")
        elif total_degree > 10:
            score += 0.15
            factors.append(f"Moderate connectivity: {total_degree} connections")

        # Alert volume
        alert_count = node.get("alert_count", 0)
        if alert_count > 50:
            score += 0.3
            factors.append(f"High alert volume: {alert_count}")
        elif alert_count > 20:
            score += 0.15
            factors.append(f"Moderate alert volume: {alert_count}")

        # Scan activity
        scan_edges = sum(
            1 for dst_map in self._edges.get(entity, {}).values()
            for etype in dst_map if etype == "scans"
        )
        if scan_edges > 5:
            score += 0.2
            factors.append(f"Scanning {scan_edges} targets")

        # External IP talking to many internals
        if node.get("type") == "external_ip":
            internal_targets = sum(
                1 for dst in self._edges.get(entity, {})
                if _is_rfc1918(dst)
            )
            if internal_targets > 3:
                score += 0.2
                factors.append(f"External IP targeting {internal_targets} internal hosts")

        return {
            "entity": entity,
            "type": node.get("type", "unknown"),
            "score": min(round(score, 2), 1.0),
            "factors": factors,
            "alert_count": alert_count,
            "degree": total_degree,
        }

    def get_full_topology(self, max_nodes: int = 0) -> dict[str, Any]:
        """Return the full graph topology for visualization.

        Returns nodes with risk scores and all edges, capped at max_nodes
        by prioritizing high-alert-count and high-degree nodes.
        """
        if not self._nodes:
            return {"nodes": [], "edges": [], "stats": self.get_stats()}

        # Score all nodes for prioritization
        node_scores: list[tuple[str, float, dict]] = []
        for entity, meta in self._nodes.items():
            out_degree = sum(len(types) for types in self._edges.get(entity, {}).values())
            in_degree = len(self._reverse.get(entity, set()))
            alert_count = meta.get("alert_count", 0)
            # Priority = alert_count * 2 + degree (favor active nodes)
            priority = alert_count * 2 + out_degree + in_degree
            node_scores.append((entity, priority, meta))

        # Sort by priority, take top N
        node_scores.sort(key=lambda x: x[1], reverse=True)
        limit = max_nodes or self._max_nodes
        keep_entities = {n[0] for n in node_scores[:limit]}

        # Build node list with scores
        nodes = []
        for entity, priority, meta in node_scores[:limit]:
            score_data = self.score_entity(entity)
            out_degree = sum(len(types) for types in self._edges.get(entity, {}).values())
            in_degree = len(self._reverse.get(entity, set()))
            nodes.append({
                "id": entity,
                "type": meta.get("type", "unknown"),
                "alert_count": meta.get("alert_count", 0),
                "geo": meta.get("geo", ""),
                "asset": meta.get("asset", ""),
                "first_seen": meta.get("first_seen", ""),
                "last_seen": meta.get("last_seen", ""),
                "risk_score": score_data.get("score", 0),
                "risk_factors": score_data.get("factors", []),
                "out_degree": out_degree,
                "in_degree": in_degree,
            })

        # Collect edges between kept nodes
        edges = []
        seen_edges: set[tuple] = set()
        for src, dst_map in self._edges.items():
            if src not in keep_entities:
                continue
            for dst, type_map in dst_map.items():
                if dst not in keep_entities:
                    continue
                for etype, edge in type_map.items():
                    key = (src, dst, etype)
                    if key not in seen_edges:
                        seen_edges.add(key)
                        edges.append({
                            "source": src,
                            "target": dst,
                            "type": etype,
                            "weight": edge.weight,
                            "first_seen": edge.first_seen,
                            "last_seen": edge.last_seen,
                        })

        # Communities for coloring
        communities = self.detect_communities()
        community_map = {}
        for i, members in enumerate(communities):
            for m in members:
                if m in keep_entities:
                    community_map[m] = i

        for node in nodes:
            node["community"] = community_map.get(node["id"], -1)

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": self.get_stats(),
            "community_count": len(communities),
        }

    def get_stats(self) -> dict[str, Any]:
        """Graph size and health stats."""
        type_counts: dict[str, int] = defaultdict(int)
        for meta in self._nodes.values():
            type_counts[meta.get("type", "unknown")] += 1

        edge_type_counts: dict[str, int] = defaultdict(int)
        for src_map in self._edges.values():
            for dst_map in src_map.values():
                for etype in dst_map:
                    edge_type_counts[etype] += 1

        return {
            "node_count": len(self._nodes),
            "edge_count": self._edge_count,
            "node_types": dict(type_counts),
            "edge_types": dict(edge_type_counts),
        }

    # ── Persistence ───────────────────────────────────────────

    async def _persist(self) -> None:
        """Save graph edges to DB for restart recovery."""
        # Snapshot FIRST: ingest_alert() mutates self._edges from the pipeline task,
        # and awaiting inside the nested loops used to yield mid-iteration ->
        # "dict changed size during iteration". The DELETE was also committed on
        # its own, so a mid-loop crash left graph_edges wiped (restart-recovery
        # silently broken under load). Build the row list synchronously FIRST so
        # the write loop iterates a static snapshot, never the live dict.
        rows = [
            (edge.src, edge.dst, edge.edge_type, edge.weight,
             edge.first_seen, edge.last_seen, edge.sample_alert_id)
            for dst_map in self._edges.values()
            for type_map in dst_map.values()
            for edge in type_map.values()
        ]
        try:
            await self._db.execute_sql("DELETE FROM graph_edges", commit=True)
            for row in rows:
                await self._db.execute_sql(
                    """INSERT OR REPLACE INTO graph_edges
                       (src, dst, edge_type, weight, first_seen, last_seen, sample_alert_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    row, commit=True,
                )
            log.debug("Graph: persisted %d edges", len(rows))
        except Exception:
            log.exception("Graph: persistence failed")

    async def _load_from_db(self) -> None:
        """Load graph from DB on startup, then overlay with recent alerts."""
        try:
            rows = await self._db.execute_sql(
                "SELECT src, dst, edge_type, weight, first_seen, last_seen, sample_alert_id FROM graph_edges"
            )
            for row in rows:
                edge = GraphEdge(
                    src=row["src"], dst=row["dst"], edge_type=row["edge_type"],
                    weight=row["weight"], first_seen=row["first_seen"],
                    last_seen=row["last_seen"], sample_alert_id=row["sample_alert_id"],
                )
                self._edges[edge.src][edge.dst][edge.edge_type] = edge
                self._reverse[edge.dst].add(edge.src)
                self._edge_count += 1

                # Ensure nodes exist
                for entity in (edge.src, edge.dst):
                    if entity not in self._nodes:
                        self._nodes[entity] = {
                            "type": "device" if _is_rfc1918(entity) else "external_ip",
                            "first_seen": edge.first_seen,
                            "last_seen": edge.last_seen,
                            "alert_count": 0,
                        }

            log.info("Graph: loaded %d edges from DB", self._edge_count)
        except Exception:
            log.debug("Graph: no persisted edges found (table may not exist yet)")

        # Overlay with recent alerts (last 24h) to build nodes
        try:
            rows = await self._db.execute_sql(
                """SELECT id, src_ip, dst_ip, src_dns, dst_dns, src_geo, dst_geo,
                          src_asset, dst_asset, category, timestamp
                   FROM alerts
                   WHERE timestamp >= datetime('now', '-24 hours')
                   ORDER BY timestamp ASC
                   LIMIT 5000"""
            )
            for row in rows:
                self.ingest_alert(dict(row))
            log.info("Graph: ingested %d recent alerts", len(rows))
        except Exception:
            log.debug("Graph: could not load recent alerts")

    # ── Pruning ───────────────────────────────────────────────

    async def _prune_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(_PRUNE_INTERVAL_SEC)
            except asyncio.CancelledError:
                return
            try:
                self._prune_old_edges()
                await self._persist()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("Graph: prune error")

    def _prune_old_edges(self) -> None:
        """Remove edges older than _EDGE_TTL_HOURS."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=_EDGE_TTL_HOURS)).isoformat()
        to_remove: list[tuple[str, str, str]] = []

        for src, dst_map in self._edges.items():
            for dst, type_map in dst_map.items():
                for etype, edge in type_map.items():
                    if edge.last_seen < cutoff:
                        to_remove.append((src, dst, etype))

        for src, dst, etype in to_remove:
            del self._edges[src][dst][etype]
            if not self._edges[src][dst]:
                del self._edges[src][dst]
                self._reverse[dst].discard(src)
            if not self._edges[src]:
                del self._edges[src]
            self._edge_count -= 1

        # Remove orphan nodes
        connected = set()
        for src, dst_map in self._edges.items():
            connected.add(src)
            for dst in dst_map:
                connected.add(dst)
        orphans = [n for n in self._nodes if n not in connected]
        for n in orphans:
            del self._nodes[n]

        if to_remove:
            log.info("Graph: pruned %d old edges, %d orphan nodes", len(to_remove), len(orphans))

    def _prune_oldest(self, keep: int) -> None:
        """Prune to keep only the N most recently seen nodes."""
        if len(self._nodes) <= keep:
            return
        sorted_nodes = sorted(
            self._nodes.items(),
            key=lambda x: x[1].get("last_seen", ""),
            reverse=True,
        )
        keep_set = {n[0] for n in sorted_nodes[:keep]}
        remove = [n for n in self._nodes if n not in keep_set]
        for n in remove:
            del self._nodes[n]
            # Outgoing edges (n -> *)
            if n in self._edges:
                for dst in list(self._edges[n]):
                    for etype in list(self._edges[n][dst]):
                        self._edge_count -= 1
                    self._reverse[dst].discard(n)
                del self._edges[n]
            # Incoming edges (* -> n): without this they dangle at a deleted
            # node — _edge_count stays inflated and graph queries return edges
            # whose dst is gone from self._nodes (unguarded self._nodes[dst]).
            for src in list(self._reverse.get(n, ())):
                emap = self._edges.get(src)
                if emap and n in emap:
                    self._edge_count -= len(emap[n])
                    del emap[n]
            self._reverse.pop(n, None)
        log.info("Graph: pruned %d nodes (cap reached)", len(remove))


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
