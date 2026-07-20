import sqlite3

conn = sqlite3.connect('/home/user/security-shallots/shallots.db')
c = conn.cursor()

# For each cluster, compute verdict from its member alerts
c.execute("""
    SELECT c.id, 
           SUM(CASE WHEN a.verdict = 'escalate' THEN 1 ELSE 0 END) as esc,
           SUM(CASE WHEN a.verdict = 'investigate' THEN 1 ELSE 0 END) as inv,
           SUM(CASE WHEN a.verdict = 'suppress' THEN 1 ELSE 0 END) as sup,
           COUNT(*) as total
    FROM clusters c
    JOIN alerts a ON a.cluster_id = c.id
    GROUP BY c.id
""")
rows = c.fetchall()

updates = {'escalate': 0, 'investigate': 0, 'suppress': 0, 'pending': 0}
for cluster_id, esc, inv, sup, total in rows:
    if esc > 0:
        verdict = 'escalate'
    elif inv > 0:
        verdict = 'investigate'
    elif sup == total:
        verdict = 'suppress'
    else:
        verdict = 'pending'
    c.execute("UPDATE clusters SET verdict = ? WHERE id = ?", (verdict, cluster_id))
    updates[verdict] += 1

conn.commit()
print("Cluster verdicts synced:")
for v, n in sorted(updates.items()):
    print(f"  {v}: {n}")

# Verify
c.execute("SELECT verdict, COUNT(*) FROM clusters GROUP BY verdict")
print("\nClusters table now:")
for r in c.fetchall():
    print(f"  {r[0]}: {r[1]}")
conn.close()
