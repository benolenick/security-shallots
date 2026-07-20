/**
 * Security Shallots — Alert Wiki
 * Knowledge base with ~49 articles covering all alert types.
 * Left-side slide-out panel with searchable index + article views.
 */

'use strict';

// ── Knowledge Base ────────────────────────────────────────────────────────────

const WIKI_ARTICLES = [

  // ── Suricata Custom Rules ────────────────────────────────────────────────

  {
    id: 'suricata-9000001',
    title: 'SSH Brute Force (SID 9000001)',
    source: 'suricata',
    severity: 'high',
    tags: ['brute-force', 'ssh', 'credential-access'],
    mitre: ['T1110', 'T1110.001'],
    summary: 'Detects repeated SSH login attempts from a single source.',
    body: {
      what: 'This rule fires when a single IP generates excessive SSH connection attempts in a short window. It indicates someone (or a bot) is systematically trying username/password combinations to gain shell access.',
      why: 'The Suricata rule tracks SSH connection frequency per source IP. When the threshold is exceeded within the configured time window, the alert fires. This is one of the most common attack patterns on internet-facing SSH services.',
      assess: 'High severity if the target is a real SSH service. Check if the source IP is external (internet) vs. internal. External brute force from multiple IPs may indicate a botnet. A single IP doing thousands of attempts is typically automated tooling (Hydra, Medusa, etc.).',
      action: '1. Check if the source IP is already banned by fail2ban/CrowdSec\n2. Verify the target host uses key-based auth (immune to brute force)\n3. If password auth is enabled, consider disabling it\n4. Add the source to your firewall blocklist if persistent\n5. Check auth logs on the target: grep "Failed password" /var/log/auth.log',
      falsePositives: 'Legitimate users who mistype passwords repeatedly. Automated deployment tools (Ansible, etc.) with expired credentials. Internal vulnerability scanners.',
    },
    statsKey: { source: 'suricata', signature_id: 9000001 },
  },
  {
    id: 'suricata-9000002',
    title: 'RDP Brute Force (SID 9000002)',
    source: 'suricata',
    severity: 'high',
    tags: ['brute-force', 'rdp', 'credential-access'],
    mitre: ['T1110', 'T1110.001'],
    summary: 'Detects repeated RDP login attempts indicating brute force.',
    body: {
      what: 'Repeated Remote Desktop Protocol connection attempts from a single source, indicating credential guessing against Windows endpoints.',
      why: 'RDP is a prime target for attackers because it provides full GUI access to Windows systems. This rule tracks RDP connection frequency and fires when the threshold is exceeded.',
      assess: 'High severity. RDP brute force is a top initial access vector for ransomware. External sources are extremely concerning. Internal sources may indicate lateral movement.',
      action: '1. Check if RDP should be exposed at all (prefer VPN)\n2. Enable Network Level Authentication (NLA)\n3. Check Windows Event Log 4625 (failed logons) on the target\n4. Consider implementing account lockout policies\n5. Block the source IP at the firewall',
      falsePositives: 'Users with expired cached credentials. RDP clients reconnecting after network issues. Vulnerability scanners.',
    },
    statsKey: { source: 'suricata', signature_id: 9000002 },
  },
  {
    id: 'suricata-9000003',
    title: 'DNS Tunnel Detected (SID 9000003)',
    source: 'suricata',
    severity: 'high',
    tags: ['dns-tunnel', 'exfiltration', 'c2'],
    mitre: ['T1071.004', 'T1048.003'],
    summary: 'Unusually long DNS queries suggesting DNS tunneling for C2 or exfiltration.',
    body: {
      what: 'DNS tunneling encodes data in DNS queries to bypass firewalls. Attackers use tools like iodine, dnscat2, or cobalt strike to create covert channels through DNS.',
      why: 'The rule looks for DNS queries with abnormally long subdomain labels (>50 chars) or high entropy, which are hallmarks of encoded data rather than legitimate domain names.',
      assess: 'High severity. DNS tunneling usually means an already-compromised host is exfiltrating data or receiving C2 commands. The encrypted/encoded nature makes it hard to inspect payload.',
      action: '1. Identify the source host immediately\n2. Check what process is generating the DNS queries\n3. Look up the queried domain — is it a known DNS tunnel provider?\n4. Capture and analyze the full DNS query log from the host\n5. Consider isolating the host pending investigation',
      falsePositives: 'Some legitimate services use long DNS names (CDNs, DKIM records, TXT verification). Anti-virus cloud lookups can have long hashes in queries.',
    },
    statsKey: { source: 'suricata', signature_id: 9000003 },
  },
  {
    id: 'suricata-9000010',
    title: 'Internal Port Scan (SID 9000010)',
    source: 'suricata',
    severity: 'medium',
    tags: ['scan', 'reconnaissance', 'internal'],
    mitre: ['T1046'],
    summary: 'An internal host is scanning multiple ports on another internal host.',
    body: {
      what: 'Internal port scanning — one host on your network is probing multiple ports on another internal host, which is a reconnaissance technique used after initial compromise.',
      why: 'This rule tracks unique destination ports per source-destination pair. When an internal host connects to many ports on another internal host in a short time, it triggers.',
      assess: 'Medium severity. Could indicate lateral movement after initial compromise, or just an IT admin running nmap. Context matters — who owns the source host?',
      action: '1. Identify the source host and its user\n2. Check if this is authorized scanning (IT admin, vuln scanner)\n3. If unexpected, investigate the source host for compromise\n4. Check what ports were being scanned — targeting 445/3389/22 suggests lateral movement',
      falsePositives: 'Vulnerability scanners (Nessus, OpenVAS). IT admins running nmap. Network monitoring tools. Service discovery protocols.',
    },
    statsKey: { source: 'suricata', signature_id: 9000010 },
  },
  {
    id: 'suricata-9000011',
    title: 'External Port Scan (SID 9000011)',
    source: 'suricata',
    severity: 'medium',
    tags: ['scan', 'reconnaissance', 'external'],
    mitre: ['T1046', 'T1595.001'],
    summary: 'An external IP is scanning ports on your network.',
    body: {
      what: 'An external host is probing multiple ports on your systems, attempting to discover what services are running and potentially vulnerable.',
      why: 'This is the reconnaissance phase of an attack — the attacker is mapping your attack surface before attempting exploitation.',
      assess: 'Medium severity on its own, but should be correlated with follow-up activity. If the same IP later tries exploits, escalate. Mass scanning (Shodan, Censys) is common background noise.',
      action: '1. Check the source IP reputation (VirusTotal, AbuseIPDB)\n2. Is it a known scanner (Shodan, Censys, your own external scanner)?\n3. Verify your firewall is blocking unauthorized ports\n4. If targeted (specific ports relevant to your services), monitor for follow-up exploitation attempts',
      falsePositives: 'Internet-wide scanners (Shodan, Censys, academic research). Your own external vulnerability scanners. CDN/cloud health checks.',
    },
    statsKey: { source: 'suricata', signature_id: 9000011 },
  },
  {
    id: 'suricata-9000020',
    title: 'Suspicious Outbound Connection (SID 9000020)',
    source: 'suricata',
    severity: 'high',
    tags: ['c2', 'outbound', 'suspicious'],
    mitre: ['T1071', 'T1571'],
    summary: 'Internal host connecting to a suspicious external IP or unusual port.',
    body: {
      what: 'An internal host is making outbound connections to an IP or port that matches known malicious infrastructure or unusual communication patterns.',
      why: 'C2 (command-and-control) callbacks from compromised hosts often use non-standard ports, known bad IPs, or unusual protocols. This rule catches those patterns.',
      assess: 'High severity. Outbound connections to suspicious infrastructure are a strong indicator of compromise. The internal host may be running malware.',
      action: '1. Identify the internal host and user\n2. Check what process/application is making the connection\n3. Look up the destination IP (VirusTotal, threat intel feeds)\n4. Check for other alerts from the same source host\n5. Consider isolating the host if confirmed suspicious',
      falsePositives: 'VPN connections to uncommon endpoints. Peer-to-peer applications. Gaming servers on non-standard ports.',
    },
    statsKey: { source: 'suricata', signature_id: 9000020 },
  },
  {
    id: 'suricata-9000030',
    title: 'ICMP Flood / Ping Sweep (SID 9000030)',
    source: 'suricata',
    severity: 'low',
    tags: ['icmp', 'sweep', 'reconnaissance'],
    mitre: ['T1018', 'T1046'],
    summary: 'High volume of ICMP packets indicating a ping sweep or ICMP flood.',
    body: {
      what: 'A burst of ICMP echo requests, either targeting many hosts (ping sweep) or flooding a single host (ICMP flood DoS).',
      why: 'Ping sweeps discover live hosts on a subnet. ICMP floods can be used for denial-of-service. Both generate abnormal ICMP traffic volumes.',
      assess: 'Low severity for typical ping sweeps — they are noisy recon. Higher severity if targeting a specific host at high volume (DoS). Check the pattern.',
      action: '1. Determine if it is a sweep (many destinations) or flood (single destination)\n2. For sweeps: identify source — internal admin or external recon?\n3. For floods: check if the target host is experiencing service degradation\n4. Consider rate-limiting ICMP at the firewall',
      falsePositives: 'Network monitoring tools (Nagios, PRTG). DHCP/network configuration. Legitimate admin ping sweeps. Containerized workloads with health checks.',
    },
    statsKey: { source: 'suricata', signature_id: 9000030 },
  },
  {
    id: 'suricata-9000040',
    title: 'Cleartext Credentials (SID 9000040)',
    source: 'suricata',
    severity: 'high',
    tags: ['cleartext', 'credentials', 'ftp', 'telnet'],
    mitre: ['T1552.001', 'T1040'],
    summary: 'Credentials detected in cleartext protocols (FTP, Telnet, HTTP Basic).',
    body: {
      what: 'Login credentials were observed in an unencrypted protocol. Anyone sniffing the network can capture these credentials.',
      why: 'FTP, Telnet, and HTTP Basic Auth transmit credentials in plaintext. This rule detects USER/PASS sequences in these protocols.',
      assess: 'High severity — credentials are exposed to anyone on the network path. Even if the service is internal, cleartext credentials are a significant risk.',
      action: '1. Identify the service and users involved\n2. Migrate to encrypted alternatives (SFTP instead of FTP, SSH instead of Telnet, HTTPS instead of HTTP)\n3. Rotate any credentials that were transmitted in cleartext\n4. Audit the network for other cleartext services',
      falsePositives: 'Legacy internal systems that cannot be upgraded. Printers with FTP firmware update. IoT devices with hardcoded protocols.',
    },
    statsKey: { source: 'suricata', signature_id: 9000040 },
  },
  {
    id: 'suricata-9000050',
    title: 'TLS/SSL Anomaly (SID 9000050)',
    source: 'suricata',
    severity: 'medium',
    tags: ['tls', 'ssl', 'certificate', 'anomaly'],
    mitre: ['T1557', 'T1573'],
    summary: 'TLS handshake anomaly — expired cert, self-signed cert to unexpected destination, or downgrade.',
    body: {
      what: 'The TLS handshake exhibited anomalous properties: expired certificate, suspicious self-signed cert, weak cipher suite, or protocol downgrade attempt.',
      why: 'Malware C2 often uses self-signed or expired certificates. Man-in-the-middle attacks may cause certificate mismatches. Protocol downgrade attacks weaken encryption.',
      assess: 'Medium severity. Self-signed certs to external sites are more suspicious than internal ones. Expired certs may just be poor maintenance. Downgrade attacks are actively malicious.',
      action: '1. Check the destination — is it a known service with cert management issues?\n2. Compare the cert fingerprint against the expected cert for the destination\n3. If the destination is unknown, investigate the connecting host\n4. For downgrade attacks, verify no MITM proxy is in the path',
      falsePositives: 'Internal services with self-signed certs (like this dashboard!). Development environments. IoT devices with old TLS stacks.',
    },
    statsKey: { source: 'suricata', signature_id: 9000050 },
  },
  {
    id: 'suricata-9000051',
    title: 'Known Malicious TLS Certificate (SID 9000051)',
    source: 'suricata',
    severity: 'critical',
    tags: ['tls', 'malware', 'c2', 'certificate'],
    mitre: ['T1573.002', 'T1071.001'],
    summary: 'TLS certificate fingerprint matches known malware C2 infrastructure.',
    body: {
      what: 'The TLS certificate presented by the server matches a known malicious certificate fingerprint (JA3S hash or cert hash) from threat intelligence feeds.',
      why: 'Malware families reuse TLS certificates across their C2 infrastructure. Matching a known bad cert fingerprint is a high-confidence indicator of compromise.',
      assess: 'Critical severity. This is a strong signal that the connecting host is communicating with known malware infrastructure.',
      action: '1. Immediately identify the internal host making the connection\n2. Isolate the host from the network\n3. Capture memory and disk evidence before remediation\n4. Check for lateral movement from this host to others\n5. Look up the cert hash in threat intel for malware family identification',
      falsePositives: 'Extremely rare. Certificate reuse by unrelated legitimate services sharing hosting is theoretically possible but unlikely.',
    },
    statsKey: { source: 'suricata', signature_id: 9000051 },
  },
  {
    id: 'suricata-9000055',
    title: 'HTTP Suspicious User-Agent (SID 9000055)',
    source: 'suricata',
    severity: 'medium',
    tags: ['http', 'user-agent', 'suspicious'],
    mitre: ['T1071.001'],
    summary: 'HTTP request with a known-malicious or highly unusual User-Agent string.',
    body: {
      what: 'An HTTP request contained a User-Agent string associated with known attack tools, malware, or an obviously fabricated/empty User-Agent.',
      why: 'Many exploit tools and malware families have distinctive User-Agent strings (e.g., "python-requests", "Go-http-client", empty UA, or tool-specific strings like "sqlmap").',
      assess: 'Medium severity. Many legitimate tools also use generic UAs. Correlate with the destination and other alerts from the same source.',
      action: '1. Check the full HTTP request — what URL was being accessed?\n2. Is the source internal or external?\n3. For internal sources, identify what application is making the request\n4. For external sources, check if it is automated scanning',
      falsePositives: 'Python/Go/curl scripts for legitimate automation. API integrations. Monitoring tools. Custom applications with default HTTP library UAs.',
    },
    statsKey: { source: 'suricata', signature_id: 9000055 },
  },
  {
    id: 'suricata-9000060',
    title: 'SMB Lateral Movement (SID 9000060)',
    source: 'suricata',
    severity: 'high',
    tags: ['smb', 'lateral-movement', 'internal'],
    mitre: ['T1021.002', 'T1570'],
    summary: 'SMB file sharing activity suggesting lateral movement between internal hosts.',
    body: {
      what: 'Suspicious SMB (Server Message Block) activity between internal hosts, such as accessing admin shares (C$, ADMIN$), or transferring executables over SMB.',
      why: 'Attackers use SMB to move laterally — copying tools to other machines, accessing file shares, or exploiting SMB vulnerabilities (EternalBlue).',
      assess: 'High severity. SMB lateral movement is a key phase in many attacks. Admin share access (C$, ADMIN$) from unexpected sources is particularly concerning.',
      action: '1. Verify the source host is authorized to access the destination via SMB\n2. Check what files were transferred or accessed\n3. Review authentication logs — was it a service account or user account?\n4. If unexpected, investigate both source and destination hosts\n5. Check for EternalBlue/SMBGhost vulnerability patches',
      falsePositives: 'IT admin using admin shares for management. Backup software. Domain controller replication. Print spooler services.',
    },
    statsKey: { source: 'suricata', signature_id: 9000060 },
  },
  {
    id: 'suricata-9000065',
    title: 'Cryptocurrency Mining Traffic (SID 9000065)',
    source: 'suricata',
    severity: 'medium',
    tags: ['cryptomining', 'stratum', 'resource-hijacking'],
    mitre: ['T1496'],
    summary: 'Network traffic matching cryptocurrency mining pool communication (Stratum protocol).',
    body: {
      what: 'An internal host is communicating with a cryptocurrency mining pool using the Stratum protocol or similar mining protocols.',
      why: 'Cryptojacking — unauthorized use of computing resources for mining — is one of the most common post-compromise activities. It is financially motivated and often automated.',
      assess: 'Medium severity. The host is likely compromised or a user is mining without authorization. While not destructive, it wastes resources and indicates a security breach.',
      action: '1. Identify the host and check for running mining processes (xmrig, etc.)\n2. Check how the miner was installed — was there a prior compromise?\n3. Kill the mining process and remove the software\n4. Investigate the initial access vector\n5. Block known mining pool domains/IPs at the firewall',
      falsePositives: 'Authorized mining operations (unlikely in most organizations). Blockchain development/testing.',
    },
    statsKey: { source: 'suricata', signature_id: 9000065 },
  },
  {
    id: 'suricata-9000070',
    title: 'Data Exfiltration Pattern (SID 9000070)',
    source: 'suricata',
    severity: 'critical',
    tags: ['exfiltration', 'data-theft', 'outbound'],
    mitre: ['T1048', 'T1041'],
    summary: 'Large or sustained outbound data transfer to an unusual destination.',
    body: {
      what: 'An internal host is transferring an unusually large amount of data to an external destination that is not a known cloud service or CDN.',
      why: 'Data exfiltration is the end goal of many attacks. This rule detects abnormal outbound data volumes that deviate from baseline traffic patterns.',
      assess: 'Critical severity. If the destination is not a known legitimate service (cloud backup, SaaS), this could be active data theft.',
      action: '1. Immediately identify the internal host and user\n2. Determine what data is being transferred and to where\n3. If suspicious, isolate the host to stop ongoing exfiltration\n4. Preserve evidence — network captures, process lists, file access logs\n5. Determine what data may have been compromised',
      falsePositives: 'Large file uploads to cloud storage (OneDrive, Google Drive). Video calls. Software updates. Backup operations to external sites.',
    },
    statsKey: { source: 'suricata', signature_id: 9000070 },
  },

  // ── Suricata ET Categories ───────────────────────────────────────────────

  {
    id: 'et-malware',
    title: 'ET MALWARE — Malware Communication',
    source: 'suricata',
    severity: 'critical',
    tags: ['malware', 'c2', 'emerging-threats'],
    mitre: ['T1071', 'T1573', 'T1105'],
    summary: 'Traffic matched a known malware communication pattern from Emerging Threats.',
    body: {
      what: 'The Emerging Threats (ET) ruleset detected network traffic that matches known malware command-and-control, payload download, or beaconing patterns.',
      why: 'ET maintains thousands of signatures for known malware families. When traffic matches these patterns, it means a host is likely infected and communicating with attacker infrastructure.',
      assess: 'Critical severity. ET MALWARE rules have high confidence because they match specific known patterns. False positives are relatively rare.',
      action: '1. Identify the internal host immediately\n2. Check the specific ET rule that triggered (see signature_id in alert details)\n3. Look up the rule SID on rules.emergingthreats.net for details\n4. Isolate the host and begin incident response\n5. Check for lateral movement from this host',
      falsePositives: 'Security researchers analyzing malware samples. Sandboxed malware detonation. Very rarely, legitimate software that coincidentally matches a pattern.',
    },
    statsKey: { source: 'suricata', category: 'ET MALWARE' },
  },
  {
    id: 'et-trojan',
    title: 'ET TROJAN — Trojan Activity',
    source: 'suricata',
    severity: 'critical',
    tags: ['trojan', 'c2', 'rat', 'emerging-threats'],
    mitre: ['T1071', 'T1219', 'T1105'],
    summary: 'Traffic matched a known trojan/RAT command-and-control pattern.',
    body: {
      what: 'Network traffic matches a known Remote Access Trojan (RAT) or trojan horse C2 communication pattern. This includes trojans like Emotet, TrickBot, Agent Tesla, AsyncRAT, etc.',
      why: 'Trojans provide attackers with persistent remote access. Their network signatures are well-documented in the ET ruleset.',
      assess: 'Critical severity. Trojan C2 traffic means an attacker likely has active access to the host. This is an active compromise.',
      action: '1. Isolate the affected host immediately\n2. Note the specific trojan family from the rule name\n3. Begin forensic analysis — capture memory, check persistence mechanisms\n4. Check all other hosts for similar traffic\n5. Identify the infection vector (email, drive-by, USB)',
      falsePositives: 'Extremely rare for specific trojan signatures. Generic trojan patterns may occasionally match legitimate obfuscated traffic.',
    },
    statsKey: { source: 'suricata', category: 'ET TROJAN' },
  },
  {
    id: 'et-exploit',
    title: 'ET EXPLOIT — Exploit Attempt',
    source: 'suricata',
    severity: 'high',
    tags: ['exploit', 'vulnerability', 'emerging-threats'],
    mitre: ['T1190', 'T1203', 'T1210'],
    summary: 'An exploit attempt was detected targeting a known vulnerability.',
    body: {
      what: 'Network traffic contains patterns matching a known exploitation technique — someone is actively trying to exploit a vulnerability in a service or application.',
      why: 'ET EXPLOIT rules detect specific CVE exploitation attempts, buffer overflows, injection attacks, and other exploitation payloads in network traffic.',
      assess: 'High severity. Even if the exploit failed, the attempt indicates an attacker is actively targeting your systems. Check if the target service is vulnerable.',
      action: '1. Determine what service was targeted and if it is vulnerable\n2. Check if the exploit was successful (follow-up connections, behavior changes)\n3. Patch the vulnerability if applicable\n4. Block the attacking IP\n5. Look up the specific CVE from the rule details',
      falsePositives: 'Vulnerability scanners (Nessus, Qualys). Penetration testing. Occasionally, legitimate traffic that contains sequences resembling exploit patterns.',
    },
    statsKey: { source: 'suricata', category: 'ET EXPLOIT' },
  },
  {
    id: 'et-scan',
    title: 'ET SCAN — Scanning Activity',
    source: 'suricata',
    severity: 'low',
    tags: ['scan', 'reconnaissance', 'emerging-threats'],
    mitre: ['T1046', 'T1595'],
    summary: 'Network scanning or enumeration activity detected.',
    body: {
      what: 'Automated scanning tools (nmap, masscan, ZMap) or manual port scanning has been detected. This is the reconnaissance phase before an attack.',
      why: 'ET SCAN rules detect the distinctive patterns of common scanning tools — SYN scans, version detection probes, OS fingerprinting, etc.',
      assess: 'Low severity in isolation. Scanning is constant background noise on the internet. Becomes medium/high if followed by exploit attempts from the same source.',
      action: '1. If external: check IP reputation. Known scanners (Shodan, Censys) are informational\n2. If internal: verify it is authorized scanning\n3. Correlate with other alerts from the same source IP\n4. Ensure your firewall is properly configured to limit exposure',
      falsePositives: 'Internet-wide scanners. Your own vulnerability assessment tools. Network monitoring and inventory tools. CDN health checks.',
    },
    statsKey: { source: 'suricata', category: 'ET SCAN' },
  },
  {
    id: 'et-info',
    title: 'ET INFO — Informational',
    source: 'suricata',
    severity: 'low',
    tags: ['informational', 'policy', 'emerging-threats'],
    mitre: ['T1071'],
    summary: 'Informational alert — noteworthy traffic but not necessarily malicious.',
    body: {
      what: 'Traffic was flagged as interesting but not definitively malicious. Examples include: unusual user agents, known VPN/proxy usage, dynamic DNS lookups, or uncommon protocols.',
      why: 'ET INFO rules track traffic patterns that might be relevant for security investigation without reaching the threshold for a definitive threat. They provide context.',
      assess: 'Low severity. These are building blocks for correlation, not standalone threats. Useful when combined with other higher-severity alerts from the same host.',
      action: '1. Note the specific finding in the alert title\n2. No immediate action required for isolated INFO alerts\n3. Use these to add context when investigating other alerts\n4. Consider writing correlation rules for INFO + higher-severity combinations',
      falsePositives: 'Very common. Many legitimate activities trigger INFO rules. This is expected — the rules are intentionally broad to capture potentially useful data.',
    },
    statsKey: { source: 'suricata', category: 'ET INFO' },
  },
  {
    id: 'et-policy',
    title: 'ET POLICY — Policy Violation',
    source: 'suricata',
    severity: 'low',
    tags: ['policy', 'compliance', 'emerging-threats'],
    mitre: ['T1048', 'T1071'],
    summary: 'Traffic that may violate organizational security policies.',
    body: {
      what: 'Network activity that might violate security or acceptable use policies — such as P2P file sharing, torrenting, unauthorized VPN tunnels, or accessing restricted services.',
      why: 'ET POLICY rules detect usage patterns that organizations commonly want to monitor or restrict, even if not directly malicious.',
      assess: 'Low severity from a threat perspective, but may be important for compliance or policy enforcement. Context-dependent.',
      action: '1. Determine if the activity violates your specific policies\n2. Identify the user and have a conversation if needed\n3. Consider blocking the traffic at the firewall if policy requires\n4. Document for compliance reporting if applicable',
      falsePositives: 'Depends entirely on your organization\'s policies. What is a violation in one org may be completely acceptable in another.',
    },
    statsKey: { source: 'suricata', category: 'ET POLICY' },
  },
  {
    id: 'et-dos',
    title: 'ET DOS — Denial of Service',
    source: 'suricata',
    severity: 'high',
    tags: ['dos', 'ddos', 'availability', 'emerging-threats'],
    mitre: ['T1498', 'T1499'],
    summary: 'Traffic patterns matching known denial-of-service attack techniques.',
    body: {
      what: 'Network traffic matches known DoS/DDoS attack patterns — SYN floods, amplification attacks, application-layer floods, or slowloris-type attacks.',
      why: 'ET DOS rules detect the specific patterns of known denial-of-service techniques that can overwhelm services and cause outages.',
      assess: 'High severity if targeting your services. Check if the target is experiencing degradation. DDoS from multiple sources is more impactful.',
      action: '1. Check if the target service is still operational\n2. Implement rate limiting if not already in place\n3. For volumetric attacks, contact your ISP\n4. Enable DDoS mitigation (Cloudflare, AWS Shield, etc.)\n5. Block the source(s) at the firewall',
      falsePositives: 'Legitimate high-traffic events (product launches, viral content). Stress testing tools in authorized testing. Burst traffic from CDNs.',
    },
    statsKey: { source: 'suricata', category: 'ET DOS' },
  },
  {
    id: 'et-web-server',
    title: 'ET WEB_SERVER — Web Server Attacks',
    source: 'suricata',
    severity: 'high',
    tags: ['web', 'injection', 'server', 'emerging-threats'],
    mitre: ['T1190', 'T1059'],
    summary: 'Attack targeting a web server — SQL injection, XSS, directory traversal, RCE attempts.',
    body: {
      what: 'An attack targeting a web server/application has been detected. This covers SQL injection, cross-site scripting (XSS), directory traversal, remote code execution, and other OWASP Top 10 attack types.',
      why: 'Web applications are the most common attack surface. ET WEB_SERVER rules detect exploitation attempts in HTTP requests targeting server-side vulnerabilities.',
      assess: 'High severity. Even if the web app is not vulnerable, the attempt indicates active targeting. If the app IS vulnerable, you may have a breach.',
      action: '1. Check the specific attack type from the rule name\n2. Determine if your web application is vulnerable to this attack\n3. Review web application logs for successful exploitation\n4. Deploy WAF rules if not already in place\n5. Patch/fix the underlying vulnerability',
      falsePositives: 'Web vulnerability scanners (Nikto, OWASP ZAP, Burp). Security researchers. Occasionally, legitimate URLs that contain characters resembling injection attempts.',
    },
    statsKey: { source: 'suricata', category: 'ET WEB_SERVER' },
  },
  {
    id: 'et-web-client',
    title: 'ET WEB_CLIENT — Web Client Attacks',
    source: 'suricata',
    severity: 'high',
    tags: ['web', 'browser', 'client', 'emerging-threats'],
    mitre: ['T1189', 'T1203'],
    summary: 'Malicious content targeting web browsers or client applications.',
    body: {
      what: 'Malicious content was detected in web traffic that targets the browser or other client applications — drive-by downloads, malicious JavaScript, exploit kits, or watering hole attacks.',
      why: 'ET WEB_CLIENT rules detect exploitation attempts directed at users browsing the web. The attack is in the response or the site content, not the user\'s request.',
      assess: 'High severity. If a user\'s browser received malicious content, the workstation may be compromised. Check if browser protections caught it.',
      action: '1. Identify the user and workstation that received the malicious content\n2. Check the URL/domain — is it a known malicious site?\n3. Run endpoint AV/EDR scan on the workstation\n4. Check browser history and determine if the exploit was successful\n5. Block the malicious domain/IP at your firewall or DNS',
      falsePositives: 'False positives in complex JavaScript (obfuscation that resembles exploit code). Ads with aggressive tracking scripts. Security research sites.',
    },
    statsKey: { source: 'suricata', category: 'ET WEB_CLIENT' },
  },

  // ── Wazuh / Clove ───────────────────────────────────────────────────────

  {
    id: 'wazuh-auth-failure',
    title: 'Authentication Failure (Wazuh)',
    source: 'wazuh',
    severity: 'medium',
    tags: ['auth', 'brute-force', 'credential-access'],
    mitre: ['T1110', 'T1078'],
    summary: 'Login attempt failed on a monitored endpoint.',
    body: {
      what: 'A login attempt failed on an endpoint monitored by Clove (Wazuh agent). This could be SSH, sudo, console, or application-level authentication.',
      why: 'Wazuh detects authentication failures from system logs (auth.log on Linux, Security Event Log on Windows). Repeated failures may indicate brute force.',
      assess: 'Medium severity for isolated failures. Escalate to high if you see many failures from the same source or targeting the same account.',
      action: '1. Check which account was targeted and from where\n2. If repeated failures: investigate for brute force\n3. Verify the account has a strong password\n4. Check if fail2ban/account lockout is protecting the service\n5. Review /var/log/auth.log or Windows Event 4625',
      falsePositives: 'Users forgetting passwords. Expired cached credentials. Service accounts with rotated passwords. Automated scripts with old credentials.',
    },
    statsKey: { source: 'wazuh', category: 'Authentication' },
  },
  {
    id: 'wazuh-syscheck',
    title: 'File Integrity Change (Syscheck)',
    source: 'wazuh',
    severity: 'medium',
    tags: ['fim', 'file-integrity', 'tampering'],
    mitre: ['T1565', 'T1036'],
    summary: 'A monitored file was added, modified, or deleted on an endpoint.',
    body: {
      what: 'Wazuh\'s syscheck (file integrity monitoring) detected that a file in a monitored directory was created, modified, or removed. This could indicate unauthorized changes.',
      why: 'FIM watches critical directories (/etc, /bin, /sbin, system32, etc.) for changes. Attackers often modify config files, add backdoors, or replace binaries.',
      assess: 'Medium severity. Most FIM changes are legitimate (package updates, config edits). Focus on unexpected changes to sensitive files like /etc/passwd, /etc/shadow, SSH configs, or system binaries.',
      action: '1. Check WHAT file changed — is it a critical system file?\n2. Check WHEN — was this during a known maintenance window?\n3. Check WHO — was there an authorized change process?\n4. Compare the old and new file hashes\n5. If unexpected, investigate the host for compromise',
      falsePositives: 'Package updates (apt/yum). Config management tools (Ansible, Puppet). Legitimate system administration. Log rotation. Temporary files.',
    },
    statsKey: { source: 'wazuh', category: 'syscheck' },
  },
  {
    id: 'wazuh-rootkit',
    title: 'Rootkit Detection (Wazuh)',
    source: 'wazuh',
    severity: 'critical',
    tags: ['rootkit', 'compromise', 'persistence'],
    mitre: ['T1014', 'T1547'],
    summary: 'Possible rootkit indicators detected on an endpoint.',
    body: {
      what: 'Wazuh\'s rootcheck module detected suspicious indicators that may suggest a rootkit is installed — hidden files, hidden processes, suspicious kernel modules, or known rootkit artifacts.',
      why: 'Rootkits operate at the OS kernel level to hide malicious activity. They can hide processes, files, network connections, and even modify system call behavior.',
      assess: 'Critical severity. Rootkit detection is a serious finding. However, rootcheck does produce false positives, so verification is essential.',
      action: '1. Do NOT reboot the host (may destroy evidence)\n2. Run additional rootkit scanners (rkhunter, chkrootkit) for confirmation\n3. Check for hidden processes: compare /proc listing with ps output\n4. Check for hidden network connections\n5. If confirmed, plan for full system rebuild — rootkits cannot be reliably removed',
      falsePositives: 'Some legitimate software hides files (e.g., .hidden directories). Container runtimes. Security tools that hook into the kernel. Outdated rootcheck signatures.',
    },
    statsKey: { source: 'wazuh', category: 'Rootkit' },
  },
  {
    id: 'wazuh-shell',
    title: 'Reverse Shell / Suspicious Shell (Wazuh)',
    source: 'wazuh',
    severity: 'critical',
    tags: ['reverse-shell', 'execution', 'c2'],
    mitre: ['T1059', 'T1071'],
    summary: 'Suspicious shell activity detected — possible reverse shell or unauthorized command execution.',
    body: {
      what: 'Wazuh custom rules detected patterns associated with reverse shells or suspicious shell activity — such as bash -i >& /dev/tcp/, python spawning shells, nc listeners, or encoded commands.',
      why: 'Reverse shells are the primary way attackers get interactive command access after exploiting a vulnerability. Detecting them is critical for catching active intrusions.',
      assess: 'Critical severity. A reverse shell typically means active attacker access to the host. Immediate investigation required.',
      action: '1. Identify the process and its parent process\n2. Check network connections — where is the reverse shell connecting?\n3. Kill the shell process\n4. Investigate how the shell was established (web exploit, SSH compromise, etc.)\n5. Check for persistence mechanisms left behind',
      falsePositives: 'Legitimate IT administration using remote shells. Docker/container exec. Development environments with nested shell sessions.',
    },
    statsKey: { source: 'wazuh', category: 'Reverse shell' },
  },
  {
    id: 'wazuh-download',
    title: 'Suspicious Download (Wazuh)',
    source: 'wazuh',
    severity: 'medium',
    tags: ['download', 'dropper', 'execution'],
    mitre: ['T1105', 'T1059'],
    summary: 'Suspicious file download detected via wget/curl/python to a sensitive directory.',
    body: {
      what: 'A download tool (wget, curl, python requests) was used to fetch a file to a directory that is unusual for legitimate downloads (/tmp, /dev/shm, writable web directories).',
      why: 'Attackers commonly download second-stage payloads after initial compromise using built-in tools. Downloads to /tmp or /dev/shm are a classic indicator.',
      assess: 'Medium severity. Context matters — was this a legitimate package install or a suspicious binary? Check what was downloaded and from where.',
      action: '1. Check what URL was fetched and what file was downloaded\n2. Examine the downloaded file — is it a known tool or binary?\n3. Check the process tree — what initiated the download?\n4. If suspicious, quarantine the file and investigate the host',
      falsePositives: 'Package installation scripts (pip, npm, apt). Docker image builds. Legitimate automation (CI/CD pipelines). Admin scripts fetching configs.',
    },
    statsKey: { source: 'wazuh', category: 'download' },
  },
  {
    id: 'wazuh-docker',
    title: 'Docker Security Event (Wazuh)',
    source: 'wazuh',
    severity: 'medium',
    tags: ['docker', 'container', 'escape'],
    mitre: ['T1610', 'T1611'],
    summary: 'Docker-related security event — privileged container, mount escape, or unusual activity.',
    body: {
      what: 'Wazuh detected a Docker security event — launching a privileged container, mounting the host filesystem, accessing Docker socket from within a container, or other container escape techniques.',
      why: 'Docker misconfigurations are a common attack vector. Privileged containers can escape to the host. Access to /var/run/docker.sock from inside a container grants host-level control.',
      assess: 'Medium-high severity depending on the specific event. Privileged containers and host mounts are significant risks.',
      action: '1. Review the Docker event details\n2. Check if the privileged/mount operation is authorized\n3. Verify container images are from trusted sources\n4. Review Docker daemon configuration for security settings\n5. Implement Docker security policies (AppArmor, seccomp, rootless)',
      falsePositives: 'Legitimate DevOps operations. CI/CD Docker-in-Docker builds. System containers that require host access by design.',
    },
    statsKey: { source: 'wazuh', category: 'docker' },
  },
  {
    id: 'wazuh-systemd',
    title: 'Systemd Service Change (Wazuh)',
    source: 'wazuh',
    severity: 'medium',
    tags: ['persistence', 'systemd', 'service'],
    mitre: ['T1543.002'],
    summary: 'New or modified systemd service unit detected — possible persistence mechanism.',
    body: {
      what: 'A systemd service unit file was created or modified. Attackers install malicious services for persistence — they survive reboots and run as system processes.',
      why: 'Wazuh FIM monitors /etc/systemd/system and /usr/lib/systemd/system for changes. New services or modifications to existing ones are flagged.',
      assess: 'Medium severity. Most service changes are legitimate (package installs, admin work). Unexpected new services or modifications to critical services warrant investigation.',
      action: '1. Check the service unit file — what binary does it run?\n2. Was a package recently installed that would explain this?\n3. Verify the binary pointed to by the service\n4. Check service status and logs: systemctl status <service> && journalctl -u <service>',
      falsePositives: 'Package installations that add services. System updates. Admin-created services. Docker/container management services.',
    },
    statsKey: { source: 'wazuh', category: 'systemd' },
  },
  {
    id: 'wazuh-priv-esc',
    title: 'Privilege Escalation Attempt (Wazuh)',
    source: 'wazuh',
    severity: 'high',
    tags: ['privilege-escalation', 'sudo', 'suid'],
    mitre: ['T1548', 'T1548.001', 'T1068'],
    summary: 'Attempt to escalate privileges via sudo abuse, SUID exploitation, or kernel exploit.',
    body: {
      what: 'Wazuh detected patterns associated with privilege escalation — unauthorized sudo usage, SUID binary abuse, kernel exploit indicators, or capabilities manipulation.',
      why: 'After initial access, attackers need root/admin privileges. Privilege escalation is a critical attack phase that enables full system control.',
      assess: 'High severity. Even if the attempt failed, it indicates an attacker has access and is actively trying to escalate.',
      action: '1. Identify the user account involved\n2. Check sudo logs: grep sudo /var/log/auth.log\n3. Audit SUID binaries: find / -perm -4000 -type f\n4. Check for recently modified SUID binaries\n5. Review the kernel version for known local privilege escalation CVEs',
      falsePositives: 'Legitimate sudo usage by admins. Package installations that set SUID bits. Security tools checking for SUID binaries.',
    },
    statsKey: { source: 'wazuh', category: 'Privilege escalation' },
  },

  // ── Argus Sentinel ──────────────────────────────────────────────────────

  {
    id: 'argus-state-change',
    title: 'Argus State Change',
    source: 'argus',
    severity: 'low',
    tags: ['endpoint', 'state', 'monitoring'],
    mitre: [],
    summary: 'Endpoint state transition detected (idle, active, locked, etc.).',
    body: {
      what: 'The Argus sentinel detected a state change on a monitored Windows endpoint — transitions between active, idle, locked, and away states.',
      why: 'Tracking endpoint state helps establish usage patterns. Unexpected state changes (e.g., active at 3 AM) can indicate unauthorized access.',
      assess: 'Low severity. These are informational baseline events. Review for anomalous patterns (unusual hours, unexpected unlocks).',
      action: '1. No immediate action needed for routine state changes\n2. Review patterns over time for anomalies\n3. Investigate active states during unexpected hours\n4. Correlate with other security events around the same time',
      falsePositives: 'Scheduled tasks waking the machine. Windows Update. Remote administration.',
    },
    statsKey: { source: 'argus', category: 'state_change' },
  },
  {
    id: 'argus-credential-access',
    title: 'Argus Credential File Access',
    source: 'argus',
    severity: 'high',
    tags: ['credentials', 'access', 'theft'],
    mitre: ['T1555', 'T1552'],
    summary: 'Sensitive credential files accessed — KeePassXC databases, SSH keys, browser profiles.',
    body: {
      what: 'Argus detected access to credential-related files: KeePassXC database files (.kdbx), SSH private keys, browser credential stores, or other sensitive credential material.',
      why: 'Credential theft is a key objective for attackers. Monitoring access to credential files provides early warning of credential harvesting attempts.',
      assess: 'High severity. Even if the access is legitimate (user opening their password manager), unexpected access patterns or access by unusual processes warrant investigation.',
      action: '1. Check which process accessed the credential file\n2. Was it the expected application (KeePassXC for .kdbx, etc.)?\n3. If an unexpected process, investigate immediately\n4. Check for credential exfiltration (file copy, network transfer)\n5. Consider rotating credentials if unauthorized access occurred',
      falsePositives: 'Normal use of password managers. SSH key usage. Browser auto-fill. Backup software reading credential files.',
    },
    statsKey: { source: 'argus', category: 'credential_access' },
  },
  {
    id: 'argus-logon-failure',
    title: 'Argus Failed Logon (Event 4625)',
    source: 'argus',
    severity: 'medium',
    tags: ['logon', 'failure', 'windows', 'brute-force'],
    mitre: ['T1110'],
    summary: 'Windows logon failure detected — possible brute force or credential stuffing.',
    body: {
      what: 'Argus detected a Windows failed logon event (Event ID 4625). This includes local console logins, RDP, network logins, and service account authentications.',
      why: 'Windows Event 4625 captures all failed authentication attempts. Repeated failures indicate brute force or credential attacks.',
      assess: 'Medium severity for isolated failures. High severity for repeated failures from the same source or targeting the same account.',
      action: '1. Check the logon type (interactive, RDP, network)\n2. Check the source IP/hostname\n3. If repeated, implement account lockout\n4. If RDP: is RDP exposed? Consider VPN requirement\n5. Check for related 4625 events in a time cluster',
      falsePositives: 'Stale credentials in mapped drives. Service accounts with expired passwords. Users locking themselves out. Domain trust issues.',
    },
    statsKey: { source: 'argus', category: 'logon_failure' },
  },
  {
    id: 'argus-account-change',
    title: 'Argus Account/Group Change',
    source: 'argus',
    severity: 'high',
    tags: ['account', 'group', 'persistence'],
    mitre: ['T1136', 'T1098'],
    summary: 'Windows account created, modified, or group membership changed (4720/4728/4732).',
    body: {
      what: 'Argus detected a Windows account management event — new account creation (4720), account modification, or group membership changes (4728 local group, 4732 global group).',
      why: 'Attackers create accounts or add themselves to privileged groups for persistence and privilege escalation.',
      assess: 'High severity. Account changes should be tracked and correlated with authorized change requests. Unexpected admin group additions are critical.',
      action: '1. Verify the change was authorized\n2. Check who made the change (Subject Account in the event)\n3. If a new account: is it needed? Who requested it?\n4. If a group change: was the user authorized for this group?\n5. Review all recent 4720/4728/4732 events for patterns',
      falsePositives: 'IT admin performing authorized account management. Domain join processes. Service account provisioning. Group policy applying changes.',
    },
    statsKey: { source: 'argus', category: 'account_change' },
  },
  {
    id: 'argus-usb',
    title: 'Argus USB Device',
    source: 'argus',
    severity: 'medium',
    tags: ['usb', 'physical', 'exfiltration'],
    mitre: ['T1052', 'T1200'],
    summary: 'USB device connected or disconnected from a monitored endpoint.',
    body: {
      what: 'A USB storage device or other USB peripheral was connected to or disconnected from a monitored Windows endpoint.',
      why: 'USB devices can be used for data exfiltration, malware delivery (rubber ducky, USB drops), or unauthorized data transfer.',
      assess: 'Medium severity. Context matters — known user plugging in their flash drive vs. unknown USB activity on a server.',
      action: '1. Identify the device (vendor, product, serial number from event details)\n2. Is this a known, authorized device?\n3. Check what files were accessed/copied after connection\n4. For servers: USB storage connections are usually unauthorized\n5. Consider implementing USB device control policies',
      falsePositives: 'Authorized USB keyboards/mice. Charging cables detected as storage. Known user flash drives. Hardware security keys (YubiKey).',
    },
    statsKey: { source: 'argus', category: 'usb' },
  },
  {
    id: 'argus-rdp-session',
    title: 'Argus RDP Session',
    source: 'argus',
    severity: 'medium',
    tags: ['rdp', 'remote', 'session'],
    mitre: ['T1021.001'],
    summary: 'RDP session started or ended on a monitored endpoint.',
    body: {
      what: 'Argus detected a Remote Desktop Protocol session event — connection, disconnection, or reconnection on a monitored Windows endpoint.',
      why: 'RDP is a common lateral movement and remote access technique. Monitoring sessions helps detect unauthorized remote access.',
      assess: 'Medium severity. Check if the RDP session is from an expected source. Unexpected RDP sessions, especially from external IPs, are high severity.',
      action: '1. Verify the source IP of the RDP session\n2. Is this an authorized user and expected access?\n3. Check session timing — is it during normal hours?\n4. Review what was done during the session\n5. If unauthorized, terminate the session and investigate',
      falsePositives: 'IT admin remote support. Authorized remote workers. Automated RDP-based management tools.',
    },
    statsKey: { source: 'argus', category: 'rdp_session' },
  },
  {
    id: 'argus-anti-tamper',
    title: 'Argus Anti-Tamper Alert',
    source: 'argus',
    severity: 'critical',
    tags: ['tamper', 'evasion', 'defense-evasion'],
    mitre: ['T1562', 'T1562.001'],
    summary: 'Someone attempted to stop, disable, or modify the Argus agent.',
    body: {
      what: 'The Argus anti-tamper system detected an attempt to interfere with the agent — service stop, process kill, binary modification, or config change.',
      why: 'Attackers disable security tools to avoid detection. Argus has anti-tamper that detects and reports these attempts.',
      assess: 'Critical severity. Tampering with security agents is a strong indicator of active compromise. The attacker is trying to blind your monitoring.',
      action: '1. Immediately investigate the endpoint\n2. Determine what process or user attempted the tampering\n3. Check if Argus is still running and reporting\n4. Look for other security tools being disabled (AV, firewall)\n5. Treat this as an active incident — begin incident response',
      falsePositives: 'IT admin performing authorized maintenance on the agent. System updates that touch the service. Accidental service manager operations.',
    },
    statsKey: { source: 'argus', category: 'anti_tamper' },
  },

  // ── CrowdSec ────────────────────────────────────────────────────────────

  {
    id: 'crowdsec-ban',
    title: 'CrowdSec Ban',
    source: 'crowdsec',
    severity: 'medium',
    tags: ['ban', 'firewall', 'community'],
    mitre: ['T1110', 'T1595'],
    summary: 'IP was banned by CrowdSec based on community threat intelligence or local detection.',
    body: {
      what: 'CrowdSec has banned an IP address — either because the IP was detected performing malicious activity locally, or it appears on the CrowdSec community blocklist.',
      why: 'CrowdSec combines local behavior detection with community-shared threat intelligence. When an IP is banned, the firewall bouncer blocks all traffic from it.',
      assess: 'Medium severity. The ban is working as intended — the threat was mitigated. Review what the IP was doing before being banned.',
      action: '1. Check CrowdSec decisions: cscli decisions list\n2. Review the reason for the ban (scenario/reputation)\n3. If community ban: the IP was flagged by other CrowdSec users\n4. If local detection: check what triggered the local scenario\n5. No further action needed if the ban is appropriate',
      falsePositives: 'Shared IPs (NAT, VPN exits) may be banned due to other users\' behavior. Dynamic IPs that were reassigned after a ban. Cloud provider IPs.',
    },
    statsKey: { source: 'crowdsec', category: 'ban' },
  },
  {
    id: 'crowdsec-captcha',
    title: 'CrowdSec Captcha Challenge',
    source: 'crowdsec',
    severity: 'low',
    tags: ['captcha', 'challenge', 'bot'],
    mitre: ['T1595'],
    summary: 'IP received a captcha challenge instead of a ban — potential bot detection.',
    body: {
      what: 'CrowdSec issued a captcha challenge to an IP. This is a softer response than a ban — the IP is suspicious but not definitively malicious. Legitimate users can solve the captcha.',
      why: 'Captcha decisions allow CrowdSec to slow down suspicious IPs without blocking legitimate users who might be on shared infrastructure.',
      assess: 'Low severity. The mitigation is in place. This is informational.',
      action: '1. Monitor if the IP escalates from captcha to ban\n2. Check if legitimate users are being challenged inappropriately\n3. Review CrowdSec scenarios to tune sensitivity if needed',
      falsePositives: 'Legitimate users on shared IPs. Search engine crawlers. Aggressive but legitimate scrapers.',
    },
    statsKey: { source: 'crowdsec', category: 'captcha' },
  },
  {
    id: 'crowdsec-throttle',
    title: 'CrowdSec Throttle',
    source: 'crowdsec',
    severity: 'low',
    tags: ['throttle', 'rate-limit'],
    mitre: ['T1498'],
    summary: 'IP is being rate-limited by CrowdSec due to excessive requests.',
    body: {
      what: 'CrowdSec is throttling (rate-limiting) requests from an IP that is generating excessive traffic, but not enough to warrant a full ban.',
      why: 'Throttling slows down potential attacks without completely blocking potentially legitimate traffic. It is a graduated response.',
      assess: 'Low severity. The mitigation is active and proportional.',
      action: '1. Monitor for escalation\n2. Check if the throttled IP is a legitimate service\n3. Adjust CrowdSec rate limits if too aggressive for your traffic patterns',
      falsePositives: 'High-traffic legitimate users. API clients with aggressive retry logic. CDN health checks.',
    },
    statsKey: { source: 'crowdsec', category: 'throttle' },
  },
  {
    id: 'crowdsec-challenge',
    title: 'CrowdSec Generic Challenge',
    source: 'crowdsec',
    severity: 'low',
    tags: ['challenge', 'verification'],
    mitre: ['T1595'],
    summary: 'IP received a generic challenge from CrowdSec for verification.',
    body: {
      what: 'CrowdSec issued a non-specific challenge to an IP. This is a verification mechanism that may include JavaScript challenges, rate limiting, or other soft mitigations.',
      why: 'Generic challenges are used when CrowdSec is uncertain about intent. They allow legitimate traffic through while impeding automated attacks.',
      assess: 'Low severity. Informational — CrowdSec is actively protecting the endpoint.',
      action: '1. No immediate action needed\n2. Monitor for escalation patterns\n3. Review if challenges are impacting legitimate users',
      falsePositives: 'Same as captcha — shared IPs, crawlers, legitimate automation.',
    },
    statsKey: { source: 'crowdsec', category: 'challenge' },
  },

  // ── pfSense ─────────────────────────────────────────────────────────────

  {
    id: 'pfsense-block',
    title: 'pfSense Firewall Block',
    source: 'pfsense',
    severity: 'low',
    tags: ['firewall', 'block', 'network'],
    mitre: ['T1046', 'T1595'],
    summary: 'pfSense firewall blocked traffic — this is normal operation showing what your firewall stops.',
    body: {
      what: 'The pfSense firewall blocked inbound or outbound traffic based on its ruleset. These logs show what is being stopped at the network perimeter.',
      why: 'Firewall block logs are the most common alert type. They show reconnaissance attempts, blocked attacks, and policy enforcement working as designed.',
      assess: 'Low severity individually. High volume of blocks from the same source or to the same port may indicate a targeted attack being mitigated. These are "good news" alerts — your firewall is working.',
      action: '1. Review for patterns — same source hitting multiple ports?\n2. Check if any blocked traffic should have been allowed (misconfigured rules)\n3. For persistent external sources, consider adding them to a blocklist\n4. Use these logs to validate your firewall rules are effective',
      falsePositives: 'This is the firewall doing its job. All blocked traffic appears here. Internet background noise (constant scanning) generates high volumes.',
    },
    statsKey: { source: 'pfsense' },
  },

  // ── Pi-hole ─────────────────────────────────────────────────────────────

  {
    id: 'pihole-blocklist',
    title: 'Pi-hole Blocklist Hit',
    source: 'pihole',
    severity: 'low',
    tags: ['dns', 'blocklist', 'tracking'],
    mitre: ['T1071.004'],
    summary: 'DNS query blocked by Pi-hole because the domain is on a blocklist.',
    body: {
      what: 'A DNS query was blocked because the requested domain appears on one of Pi-hole\'s configured blocklists. This is typically ad/tracker domains but can include malware domains.',
      why: 'Pi-hole acts as a DNS sinkhole, blocking known ad, tracking, and malware domains at the DNS level. Blocked queries never reach the destination.',
      assess: 'Low severity for ad/tracking domains. Medium severity if the domain is on a malware blocklist — check which blocklist triggered.',
      action: '1. Check which blocklist contains the domain\n2. If it is a malware domain: identify which host made the query\n3. If a legitimate domain was blocked: whitelist it\n4. Review Pi-hole query log for patterns',
      falsePositives: 'Overly aggressive blocklists that include CDN or legitimate service domains. New services not yet whitelisted. Regional content delivery domains.',
    },
    statsKey: { source: 'pihole', category: 'blocklist' },
  },
  {
    id: 'pihole-regex',
    title: 'Pi-hole Regex Deny',
    source: 'pihole',
    severity: 'low',
    tags: ['dns', 'regex', 'blocklist'],
    mitre: ['T1071.004'],
    summary: 'DNS query blocked by a Pi-hole regex deny rule.',
    body: {
      what: 'A DNS query was blocked by a custom regex rule in Pi-hole. These are more targeted than blocklists and usually match patterns like specific TLDs or known DGA (domain generation algorithm) patterns.',
      why: 'Regex rules catch domains that don\'t appear on static blocklists but match suspicious patterns — random-looking domains, known malicious TLDs, etc.',
      assess: 'Low severity for ad patterns. Medium if the regex targets DGA or malware patterns — the querying host may be compromised.',
      action: '1. Check which regex rule matched\n2. Verify the blocked domain — is it suspicious or a false positive?\n3. If DGA pattern: investigate the source host for malware\n4. Adjust regex rules if they are causing false positives',
      falsePositives: 'Overly broad regex patterns. Legitimate domains with random-looking subdomains (CDNs, SaaS services).',
    },
    statsKey: { source: 'pihole', category: 'regex' },
  },
  {
    id: 'pihole-cname',
    title: 'Pi-hole CNAME Block',
    source: 'pihole',
    severity: 'low',
    tags: ['dns', 'cname', 'tracking'],
    mitre: ['T1071.004'],
    summary: 'DNS query blocked because the CNAME chain resolves to a blocked domain.',
    body: {
      what: 'A DNS query was allowed initially, but the CNAME (canonical name) chain eventually pointed to a blocked domain. Pi-hole followed the chain and blocked it.',
      why: 'Some trackers and ad services use CNAME cloaking — hiding behind legitimate-looking first-party domains that CNAME to tracking infrastructure.',
      assess: 'Low severity. CNAME cloaking is primarily a tracking/privacy concern rather than a security threat, but can also be used by malware.',
      action: '1. Check the CNAME chain to understand the blocking\n2. Verify the end domain is actually undesirable\n3. If legitimate, whitelist the original domain\n4. Consider if CNAME-based blocking is too aggressive for your needs',
      falsePositives: 'Legitimate services that happen to use CDNs or infrastructure providers that are on blocklists. First-party CNAME setups for analytics.',
    },
    statsKey: { source: 'pihole', category: 'cname' },
  },

  // ── Syslog ──────────────────────────────────────────────────────────────

  {
    id: 'syslog-auth',
    title: 'Syslog Authentication Event',
    source: 'syslog',
    severity: 'medium',
    tags: ['auth', 'syslog', 'login'],
    mitre: ['T1078', 'T1110'],
    summary: 'Authentication event received via syslog from a network device or server.',
    body: {
      what: 'An authentication event (success or failure) was received via the syslog receiver from a network device, server, or other syslog-capable system.',
      why: 'Many network devices (routers, switches, access points) send authentication events via syslog. These provide visibility into login activity across infrastructure.',
      assess: 'Medium severity for failures, low for successes. Correlate with other auth events for brute force detection. Device-level authentication failures can indicate network compromise attempts.',
      action: '1. Identify the source device\n2. Check if the auth event is a success or failure\n3. For failures: check for repeated attempts (brute force)\n4. For successes: verify the login was authorized\n5. Review device access policies',
      falsePositives: 'SNMP polling triggering auth events. Monitoring tools authenticating frequently. Stale credentials in network management systems.',
    },
    statsKey: { source: 'syslog', category: 'auth' },
  },
  {
    id: 'syslog-kern',
    title: 'Syslog Kernel Message',
    source: 'syslog',
    severity: 'medium',
    tags: ['kernel', 'syslog', 'hardware'],
    mitre: ['T1499', 'T1498'],
    summary: 'Kernel-level message received via syslog — hardware errors, OOM kills, or security events.',
    body: {
      what: 'A kernel-level log message was received via syslog. These include hardware failures, out-of-memory (OOM) kills, storage errors, network interface issues, and kernel security events.',
      why: 'Kernel messages often indicate infrastructure problems that could affect security monitoring. OOM kills can be caused by DoS attacks. Hardware failures can compromise system integrity.',
      assess: 'Medium severity. Depends on the specific kernel message. OOM kills, disk errors, and network failures deserve investigation.',
      action: '1. Read the specific kernel message in the alert details\n2. For OOM: check what process was killed and why memory is exhausted\n3. For disk errors: check storage health (smartctl, dmesg)\n4. For network: check interface status and connectivity\n5. For security: check for kernel exploit indicators',
      falsePositives: 'Normal kernel informational messages. Hardware experiencing expected load. Driver update messages.',
    },
    statsKey: { source: 'syslog', category: 'kern' },
  },

  // ── Protocol Anomalies ──────────────────────────────────────────────────

  {
    id: 'suricata-applayer',
    title: 'Suricata Application Layer Anomaly',
    source: 'suricata',
    severity: 'medium',
    tags: ['anomaly', 'protocol', 'evasion'],
    mitre: ['T1001', 'T1071'],
    summary: 'Protocol parser detected malformed or anomalous traffic that does not conform to standards.',
    body: {
      what: 'Suricata\'s application-layer protocol parsers detected traffic that does not conform to the expected protocol specification — malformed HTTP, invalid TLS, unusual DNS, etc.',
      why: 'Protocol anomalies can indicate: exploitation attempts using malformed packets, evasion techniques, tunneling protocols inside others, or simply buggy software.',
      assess: 'Medium severity. Many anomalies are benign (buggy IoT devices, old software). However, sophisticated attacks often produce protocol anomalies as they exploit parser differences.',
      action: '1. Check the specific protocol and anomaly type\n2. Identify the source and destination\n3. For HTTP anomalies: check the full request for exploit patterns\n4. For TLS anomalies: check cert validity and cipher suites\n5. For DNS anomalies: check for tunneling indicators',
      falsePositives: 'IoT devices with non-standard protocol implementations. Legacy software. Load balancers modifying traffic. VPN/tunnel encapsulation.',
    },
    statsKey: { source: 'suricata', category: 'applayer' },
  },
];

// ── Source metadata for grouping ──────────────────────────────────────────────

const WIKI_GROUPS = [
  { key: 'suricata-custom',  label: 'Suricata Custom Rules',   icon: 'suricata',  filter: a => a.source === 'suricata' && a.id.startsWith('suricata-9') },
  { key: 'suricata-et',      label: 'Suricata ET Categories',  icon: 'suricata',  filter: a => a.source === 'suricata' && a.id.startsWith('et-') },
  { key: 'suricata-anomaly', label: 'Protocol Anomalies',      icon: 'suricata',  filter: a => a.id === 'suricata-applayer' },
  { key: 'wazuh',            label: 'Wazuh / Clove',           icon: 'wazuh',     filter: a => a.source === 'wazuh' },
  { key: 'argus',            label: 'Argus Sentinel',          icon: 'argus',     filter: a => a.source === 'argus' },
  { key: 'crowdsec',         label: 'CrowdSec',                icon: 'crowdsec',  filter: a => a.source === 'crowdsec' },
  { key: 'pfsense',          label: 'pfSense',                 icon: 'pfsense',   filter: a => a.source === 'pfsense' },
  { key: 'pihole',           label: 'Pi-hole',                 icon: 'pihole',    filter: a => a.source === 'pihole' },
  { key: 'syslog',           label: 'Syslog',                  icon: 'syslog',    filter: a => a.source === 'syslog' },
];

// ── Wiki state ────────────────────────────────────────────────────────────────

const wikiState = {
  open: false,
  view: 'index',       // 'index' | 'article'
  currentArticle: null,
  searchQuery: '',
};

// ── Resolve alert → wiki article ──────────────────────────────────────────────

function resolveWikiArticle(alert) {
  if (!alert) return null;
  const sigId = alert.signature_id;
  const source = (alert.source || '').toLowerCase();
  const category = (alert.category || '').toUpperCase();
  const title = (alert.title || '').toUpperCase();

  // 1. Exact signature_id match (Suricata SIDs, Wazuh rule IDs)
  if (sigId) {
    const exact = WIKI_ARTICLES.find(a =>
      a.statsKey.signature_id && a.statsKey.signature_id === sigId
    );
    if (exact) return exact;
  }

  // 2. Source + category prefix match
  const combined = title + ' ' + category;
  const categoryMatches = [
    { prefix: 'ET MALWARE',    id: 'et-malware' },
    { prefix: 'ET TROJAN',     id: 'et-trojan' },
    { prefix: 'ET EXPLOIT',    id: 'et-exploit' },
    { prefix: 'ET SCAN',       id: 'et-scan' },
    { prefix: 'ET INFO',       id: 'et-info' },
    { prefix: 'ET POLICY',     id: 'et-policy' },
    { prefix: 'ET DOS',        id: 'et-dos' },
    { prefix: 'ET WEB_SERVER', id: 'et-web-server' },
    { prefix: 'ET WEB_CLIENT', id: 'et-web-client' },
  ];

  for (const { prefix, id } of categoryMatches) {
    if (combined.includes(prefix)) {
      return WIKI_ARTICLES.find(a => a.id === id) || null;
    }
  }

  // Wazuh category matching
  if (source === 'wazuh') {
    const wazuhMap = [
      { pattern: 'AUTHENTICATION',     id: 'wazuh-auth-failure' },
      { pattern: 'SYSCHECK',           id: 'wazuh-syscheck' },
      { pattern: 'FILE INTEGRITY',     id: 'wazuh-syscheck' },
      { pattern: 'ROOTKIT',            id: 'wazuh-rootkit' },
      { pattern: 'REVERSE SHELL',      id: 'wazuh-shell' },
      { pattern: 'DOWNLOAD',           id: 'wazuh-download' },
      { pattern: 'DOCKER',             id: 'wazuh-docker' },
      { pattern: 'SYSTEMD',            id: 'wazuh-systemd' },
      { pattern: 'PRIVILEGE',          id: 'wazuh-priv-esc' },
    ];
    for (const { pattern, id } of wazuhMap) {
      if (combined.includes(pattern)) return WIKI_ARTICLES.find(a => a.id === id) || null;
    }
  }

  // Argus category matching
  if (source === 'argus') {
    const argusMap = [
      { pattern: 'STATE_CHANGE',    id: 'argus-state-change' },
      { pattern: 'CREDENTIAL',      id: 'argus-credential-access' },
      { pattern: 'LOGON_FAILURE',   id: 'argus-logon-failure' },
      { pattern: 'FAILED LOGON',    id: 'argus-logon-failure' },
      { pattern: '4625',            id: 'argus-logon-failure' },
      { pattern: 'ACCOUNT',         id: 'argus-account-change' },
      { pattern: '4720',            id: 'argus-account-change' },
      { pattern: '4728',            id: 'argus-account-change' },
      { pattern: '4732',            id: 'argus-account-change' },
      { pattern: 'USB',             id: 'argus-usb' },
      { pattern: 'RDP',             id: 'argus-rdp-session' },
      { pattern: 'ANTI_TAMPER',     id: 'argus-anti-tamper' },
      { pattern: 'TAMPER',          id: 'argus-anti-tamper' },
    ];
    for (const { pattern, id } of argusMap) {
      if (combined.includes(pattern)) return WIKI_ARTICLES.find(a => a.id === id) || null;
    }
  }

  // CrowdSec
  if (source === 'crowdsec') {
    const csMap = [
      { pattern: 'BAN',       id: 'crowdsec-ban' },
      { pattern: 'CAPTCHA',   id: 'crowdsec-captcha' },
      { pattern: 'THROTTLE',  id: 'crowdsec-throttle' },
      { pattern: 'CHALLENGE', id: 'crowdsec-challenge' },
    ];
    for (const { pattern, id } of csMap) {
      if (combined.includes(pattern)) return WIKI_ARTICLES.find(a => a.id === id) || null;
    }
  }

  // Pi-hole
  if (source === 'pihole') {
    if (combined.includes('CNAME'))     return WIKI_ARTICLES.find(a => a.id === 'pihole-cname');
    if (combined.includes('REGEX'))     return WIKI_ARTICLES.find(a => a.id === 'pihole-regex');
    return WIKI_ARTICLES.find(a => a.id === 'pihole-blocklist');
  }

  // pfSense
  if (source === 'pfsense') return WIKI_ARTICLES.find(a => a.id === 'pfsense-block');

  // Syslog
  if (source === 'syslog') {
    if (combined.includes('AUTH')) return WIKI_ARTICLES.find(a => a.id === 'syslog-auth');
    if (combined.includes('KERN')) return WIKI_ARTICLES.find(a => a.id === 'syslog-kern');
    return WIKI_ARTICLES.find(a => a.id === 'syslog-auth');
  }

  // Applayer anomalies
  if (combined.includes('APPLAYER') || combined.includes('ANOMALY')) {
    return WIKI_ARTICLES.find(a => a.id === 'suricata-applayer');
  }

  return null;
}

// ── UI Rendering ──────────────────────────────────────────────────────────────

function openWiki(articleId) {
  wikiState.open = true;
  const overlay = document.getElementById('wiki-overlay');
  overlay.style.display = 'block';
  document.body.style.overflow = 'hidden';

  if (articleId) {
    const article = WIKI_ARTICLES.find(a => a.id === articleId);
    if (article) {
      showWikiArticle(article);
      return;
    }
  }
  showWikiIndex();
}

function closeWiki() {
  wikiState.open = false;
  const overlay = document.getElementById('wiki-overlay');
  overlay.style.display = 'none';
  document.body.style.overflow = '';
}

function showWikiIndex() {
  wikiState.view = 'index';
  wikiState.currentArticle = null;
  const body = document.getElementById('wiki-body');
  const query = wikiState.searchQuery.toLowerCase().trim();

  let html = `<div class="wiki-search-wrap">
    <input type="search" id="wiki-search" class="wiki-search" placeholder="Search articles by title, tags, or MITRE ID..." value="${escHtml(wikiState.searchQuery)}" autocomplete="off" spellcheck="false" />
  </div>`;

  for (const group of WIKI_GROUPS) {
    let articles = WIKI_ARTICLES.filter(group.filter);
    if (query) {
      articles = articles.filter(a => {
        const hay = (a.title + ' ' + a.summary + ' ' + a.tags.join(' ') + ' ' + a.mitre.join(' ')).toLowerCase();
        return hay.includes(query);
      });
    }
    if (!articles.length) continue;

    html += `<div class="wiki-group">
      <div class="wiki-group-header">
        <span class="badge badge-src-${group.icon}">${escHtml(group.label)}</span>
        <span class="wiki-group-count">${articles.length}</span>
      </div>
      <div class="wiki-grid">`;

    for (const a of articles) {
      const sevClass = `badge-sev-${a.severity}`;
      html += `<div class="wiki-card" data-article-id="${a.id}">
        <div class="wiki-card-header">
          <span class="badge ${sevClass}">${a.severity}</span>
          <span class="wiki-card-title">${escHtml(a.title)}</span>
        </div>
        <div class="wiki-card-summary">${escHtml(a.summary)}</div>
        <div class="wiki-card-tags">${a.mitre.map(m => `<span class="wiki-mitre-tag">${m}</span>`).join('')}${a.tags.slice(0, 3).map(t => `<span class="wiki-tag">${escHtml(t)}</span>`).join('')}</div>
      </div>`;
    }

    html += `</div></div>`;
  }

  // No results
  if (query && !html.includes('wiki-card')) {
    html += `<div class="empty-state-smart">
      <div class="empty-icon">📚</div>
      <div class="empty-title">No articles found</div>
      <div class="empty-desc">No wiki articles match "${escHtml(query)}". Try a different search term.</div>
    </div>`;
  }

  body.innerHTML = html;

  // Wire search
  const searchInput = document.getElementById('wiki-search');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      wikiState.searchQuery = searchInput.value;
      showWikiIndex();
      // Refocus and restore cursor
      const newInput = document.getElementById('wiki-search');
      if (newInput) {
        newInput.focus();
        newInput.setSelectionRange(newInput.value.length, newInput.value.length);
      }
    });
  }

  // Wire card clicks
  body.querySelectorAll('.wiki-card').forEach(card => {
    card.addEventListener('click', () => {
      const article = WIKI_ARTICLES.find(a => a.id === card.dataset.articleId);
      if (article) showWikiArticle(article);
    });
  });
}

function showWikiArticle(article) {
  wikiState.view = 'article';
  wikiState.currentArticle = article;
  const body = document.getElementById('wiki-body');

  const sevClass = `badge-sev-${article.severity}`;
  const b = article.body;

  let html = `
    <button class="wiki-back" id="wiki-back">&larr; Back to index</button>
    <div class="wiki-article">
      <div class="wiki-article-header">
        <span class="badge badge-src-${article.source}">${article.source}</span>
        <span class="badge ${sevClass}">${article.severity}</span>
        <h2 class="wiki-article-title">${escHtml(article.title)}</h2>
      </div>
      <div class="wiki-article-tags">
        ${article.mitre.map(m => `<a class="wiki-mitre-tag clickable" href="https://attack.mitre.org/techniques/${m.replace('.', '/')}" target="_blank" rel="noopener">${m}</a>`).join('')}
        ${article.tags.map(t => `<span class="wiki-tag">${escHtml(t)}</span>`).join('')}
      </div>

      <div class="wiki-stats-strip" id="wiki-stats-strip">
        <span class="loading-spinner"></span> Loading stats...
      </div>

      <section class="wiki-section">
        <h3>What this alert means</h3>
        <p>${escHtml(b.what)}</p>
      </section>

      <section class="wiki-section">
        <h3>Why it fires</h3>
        <p>${escHtml(b.why)}</p>
      </section>

      <section class="wiki-section">
        <h3>Severity assessment</h3>
        <p>${escHtml(b.assess)}</p>
      </section>

      <section class="wiki-section">
        <h3>What to do</h3>
        <div class="wiki-action-steps">${formatSteps(b.action)}</div>
      </section>

      <section class="wiki-section">
        <h3>Common false positives</h3>
        <p>${escHtml(b.falsePositives)}</p>
      </section>

      <div class="wiki-recent" id="wiki-recent">
        <h3>Recent examples</h3>
        <div class="wiki-recent-table"><span class="loading-spinner"></span> Loading...</div>
      </div>

      <div class="wiki-ai-section">
        <h3>Ask AI about this topic</h3>
        <div class="wiki-ai-chat" id="wiki-ai-chat"></div>
        <div class="wiki-ai-input-wrap">
          <input type="text" id="wiki-ai-input" class="wiki-ai-input" placeholder="Ask anything about ${escHtml(article.title)}..." />
          <button class="btn wiki-ai-send" id="wiki-ai-send">Ask AI</button>
        </div>
      </div>
    </div>`;

  body.innerHTML = html;

  // Wire back button
  document.getElementById('wiki-back').addEventListener('click', () => showWikiIndex());

  // Wire AI question
  wireWikiAi(article);

  // Fetch live stats
  fetchWikiStats(article);
  fetchWikiRecent(article);
}

function formatSteps(text) {
  // Convert numbered lines to an ordered list
  const lines = text.split('\n').filter(l => l.trim());
  if (lines.length > 1 && /^\d+\./.test(lines[0].trim())) {
    return '<ol>' + lines.map(l => `<li>${escHtml(l.replace(/^\d+\.\s*/, ''))}</li>`).join('') + '</ol>';
  }
  return `<p>${escHtml(text)}</p>`;
}

async function fetchWikiStats(article) {
  const strip = document.getElementById('wiki-stats-strip');
  if (!strip) return;

  const params = new URLSearchParams();
  const sk = article.statsKey;
  if (sk.source) params.set('source', sk.source);
  if (sk.signature_id) params.set('signature_id', sk.signature_id);
  if (sk.category) params.set('category', sk.category);

  try {
    const res = await fetch(`/api/wiki/stats?${params}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const total = (data.total || 0).toLocaleString();
    const first = data.first_seen ? fmtTime(data.first_seen) : 'N/A';
    const last = data.last_seen ? fmtTime(data.last_seen) : 'N/A';
    const lastRel = data.last_seen ? fmtRelative(data.last_seen) : '';

    strip.innerHTML = `
      <div class="wiki-stat"><span class="wiki-stat-label">Total</span><span class="wiki-stat-value">${total}</span></div>
      <div class="wiki-stat"><span class="wiki-stat-label">First seen</span><span class="wiki-stat-value">${first}</span></div>
      <div class="wiki-stat"><span class="wiki-stat-label">Last seen</span><span class="wiki-stat-value">${last}${lastRel ? ` (${lastRel})` : ''}</span></div>`;
  } catch {
    strip.innerHTML = `<span class="wiki-stat-empty">Stats unavailable</span>`;
  }
}

async function fetchWikiRecent(article) {
  const container = document.getElementById('wiki-recent');
  if (!container) return;

  const params = new URLSearchParams({ limit: '5' });
  const sk = article.statsKey;
  if (sk.source) params.set('source', sk.source);
  if (sk.signature_id) params.set('signature_id', sk.signature_id);
  if (sk.category) params.set('category', sk.category);

  try {
    const res = await fetch(`/api/wiki/recent?${params}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const rows = data.recent || [];

    if (!rows.length) {
      container.querySelector('.wiki-recent-table').innerHTML = '<div class="wiki-stat-empty">No recent alerts of this type</div>';
      return;
    }

    let tableHtml = `<table class="wiki-examples-table">
      <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Title</th><th>Severity</th><th>Verdict</th></tr></thead>
      <tbody>`;

    for (const r of rows) {
      tableHtml += `<tr>
        <td>${fmtTime(r.timestamp)}</td>
        <td class="mono">${escHtml(r.src_ip || '—')}</td>
        <td class="mono">${escHtml(r.dst_ip || '—')}</td>
        <td>${escHtml((r.title || '').slice(0, 60))}</td>
        <td>${severityBadge(r.severity)}</td>
        <td>${verdictBadge(r.verdict)}</td>
      </tr>`;
    }

    tableHtml += '</tbody></table>';
    container.querySelector('.wiki-recent-table').innerHTML = tableHtml;
  } catch {
    container.querySelector('.wiki-recent-table').innerHTML = '<div class="wiki-stat-empty">Could not load recent examples</div>';
  }
}

// ── Wiki AI Chat ─────────────────────────────────────────────────────────────

function wireWikiAi(article) {
  const input = document.getElementById('wiki-ai-input');
  const sendBtn = document.getElementById('wiki-ai-send');
  const chatEl = document.getElementById('wiki-ai-chat');
  if (!input || !sendBtn || !chatEl) return;

  async function askWikiAi() {
    const question = input.value.trim();
    if (!question) return;

    // Show user message
    chatEl.innerHTML += `<div class="ai-chat-msg user">${escHtml(question)}</div>`;
    input.value = '';

    // Show loading
    chatEl.innerHTML += `<div class="ai-chat-msg assistant" id="wiki-ai-loading"><span class="ai-typing"><span>.</span><span>.</span><span>.</span></span></div>`;
    chatEl.scrollTop = chatEl.scrollHeight;

    try {
      // Build context from article content
      const articleContext = [
        `Topic: ${article.title}`,
        `Source: ${article.source}`,
        `Severity: ${article.severity}`,
        `MITRE: ${article.mitre.join(', ')}`,
        `What it means: ${article.body.what}`,
        `Why it fires: ${article.body.why}`,
        `Assessment: ${article.body.assess}`,
        `Remediation: ${article.body.action}`,
        `False positives: ${article.body.falsePositives}`,
      ].join('\n');

      const res = await fetch('/api/wiki/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' },
        body: JSON.stringify({ question, article_context: articleContext, article_id: article.id }),
      });

      const loading = document.getElementById('wiki-ai-loading');

      if (res.headers.get('Content-Type')?.includes('text/event-stream')) {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let fullText = '';

        if (loading) loading.id = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value, { stream: true });
          const lines = chunk.split('\n');
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            const payload = line.slice(6).trim();
            if (payload === '[DONE]') break;
            try {
              const data = JSON.parse(payload);
              if (data.token) {
                fullText += data.token;
                if (loading) {
                  loading.innerHTML = typeof renderAiMarkdown === 'function'
                    ? renderAiMarkdown(fullText) : escHtml(fullText);
                }
              }
            } catch { /* skip */ }
          }
        }
      } else {
        const data = await res.json();
        const text = data.response || '(no response)';
        if (loading) {
          loading.innerHTML = typeof renderAiMarkdown === 'function'
            ? renderAiMarkdown(text) : escHtml(text);
          loading.id = '';
        }
      }
    } catch (err) {
      const loading = document.getElementById('wiki-ai-loading');
      if (loading) {
        loading.innerHTML = `<span style="color:var(--sev-critical)">AI request failed: ${escHtml(err.message)}</span>`;
        loading.id = '';
      }
    }
    chatEl.scrollTop = chatEl.scrollHeight;
  }

  sendBtn.addEventListener('click', askWikiAi);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') askWikiAi();
  });
}

// ── Exported API ──────────────────────────────────────────────────────────────

// These use functions from app.js (escHtml, fmtTime, fmtRelative, severityBadge, verdictBadge)
// which are in the global scope.

window.WIKI_ARTICLES = WIKI_ARTICLES;
window.resolveWikiArticle = resolveWikiArticle;
window.openWiki = openWiki;
window.closeWiki = closeWiki;
