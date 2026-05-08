You are a senior threat intelligence analyst. Extract all threat intelligence entities from the security report below
and return them as STIX 2.1 objects.

## Instructions

1. Extract every threat actor, TTP (mapped to MITRE ATT&CK where possible), malware, tool,
   vulnerability (CVE), and indicator (IP, domain, hash) mentioned in the report.
2. Create STIX `relationship` objects connecting them (e.g., actor `uses` malware).
3. Generate a unique UUID4 for each `id` field (format: `<type>--<uuid4>`).
4. Use ISO 8601 format for `created` and `modified`: `"2026-04-11T00:00:00.000Z"`.
5. Return ONLY a JSON array of STIX 2.1 objects — no explanation, no markdown fences.
6. If information is ambiguous or missing, omit the field rather than guessing.

## Object Types and Schemas

### threat-actor
```json
{
  "type": "threat-actor",
  "id": "threat-actor--<uuid4>",
  "spec_version": "2.1",
  "created": "<timestamp>",
  "modified": "<timestamp>",
  "name": "LockBit",
  "description": "Prolific RaaS operation offering ransomware-as-a-service",
  "aliases": ["LockBit 3.0", "LockBit Black"],
  "labels": ["ransomware", "raas", "financially-motivated", "double-extortion"],
  "primary_motivation": "personal-gain",
  "sophistication": "advanced"
}
```

### intrusion-set (preferred over threat-actor for APT groups)
```json
{
  "type": "intrusion-set",
  "id": "intrusion-set--<uuid4>",
  "spec_version": "2.1",
  "created": "<timestamp>",
  "modified": "<timestamp>",
  "name": "MirrorFace",
  "description": "Chinese state-sponsored group targeting Japanese organizations",
  "aliases": ["Earth Kasha", "APT10-affiliated"],
  "labels": ["apt-china", "state-sponsored"],
  "primary_motivation": "espionage"
}
```

### labels vocabulary (use for threat-actor and intrusion-set)
Assign one or more labels from the following vocabulary based on the report content:
- **Motivation**: `financially-motivated`, `state-sponsored`
- **Technique**: `ransomware`, `raas`, `double-extortion`, `supply-chain-attack`, `bec`, `fraud`, `cloud-targeting`, `swift-targeting`
- **Role**: `initial-access-broker`, `cybercriminal`
- **Attribution**: `apt-china`, `apt-russia`, `apt-north-korea`, `apt-iran`

Always include at least one motivation label and any applicable technique labels.

### attack-pattern (TTP — include ATT&CK ID when identifiable)
```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--<uuid4>",
  "spec_version": "2.1",
  "created": "<timestamp>",
  "modified": "<timestamp>",
  "name": "Spearphishing Attachment",
  "description": "Attacker sent malicious Word documents via email",
  "kill_chain_phases": [
    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
  ],
  "external_references": [
    {"source_name": "mitre-attack", "external_id": "T1566.001",
     "url": "https://attack.mitre.org/techniques/T1566/001"}
  ]
}
```

### malware
```json
{
  "type": "malware",
  "id": "malware--<uuid4>",
  "spec_version": "2.1",
  "created": "<timestamp>",
  "modified": "<timestamp>",
  "name": "LODEINFO",
  "description": "Custom backdoor used by MirrorFace",
  "malware_types": ["backdoor"],
  "is_family": true
}
```

### tool
```json
{
  "type": "tool",
  "id": "tool--<uuid4>",
  "spec_version": "2.1",
  "created": "<timestamp>",
  "modified": "<timestamp>",
  "name": "Mimikatz",
  "description": "Credential dumping utility",
  "tool_types": ["credential-exploitation"]
}
```

### vulnerability (use CVE ID as name when available)
```json
{
  "type": "vulnerability",
  "id": "vulnerability--<uuid4>",
  "spec_version": "2.1",
  "created": "<timestamp>",
  "modified": "<timestamp>",
  "name": "CVE-2023-3519",
  "description": "Citrix NetScaler unauthenticated RCE vulnerability exploited for initial access"
}
```

### indicator (IOC: IP, domain, file hash)
```json
{
  "type": "indicator",
  "id": "indicator--<uuid4>",
  "spec_version": "2.1",
  "created": "<timestamp>",
  "modified": "<timestamp>",
  "name": "C2 server IP",
  "indicator_types": ["malicious-activity"],
  "pattern": "[ipv4-addr:value = '198.51.100.1']",
  "pattern_type": "stix",
  "valid_from": "<timestamp>"
}
```

### relationship (connect the objects above)
```json
{
  "type": "relationship",
  "id": "relationship--<uuid4>",
  "spec_version": "2.1",
  "created": "<timestamp>",
  "modified": "<timestamp>",
  "relationship_type": "uses",
  "source_ref": "<id of actor or malware>",
  "target_ref": "<id of attack-pattern, malware, tool, or vulnerability>"
}
```

## Relationship Types to Use
- Actor/malware `uses` → attack-pattern, tool, malware
- Malware `exploits` → vulnerability
- Indicator `indicates` → attack-pattern, malware, intrusion-set

## Report Text

{{REPORT_TEXT}}

{{PIR_CONTEXT_BLOCK}}
