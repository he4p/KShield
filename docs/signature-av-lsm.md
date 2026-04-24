# Signature Antivirus With LSM

A simple signature-based antivirus is possible in this project, but the split matters:

- eBPF LSM is good at inline enforcement: allow or deny `exec`, `open`, `write`, `ptrace`, and similar operations.
- Userspace is the right place for signature scanning: hashing files, reading file contents, parsing signature databases, and making richer verdicts.

Do not try to build a full file-content scanner inside eBPF. BPF programs are bounded, cannot freely read whole files, and are not a good place for SHA/YARA-style work. Use BPF LSM to enforce verdicts that userspace has already computed.

## Recommended Architecture

1. Agent observes file activity and execution attempts.
2. Agent or helper scanner hashes files in userspace.
3. Agent checks hashes against a local signature database.
4. Agent writes malicious verdicts into BPF maps.
5. LSM hooks block future matching execution or file access.
6. Agent forwards `malware_detected` and block events to the manager.
7. Manager stores detections and distributes signature updates.

## Enforcement Keys

Prefer stable file identity over path-only matching:

- `dev`
- `inode`
- optional `ctime` or size
- optional file hash

Path rules are useful for policy, but weak for antivirus because files can move, link, or be replaced.

Good first implementation:

- Userspace scanner computes SHA-256.
- Signature DB maps SHA-256 to malware name/severity.
- Agent keeps a userspace cache: `(dev, inode) -> verdict`.
- Agent syncs blocked `(dev, inode)` keys into an eBPF map.
- `bprm_check_security` blocks execution if `(dev, inode)` is in the malicious map.
- `file_permission` can optionally block read or write for known malicious files.

## Signature Database Shape

Start simple:

```json
{
  "version": 1,
  "updated_at": "2026-04-24T00:00:00Z",
  "hashes": [
    {
      "sha256": "0123456789abcdef...",
      "name": "EICAR-Test-File",
      "severity": "critical",
      "action": "block"
    }
  ]
}
```

Manager can serve this as a policy endpoint later, for example:

```text
GET /api/v1/signatures
```

Agent should cache the database locally so enforcement survives manager outages.

## LSM Hooks To Use

Useful hooks:

- `bprm_check_security`: best first hook for blocking malicious executable launches.
- `file_permission`: can block reads/writes after a file is known malicious.
- `inode_create`, `inode_rename`, `inode_unlink`, `file_open`: possible future hooks for cache invalidation and quarantine workflows.

Best first milestone:

1. Scan on `execve` observation or before `bprm_check_security` verdict is needed.
2. Cache clean/malicious file verdicts in userspace.
3. Block known-malicious `(dev, inode)` in `bprm_check_security`.

## Race Conditions

Pure userspace scanning has a time-of-check/time-of-use risk:

- file is scanned clean
- file content changes
- file is executed before rescan

Reduce this with:

- cache key includes `mtime`, `ctime`, and size
- invalidate cache on write events
- rescan on first execution after write
- block unknown execution until scan completes if strict mode is enabled

Strict mode is safer but can break usability if scanners are slow.

## Scanner Options

Minimal scanner:

- SHA-256 exact hash signatures
- local JSON signature DB
- verdict cache
- BPF map sync for malicious file IDs

Better scanner:

- SHA-256 plus fuzzy hashes
- YARA-compatible rules in userspace
- quarantine metadata
- allowlists for trusted paths/signers
- per-agent signature policy from manager

## Event Types To Add

Suggested manager event types:

- `malware_scan`: scan completed
- `malware_detected`: malicious signature matched
- `malware_block`: LSM blocked access to known malicious file

Useful event fields:

- `subject`: path if available
- `arg0`: signature database version or scanner verdict code
- `arg1`: file size or signature rule ID if numeric
- `process_path`: process that touched the file
- additional raw JSON fields: `sha256`, `signature_name`, `file_dev`, `file_inode`

## Practical Next Step

Build exact-hash blocking first:

1. Add a manager signature DB endpoint or local agent signature file.
2. Add agent userspace SHA-256 scanner and verdict cache.
3. Add BPF map keyed by `(dev, inode)` for malicious files.
4. Add `bprm_check_security` enforcement against that map.
5. Emit `malware_detected` and `malware_block` events.
6. Add TOML detectors for those event types.

This gives antivirus-like blocking while keeping BPF small and reliable.
