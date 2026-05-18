Create an initial scaffold for a repository named:

  uda-lab/kunadonokami

Purpose:
A defensive-security-oriented framework for collecting, reducing, and reviewing Linux VPS security snapshots using AI-assisted analysis.

Core philosophy:

- privileged collection, unprivileged analysis
- deterministic preprocessing before LLM reasoning
- read-only review
- defensive use only
- minimise attack surface
- avoid direct agent shell access to production VPS
- no autonomous remediation
- transparent artifact pipeline

The repository is NOT:

- a penetration testing framework
- an offensive security toolkit
- an autonomous remediation system
- an MCP server with unrestricted shell access

Initial repository structure:

- README.md
- LICENSE
- docs/
- schemas/
- scripts/
- reducers/
- prompts/
- examples/
- policies/
- skills/

Key deliverables for the initial scaffold:

1. snapshot collection shell script
2. normalized SSH event schema
3. reduced security summary schema
4. deterministic reducer design notes
5. AI handoff prompt template
6. SKILL.md for read-only review
7. example sanitized snapshot
8. security philosophy document
9. threat model document
10. explicit non-goals

Design constraints:

- keep the implementation small
- prefer shell, Python, plain text, and JSON
- avoid Kubernetes, cloud infrastructure, databases, or heavy frameworks
- do not add autonomous patching
- do not modify firewall rules
- do not edit SSH configuration automatically
- do not require an always-running daemon
- do not require a paid SaaS

Target environment:

- Ubuntu/Debian VPS
- systemd
- sshd
- fail2ban
- optional nftables or ufw

The initial scaffold should be practical, auditable, and easy for coding agents to extend. Documentation should be concise but rigorous.
