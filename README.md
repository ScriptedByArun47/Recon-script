# recon-tool

Automated web reconnaissance and attack-surface mapping framework for authorized security assessments. It chains 20+ industry-standard tools into a single pipeline — subdomain enumeration, live-host detection, port scanning, JS/secret analysis, directory brute-forcing, and vulnerability scanning — with resumable checkpoints, scope filtering, and a live JSON status feed.

Phases run as a **dependency graph**: each phase launches the moment its actual data dependencies are satisfied, with a configurable concurrency cap, rather than running strictly one phase at a time.

> ⚠️ **For authorized testing only.** Only run this against targets you own or have explicit written permission to test.

---

## Features

- **22 phases** covering recon, live-host probing, port scanning, JS/endpoint/secret discovery, subdomain takeover checks, vulnerability scanning, screenshots, header/CORS auditing, tech fingerprinting, favicon pivoting, ASN intel, content discovery, 403 bypass, parameter enumeration, and cloud bucket enumeration
- **Dependency-graph scheduler** — independent phases (WAF detection, header audit, tech fingerprinting, screenshots, content discovery, etc.) run concurrently once their shared prerequisite (`httpx`) is done, instead of queuing one after another
- **Resumable** — `.checkpoint` tracks completed phases; `--resume` picks up where you left off without re-running finished work
- **Scope control** — plain-text pattern files or Burp Suite JSON scope files, auto-detected
- **Live JSON dashboard feed** — `--json` continuously writes `summary.json` (per-phase status + aggregate stats) for an external dashboard to poll
- **Single-target port scan mode** — `-u/--url` restricts the port-scanning phase to one host, independent of the rest of the pipeline
- Graceful degradation — a failed or missing tool doesn't stop the run; phases fall back to empty output and downstream phases continue

---

## Requirements

**Required tools** (the script exits early if any are missing):

```
subfinder  assetfinder  dnsx  httpx  naabu  shuffledns  jq  curl  gau  katana  ffuf
```

**Optional tools** (features degrade gracefully if absent — a warning is printed but the run continues):

```
amass  github-subdomains  nuclei  gowitness  wafw00f  subzy  trufflehog
gf  whatweb  alterx  notify  arjun  s3scanner  qsreplace  cloud_enum  massdns
```

Install everything with:

```bash
./recon-tool.sh --install-deps
```

This installs the Go-based tools (requires Go 1.21+), the pip-based tools, `gf` patterns, AWSBucketDump, trufflehog, nuclei templates, and a default resolver list.

**Shell:** requires **bash 4.3+** (the scheduler uses `wait -n`).

---

## Quick start

```bash
chmod +x recon-tool.sh
./recon-tool.sh example.com
```

Output is written to `recon/example.com/`, organized by data type (`passive/`, `active/`, `web/`, `js/`, `secrets/`, `vulns/`, `dirbrute/`, `params/`, `cloud/`, etc.), with per-phase logs in `recon/example.com/logs/<phase>.log`.

---

## Usage

```
./recon-tool.sh target.com [OPTIONS]
```

### Resume / checkpoint

| Flag | Description |
|---|---|
| `--resume` | Continue from last completed phase |
| `--reset` | Wipe checkpoint, start fresh |
| `--status` | Show phase progress and exit |

### Scope / rate

| Flag | Description |
|---|---|
| `--scope FILE` | Only keep subdomains/URLs matching `FILE` (plain-text patterns or Burp Suite JSON scope — auto-detected) |
| `--rate-limit N` | Global req/s cap per phase (default: `50`) |

### Concurrency

| Flag | Description |
|---|---|
| `--max-parallel-phases N` | Max number of phases running at once in the dependency graph (default: `6`). Each phase's own internal parallelism (ffuf threads, gau workers, etc.) is separate and stacks on top of this. |

### Targeting

| Flag | Description |
|---|---|
| `-u, --url HOST` | Restrict the port-scanning phase to a single host — combine with `--only-ports` for a standalone scan |

### Feature flags

| Flag | Description |
|---|---|
| `--mutate` | Enable subdomain mutation (opt-in, via `alterx`) |
| `--json` | Continuously write `summary.json` for a live dashboard |
| `--deep-nuclei` | Also run tech/CVE/JS-endpoint/swagger nuclei passes (slower). Default is a fast basic pass. |
| `--install-deps` | Install all tools, then exit |

### Skip flags

Disable individual phases:

```
--skip-whois --skip-passive --skip-dns --skip-mutation --skip-resolve
--skip-httpx --skip-waf --skip-ports --skip-nmap --skip-js --skip-jsdeep
--skip-secrets --skip-takeover --skip-nuclei --skip-screenshots
--skip-headers --skip-techfp --skip-favicon --skip-asn --skip-dirbrute
--skip-403bypass --skip-params --skip-cloud --skip-vulnhelper --skip-amass
```

### Only flags

Disable everything except the listed phase(s) — combinable:

```
--only-whois --only-passive --only-dns --only-mutation --only-resolve
--only-httpx --only-waf --only-ports --only-js --only-jsdeep --only-secrets
--only-takeover --only-nuclei --only-screenshots --only-headers --only-techfp
--only-favicon --only-asn --only-dirbrute --only-403bypass --only-params
--only-cloud --only-vulnhelper
```

### Environment variables

| Variable | Description |
|---|---|
| `SHODAN_API_KEY` | Enables Shodan host/favicon-hash lookups |
| `GITHUB_TOKEN` | Enables GitHub subdomain discovery and secret dorking |
| `RESOLVERS_FILE` | Path to a resolver list (default: `~/resolvers.txt`) |
| `SECRETFINDER_PATH` | Path to `SecretFinder.py` |
| `SECRETFINDER_PYTHON` | Python binary for SecretFinder (default: `python3`) |
| `DIRBRUTE_WORDLIST` | Wordlist for `ffuf` (default: SecLists `common.txt`) |
| `PARAMS_WORDLIST` | Wordlist for `arjun` |
| `FFUF_RATE` | `ffuf` req/s per process (default: `200`) |

---

## Examples

```bash
# Basic run, default concurrency (6 phases at once)
./recon-tool.sh example.com

# Gentler on the target — fewer concurrent phases + lower rate limit
./recon-tool.sh example.com --rate-limit 20 --max-parallel-phases 3

# Scope-restricted run with a Burp Suite JSON export
./recon-tool.sh example.com --scope scope.json --rate-limit 30

# Resume an interrupted run
./recon-tool.sh example.com --resume

# Live JSON dashboard feed
./recon-tool.sh example.com --json --max-parallel-phases 5

# Subdomain mutation enabled
./recon-tool.sh example.com --mutate

# Just content discovery + parameter enumeration
./recon-tool.sh example.com --only-dirbrute --only-params

# Deep nuclei pass (tech/CVE/JS-endpoint/swagger)
./recon-tool.sh example.com --deep-nuclei

# Standalone port scan against one host
./recon-tool.sh example.com --only-ports -u sub.example.com

# Skip noisy/slow phases
./recon-tool.sh example.com --skip-nmap --skip-amass --skip-mutation

# Check progress without running anything
./recon-tool.sh example.com --status

# Install all dependencies
./recon-tool.sh --install-deps
```

### Watching progress

Each phase writes its full output to its own log, since multiple phases run concurrently:

```bash
tail -f recon/example.com/logs/dirbrute.log      # one phase
tail -f recon/example.com/logs/*.log             # everything
```

---

## Phases

| # | Phase | Depends on | What it does |
|---|---|---|---|
| 1 | WHOIS & IP Intel | — | WHOIS lookup, DNS record dump, IP geolocation, optional Shodan host lookup |
| 2 | Passive Subdomain Enumeration | — | subfinder, assetfinder, amass, crt.sh, Certspotter, Wayback, RapidDNS, GitHub subdomains/dorking |
| 3 | DNS Deep Dive | WHOIS | Zone transfer attempts, DNSSEC, SPF/DMARC/DKIM evaluation, reverse DNS |
| 4 | Subdomain Mutation (`--mutate`) | Passive | `alterx` permutations of known subdomains |
| 5 | Active Resolution | Passive (+ Mutation) | dnsx/massdns/shuffledns/amass active resolution |
| 6 | Live Host Detection | Resolution | `httpx` probing — title, status, CDN, favicon hash |
| 7 | WAF Detection | Live Hosts | `wafw00f` |
| 8 | Port Scanning | Resolution, Live Hosts | naabu + nmap service detection (supports `-u/--url` single-target mode) |
| 9 | JS & Endpoint Discovery | Live Hosts | gau + katana crawl, background JS file download |
| 9b | JS Deep Analysis | JS | Endpoint/secret/GraphQL extraction from downloaded JS |
| 10 | Secret Scanning | JS | TruffleHog + `gf` secret patterns |
| 11 | Subdomain Takeover | Resolution | `subzy` or CNAME→NXDOMAIN fallback |
| 12 | Vulnerability Scanning | Live Hosts (+ JS Deep if `--deep-nuclei`) | `nuclei` — basic pass by default, deep pass optional |
| 13 | Screenshots | Live Hosts | `gowitness` |
| 14 | CORS & Security Header Audit | Live Hosts | Reflected-origin CORS checks, missing-header detection, weak CSP |
| 15 | Tech Fingerprinting | Live Hosts | `whatweb` or header fallback, NVD search URL generation |
| 16 | Favicon Hash Hunt | Live Hosts | Favicon hash extraction, optional Shodan pivot |
| 17 | ASN & Network Intel | WHOIS | ASN lookup, IP ranges, `amass intel`, passive cloud enum |
| 18 | Content Discovery | Live Hosts | Parallelized `ffuf` directory brute-force |
| 18b | 403 Bypass + Path Merge | Content Discovery | Merges ffuf results, flags high-value paths, header-based 403 bypass attempts |
| 19 | Parameter Enumeration | JS | `arjun`, `paramspider`, `gf` patterns, Swagger/OpenAPI discovery |
| 20 | Cloud Enumeration | — | `s3scanner`, AWSBucketDump, passive Azure Blob/GCP bucket probing |
| 21 | Vulnerability Helpers | JS | `gf` + `qsreplace` candidate XSS/SQLi/redirect/SSRF/LFI/IDOR generation with lightweight confirmation |

---

## Output structure

```
recon/<target>/
├── .checkpoint          # completed phase keys
├── .session_config      # saved scope/rate-limit for --resume
├── summary.json          # live status feed (--json)
├── logs/                 # per-phase full output
│   ├── whois.log
│   ├── passive.log
│   └── ...
├── passive/               # Phase 2
├── dns/                   # Phase 3
├── active/                 # Phases 4–5
├── web/                    # Phase 6
├── ports/                  # Phase 8
├── js/                      # Phases 9–9b
├── secrets/                 # Phases 9b–10
├── vulns/                    # Phases 11–12
├── screenshots/               # Phase 13
├── headers/                    # Phase 14
├── techfp/                      # Phase 15
├── asn/                          # Phase 17
├── dirbrute/                      # Phases 18–18b
├── params/                         # Phase 19
├── cloud/                           # Phase 20
└── vulnhelpers/                      # Phase 21
```

---

## Scope files

Two formats are auto-detected:

- **Burp Suite JSON scope export** (`.json`, or content starting with `{`) — parsed via `scope_parser.sh` (must sit next to the main script)
- **Plain-text pattern file** (anything else) — one grep pattern per line, legacy mode

```bash
./recon-tool.sh example.com --scope scope.json
./recon-tool.sh example.com --scope patterns.txt
```

---

## A note on concurrency

With the default `--max-parallel-phases 6`, several phases that each probe every live host (WAF detection, header audit, tech fingerprinting, content discovery, nuclei, screenshots...) can run **at the same time** once `httpx` finishes. Each respects `--rate-limit` individually, but the *aggregate* request volume against the target scales with how many phases are running concurrently. If you need a softer footprint, lower both `--rate-limit` and `--max-parallel-phases` together:

```bash
./recon-tool.sh example.com --rate-limit 15 --max-parallel-phases 2
```

---

## Legal

This tool is provided for authorized security testing and educational purposes only. Running it against systems you do not own or do not have explicit, written authorization to test may violate computer-crime laws in your jurisdiction. You are solely responsible for ensuring you have permission before scanning any target.
