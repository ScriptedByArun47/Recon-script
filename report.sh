#!/bin/bash

# ============================================================
# PENTURION v7 — report.sh
# Standalone HTML + JSON report generator
# Usage: ./report.sh <domain> <recon_base_dir> [json: true|false] [scope_file] [rate_limit]
#
# Examples:
#   ./report.sh target.com recon/target.com
#   ./report.sh target.com recon/target.com true scope.txt 50
#   ./report.sh target.com recon/target.com true          # JSON on, no scope
# ============================================================

set -euo pipefail

# ─────────────────────────────────────────
# ARGS
# ─────────────────────────────────────────
domain="${1:-}"
BASE="${2:-recon/$domain}"
JSON_OUTPUT="${3:-false}"
SCOPE_FILE="${4:-}"
RATE_LIMIT="${5:-50}"

if [ -z "$domain" ]; then
  echo "Usage: $0 <domain> [recon_base_dir] [json:true|false] [scope_file] [rate_limit]"
  exit 1
fi

if [ ! -d "$BASE" ]; then
  echo "[-] Recon directory not found: $BASE"
  exit 1
fi

cd "$BASE" || exit 1

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'; BOLD='\033[1m'
info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }

mkdir -p report

# ─────────────────────────────────────────
# COLLECT STATS
# ─────────────────────────────────────────
CHECKPOINT_FILE=".checkpoint"
ORIG_START=$(cat .start_time_epoch 2>/dev/null || date +%s)
END_TIME=$(date +%s)
DURATION=$((END_TIME - ORIG_START))
DURATION_FMT=$(printf '%02dh %02dm %02ds' $((DURATION/3600)) $(((DURATION%3600)/60)) $((DURATION%60)))
DONE_PHASES=$(wc -l < "$CHECKPOINT_FILE" 2>/dev/null | tr -d " " || echo 0)
TOTAL_PHASES=21

PASSIVE_COUNT=$(wc -l < passive/all_passive.txt        2>/dev/null || echo 0)
RESOLVED_COUNT=$(wc -l < active/final_subdomains.txt   2>/dev/null || echo 0)
LIVE_COUNT=$(wc -l < web/live_hosts.txt                2>/dev/null || echo 0)
JS_COUNT=$(wc -l < js/all_js_files.txt                 2>/dev/null || echo 0)
JS_DEEP_COUNT=$(find js/downloaded -name "*.js" -size +0c 2>/dev/null | wc -l || echo 0)
JS_HIDDEN=$(wc -l < js/js_sensitive_endpoints.txt      2>/dev/null || echo 0)
OPEN_PORTS=$(wc -l < ports/all_open_ports.txt          2>/dev/null || echo 0)
NUCLEI_F=$(wc -l < vulns/nuclei_results.txt            2>/dev/null || echo 0)
SECRETS=$(wc -l < secrets/credential_patterns.txt      2>/dev/null || echo 0)
JS_SEC=$(wc -l < secrets/js_hardcoded_secrets.txt      2>/dev/null || echo 0)
CORS=$(wc -l < headers/cors_vulns.txt                  2>/dev/null || echo 0)
MISS_HDR=$(wc -l < headers/missing_headers.txt         2>/dev/null || echo 0)
TECH=$(wc -l < techfp/detected_versions.txt            2>/dev/null || echo 0)
FAV=$(wc -l < whois/favicon_hashes.txt                 2>/dev/null || echo 0)
DIRBRUTE_COUNT=$(wc -l < dirbrute/all_found_paths.txt  2>/dev/null || echo 0)
HIGH_VALUE=$(wc -l < dirbrute/high_value.txt           2>/dev/null || echo 0)
XSS=$(wc -l < vulnhelpers/xss_candidates.txt           2>/dev/null || echo 0)
SQLI=$(wc -l < vulnhelpers/sqli_candidates.txt         2>/dev/null || echo 0)
REDIRECT=$(wc -l < vulnhelpers/redirect_candidates.txt 2>/dev/null || echo 0)
SSRF=$(wc -l < vulnhelpers/ssrf_candidates.txt         2>/dev/null || echo 0)
CLOUD_S3=$(wc -l < cloud/s3_open_buckets.txt           2>/dev/null || echo 0)
CLOUD_AZ=$(wc -l < cloud/azure_blobs.txt               2>/dev/null || echo 0)
CLOUD_GCP=$(wc -l < cloud/gcp_buckets.txt             2>/dev/null || echo 0)
GH_DORKS=$(wc -l < passive/github_dorks.txt            2>/dev/null || echo 0)
PARAMS_COUNT=$(wc -l < params/all_gf_params.txt        2>/dev/null || echo 0)
API_SPECS=$(wc -l < params/api_specs_found.txt         2>/dev/null || echo 0)
EMAIL_ISSUES=$(wc -l < dns/email_security_eval.txt     2>/dev/null || echo 0)

# ─────────────────────────────────────────
# JSON REPORT
# ─────────────────────────────────────────
if [ "$JSON_OUTPUT" = "true" ]; then
  cat > report/summary.json << JSONEOF
{
  "meta": {
    "tool": "PENTURION v7",
    "target": "$domain",
    "generated": "$(date -u -Iseconds)",
    "duration": "$DURATION_FMT",
    "phases_completed": $DONE_PHASES,
    "total_phases": $TOTAL_PHASES,
    "scope_file": "${SCOPE_FILE:-null}",
    "rate_limit": $RATE_LIMIT
  },
  "recon": {
    "passive_subdomains": $PASSIVE_COUNT,
    "resolved_subdomains": $RESOLVED_COUNT,
    "live_hosts": $LIVE_COUNT,
    "open_ports": $OPEN_PORTS
  },
  "js_analysis": {
    "js_files_found": $JS_COUNT,
    "js_files_downloaded": $JS_DEEP_COUNT,
    "hidden_endpoints": $JS_HIDDEN,
    "hardcoded_secrets": $JS_SEC
  },
  "vulnerabilities": {
    "nuclei_findings": $NUCLEI_F,
    "cors_issues": $CORS,
    "missing_headers": $MISS_HDR,
    "credential_patterns": $SECRETS,
    "xss_candidates": $XSS,
    "sqli_candidates": $SQLI,
    "open_redirect_candidates": $REDIRECT,
    "ssrf_candidates": $SSRF
  },
  "content_discovery": {
    "paths_found": $DIRBRUTE_COUNT,
    "high_value_paths": $HIGH_VALUE,
    "api_specs_found": $API_SPECS,
    "parameter_matches": $PARAMS_COUNT
  },
  "cloud": {
    "s3_open_buckets": $CLOUD_S3,
    "azure_blobs": $CLOUD_AZ,
    "gcp_buckets": $CLOUD_GCP
  },
  "intelligence": {
    "tech_versions": $TECH,
    "favicon_hashes": $FAV,
    "github_dork_results": $GH_DORKS,
    "email_security_issues": $EMAIL_ISSUES
  }
}
JSONEOF
  success "JSON: report/summary.json"
fi

# ─────────────────────────────────────────
# ASCII SUMMARY
# ─────────────────────────────────────────
cat > report/summary.txt << EOF
╔══════════════════════════════════════════════════════════════════╗
║              PENTURION v7 — $domain
╠══════════════════════════════════════════════════════════════════╣
║  Duration              : $DURATION_FMT
║  Phases completed      : $DONE_PHASES / $TOTAL_PHASES
║  Scope file            : ${SCOPE_FILE:-none}
║  Rate limit            : ${RATE_LIMIT} req/s
╠══════════════════════════════════════════════════════════════════╣
║  RECON SURFACE
║  Passive subs          : $PASSIVE_COUNT
║  Resolved subs         : $RESOLVED_COUNT
║  Live hosts            : $LIVE_COUNT
║  Open ports            : $OPEN_PORTS
╠══════════════════════════════════════════════════════════════════╣
║  JS ANALYSIS
║  JS files (URLs)       : $JS_COUNT
║  JS files (downloaded) : $JS_DEEP_COUNT
║  JS hidden endpoints   : $JS_HIDDEN
║  JS hardcoded secrets  : $JS_SEC
╠══════════════════════════════════════════════════════════════════╣
║  VULNERABILITIES
║  Nuclei findings       : $NUCLEI_F
║  CORS issues           : $CORS
║  Missing headers       : $MISS_HDR
║  Credential patterns   : $SECRETS
║  XSS candidates        : $XSS
║  SQLi candidates       : $SQLI
║  Open redirect         : $REDIRECT
║  SSRF candidates       : $SSRF
╠══════════════════════════════════════════════════════════════════╣
║  CONTENT DISCOVERY
║  Paths found           : $DIRBRUTE_COUNT
║  High value paths      : $HIGH_VALUE
║  API specs found       : $API_SPECS
║  Parameter matches     : $PARAMS_COUNT
╠══════════════════════════════════════════════════════════════════╣
║  CLOUD
║  S3 open buckets       : $CLOUD_S3
║  Azure blobs           : $CLOUD_AZ
║  GCP buckets           : $CLOUD_GCP
╠══════════════════════════════════════════════════════════════════╣
║  INTELLIGENCE
║  Tech versions         : $TECH
║  Favicon hashes        : $FAV
║  GitHub dork results   : $GH_DORKS
║  Email security issues : $EMAIL_ISSUES
╚══════════════════════════════════════════════════════════════════╝
EOF
cat report/summary.txt

# ─────────────────────────────────────────
# HTML TABLE BUILDER
# ─────────────────────────────────────────
mk_rows() {
  local f="$1" limit="${2:-500}"
  if [ -s "$f" ]; then
    head -"$limit" "$f" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' \
      | while IFS= read -r l; do echo "<tr><td>${l}</td></tr>"; done
  else
    echo '<tr><td class="empty">No data</td></tr>'
  fi
}

LIVE_TBL=$(mk_rows web/live_hosts.txt 200)
PORT_TBL=$(mk_rows ports/all_open_ports.txt 200)
SEC_TBL=$(mk_rows secrets/credential_patterns.txt 100)
VULN_TBL=$(mk_rows vulns/nuclei_results.txt 200)
CORS_TBL=$(mk_rows headers/cors_vulns.txt)
HDR_TBL=$(mk_rows headers/missing_headers.txt 100)
TECH_TBL=$(mk_rows techfp/detected_versions.txt 100)
JSEP_TBL=$(mk_rows js/js_sensitive_endpoints.txt 100)
JSSEC_TBL=$(mk_rows secrets/js_hardcoded_secrets.txt 100)
DIR_TBL=$(mk_rows dirbrute/all_found_paths.txt 200)
HIGHVAL_TBL=$(mk_rows dirbrute/high_value.txt)
PARAM_TBL=$(mk_rows params/all_gf_params.txt 100)
XSS_TBL=$(mk_rows vulnhelpers/xss_candidates.txt 100)
SQLI_TBL=$(mk_rows vulnhelpers/sqli_candidates.txt 100)
REDIRECT_TBL=$(mk_rows vulnhelpers/redirect_candidates.txt 100)
CLOUD_TBL=$(mk_rows cloud/s3_open_buckets.txt)
GH_TBL=$(mk_rows passive/github_dorks.txt 50)
EMAIL_TBL=$(mk_rows dns/email_security_eval.txt)
API_TBL=$(mk_rows params/api_specs_found.txt)

PROGRESS_PCT=$(( (DONE_PHASES * 100) / TOTAL_PHASES ))

# ─────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────
cat > report/report.html << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PENTURION v7 — $domain</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
:root {
  --bg:     #0a0c0f; --bg2: #0f1318; --bg3: #141920;
  --green:  #00ff88; --cyan: #00d4ff; --red: #ff4466;
  --orange: #ff8800; --yellow: #ffd700; --magenta: #cc44ff;
  --dim:    #4a5568; --text: #c8d6e0;  --border: #1e2d3d;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'Rajdhani', sans-serif; font-size: 16px; line-height: 1.6; }
body::before {
  content: ''; position: fixed; inset: 0; pointer-events: none;
  background: radial-gradient(ellipse at 20% 20%, rgba(0,255,136,.04), transparent 60%),
              radial-gradient(ellipse at 80% 80%, rgba(0,212,255,.04), transparent 60%);
}
.wrap { max-width: 1400px; margin: 0 auto; padding: 40px 24px; position: relative; z-index: 1; }

/* ── HEADER ── */
header { border-bottom: 1px solid var(--border); padding-bottom: 32px; margin-bottom: 40px; }
.logo  { font-family: 'Share Tech Mono', monospace; font-size: 11px; color: var(--dim); letter-spacing: 3px; text-transform: uppercase; margin-bottom: 16px; }
h1     { font-size: 48px; font-weight: 700; background: linear-gradient(135deg, var(--green), var(--cyan)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.meta  { font-family: 'Share Tech Mono', monospace; font-size: 12px; color: var(--dim); margin-top: 8px; }
.meta span { color: var(--cyan); }
.pbar  { height: 6px; background: var(--bg3); border-radius: 3px; margin: 16px 0; overflow: hidden; }
.pfill { height: 100%; background: linear-gradient(90deg, var(--green), var(--cyan)); width: ${PROGRESS_PCT}%; transition: width .5s; }

/* ── NAV ── */
nav { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 32px; }
nav a { font-family: 'Share Tech Mono', monospace; font-size: 11px; color: var(--dim); border: 1px solid var(--border); padding: 4px 10px; border-radius: 4px; text-decoration: none; transition: all .2s; }
nav a:hover { color: var(--cyan); border-color: var(--cyan); }

/* ── SECTION LABELS ── */
.slabel { font-family: 'Share Tech Mono', monospace; font-size: 10px; letter-spacing: 3px; text-transform: uppercase; color: var(--dim); margin: 40px 0 12px; }

/* ── STAT GRIDS ── */
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 12px; }
.stat { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; position: relative; overflow: hidden; }
.stat::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }
.g::before { background: var(--green); } .c::before { background: var(--cyan); }
.r::before { background: var(--red); }  .y::before { background: var(--yellow); }
.o::before { background: var(--orange); } .m::before { background: var(--magenta); }
.sv { font-family: 'Share Tech Mono', monospace; font-size: 32px; font-weight: 700; color: var(--green); line-height: 1; }
.c .sv { color: var(--cyan); } .r .sv { color: var(--red); }
.y .sv { color: var(--yellow); } .o .sv { color: var(--orange); } .m .sv { color: var(--magenta); }
.sl { font-size: 11px; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }

/* ── SECTIONS ── */
section { margin-bottom: 40px; scroll-margin-top: 20px; }
h2 { font-size: 17px; font-weight: 600; color: var(--cyan); letter-spacing: 2px; text-transform: uppercase; border-left: 3px solid var(--cyan); padding-left: 12px; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
h2.r { color: var(--red);    border-color: var(--red); }
h2.o { color: var(--orange); border-color: var(--orange); }
h2.y { color: var(--yellow); border-color: var(--yellow); }
h2.m { color: var(--magenta); border-color: var(--magenta); }
.badge { font-size: 10px; background: var(--bg3); border: 1px solid var(--border); padding: 2px 8px; border-radius: 10px; color: var(--dim); font-family: 'Share Tech Mono', monospace; }

/* ── TABLES ── */
.tw { overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; }
table { width: 100%; border-collapse: collapse; }
th { background: var(--bg3); font-family: 'Share Tech Mono', monospace; font-size: 10px; color: var(--dim); text-transform: uppercase; letter-spacing: 2px; padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
td { padding: 9px 14px; font-family: 'Share Tech Mono', monospace; font-size: 12px; border-bottom: 1px solid rgba(30,45,61,.5); word-break: break-all; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(0,255,136,.03); }
.empty { color: var(--dim); text-align: center; padding: 20px; font-style: italic; }

/* ── FOOTER ── */
footer { border-top: 1px solid var(--border); padding-top: 20px; margin-top: 60px; font-family: 'Share Tech Mono', monospace; font-size: 11px; color: var(--dim); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="logo">// PENTURION RECON FRAMEWORK v7 — AUTOMATED WEB PENTESTING</div>
  <h1>$domain</h1>
  <div class="meta">
    Generated: <span>$(date -u)</span> &nbsp;|&nbsp;
    Duration: <span>$DURATION_FMT</span> &nbsp;|&nbsp;
    Phases: <span>${DONE_PHASES}/${TOTAL_PHASES}</span> &nbsp;|&nbsp;
    Rate: <span>${RATE_LIMIT} rps</span>
    $([ -n "$SCOPE_FILE" ] && echo "&nbsp;|&nbsp; Scope: <span>$SCOPE_FILE</span>" || true)
  </div>
  <div class="pbar"><div class="pfill"></div></div>
</header>

<nav>
  <a href="#recon">Recon</a>
  <a href="#vulns">Vulnerabilities</a>
  <a href="#content">Content Discovery</a>
  <a href="#params">Parameters</a>
  <a href="#cloud">Cloud</a>
  <a href="#js">JS Analysis</a>
  <a href="#intel">Intelligence</a>
  <a href="#hosts">Hosts & Ports</a>
</nav>

<!-- ══ RECON OVERVIEW ══ -->
<div class="slabel" id="recon">// recon surface</div>
<div class="grid">
  <div class="stat g"><div class="sv">$PASSIVE_COUNT</div><div class="sl">Passive Subs</div></div>
  <div class="stat g"><div class="sv">$RESOLVED_COUNT</div><div class="sl">Resolved</div></div>
  <div class="stat c"><div class="sv">$LIVE_COUNT</div><div class="sl">Live Hosts</div></div>
  <div class="stat c"><div class="sv">$OPEN_PORTS</div><div class="sl">Open Ports</div></div>
  <div class="stat o"><div class="sv">$DIRBRUTE_COUNT</div><div class="sl">Paths Found</div></div>
  <div class="stat r"><div class="sv">$HIGH_VALUE</div><div class="sl">High Value Paths</div></div>
</div>

<!-- ══ VULNERABILITIES ══ -->
<div class="slabel" id="vulns">// vulnerabilities</div>
<div class="grid">
  <div class="stat r"><div class="sv">$NUCLEI_F</div><div class="sl">Nuclei Findings</div></div>
  <div class="stat r"><div class="sv">$CORS</div><div class="sl">CORS Issues</div></div>
  <div class="stat r"><div class="sv">$SECRETS</div><div class="sl">Credential Patterns</div></div>
  <div class="stat o"><div class="sv">$XSS</div><div class="sl">XSS Candidates</div></div>
  <div class="stat o"><div class="sv">$SQLI</div><div class="sl">SQLi Candidates</div></div>
  <div class="stat o"><div class="sv">$REDIRECT</div><div class="sl">Open Redirects</div></div>
  <div class="stat o"><div class="sv">$SSRF</div><div class="sl">SSRF Candidates</div></div>
  <div class="stat y"><div class="sv">$MISS_HDR</div><div class="sl">Missing Headers</div></div>
</div>

<!-- ══ JS & CLOUD ══ -->
<div class="slabel">// js analysis &amp; cloud</div>
<div class="grid">
  <div class="stat c"><div class="sv">$JS_DEEP_COUNT</div><div class="sl">JS Downloaded</div></div>
  <div class="stat o"><div class="sv">$JS_HIDDEN</div><div class="sl">Hidden Endpoints</div></div>
  <div class="stat r"><div class="sv">$JS_SEC</div><div class="sl">Hardcoded Secrets</div></div>
  <div class="stat m"><div class="sv">$CLOUD_S3</div><div class="sl">S3 Open Buckets</div></div>
  <div class="stat m"><div class="sv">$CLOUD_AZ</div><div class="sl">Azure Blobs</div></div>
  <div class="stat m"><div class="sv">$CLOUD_GCP</div><div class="sl">GCP Buckets</div></div>
  <div class="stat y"><div class="sv">$GH_DORKS</div><div class="sl">GitHub Dork Hits</div></div>
  <div class="stat y"><div class="sv">$API_SPECS</div><div class="sl">API Specs Found</div></div>
</div>

<!-- ══ NUCLEI ══ -->
<section id="nuclei-section">
  <h2 class="r">Nuclei findings <span class="badge">$NUCLEI_F</span></h2>
  <div class="tw"><table><thead><tr><th>Finding</th></tr></thead><tbody>${VULN_TBL}</tbody></table></div>
</section>

<!-- ══ CORS ══ -->
<section>
  <h2 class="r">CORS vulnerabilities <span class="badge">$CORS</span></h2>
  <div class="tw"><table><thead><tr><th>Finding</th></tr></thead><tbody>${CORS_TBL}</tbody></table></div>
</section>

<!-- ══ MISSING HEADERS ══ -->
<section>
  <h2 class="o">Missing security headers <span class="badge">$MISS_HDR</span></h2>
  <div class="tw"><table><thead><tr><th>Issue</th></tr></thead><tbody>${HDR_TBL}</tbody></table></div>
</section>

<!-- ══ VULN HELPERS ══ -->
<section id="params">
  <h2 class="o">XSS candidates <span class="badge">$XSS</span></h2>
  <div class="tw"><table><thead><tr><th>URL</th></tr></thead><tbody>${XSS_TBL}</tbody></table></div>
</section>
<section>
  <h2 class="o">SQLi candidates <span class="badge">$SQLI</span></h2>
  <div class="tw"><table><thead><tr><th>URL</th></tr></thead><tbody>${SQLI_TBL}</tbody></table></div>
</section>
<section>
  <h2 class="o">Open redirect candidates <span class="badge">$REDIRECT</span></h2>
  <div class="tw"><table><thead><tr><th>URL</th></tr></thead><tbody>${REDIRECT_TBL}</tbody></table></div>
</section>

<!-- ══ CONTENT DISCOVERY ══ -->
<section id="content">
  <h2 class="y">High value paths <span class="badge">$HIGH_VALUE</span></h2>
  <div class="tw"><table><thead><tr><th>Path</th></tr></thead><tbody>${HIGHVAL_TBL}</tbody></table></div>
</section>
<section>
  <h2>All discovered paths <span class="badge">$DIRBRUTE_COUNT</span></h2>
  <div class="tw"><table><thead><tr><th>Path</th></tr></thead><tbody>${DIR_TBL}</tbody></table></div>
</section>

<!-- ══ API SPECS ══ -->
<section>
  <h2>API specs found <span class="badge">$API_SPECS</span></h2>
  <div class="tw"><table><thead><tr><th>URL</th></tr></thead><tbody>${API_TBL}</tbody></table></div>
</section>

<!-- ══ PARAMETERS ══ -->
<section>
  <h2>Parameter matches (gf) <span class="badge">$PARAMS_COUNT</span></h2>
  <div class="tw"><table><thead><tr><th>URL</th></tr></thead><tbody>${PARAM_TBL}</tbody></table></div>
</section>

<!-- ══ CLOUD ══ -->
<section id="cloud">
  <h2 class="m">Cloud assets <span class="badge">S3: $CLOUD_S3 | Azure: $CLOUD_AZ | GCP: $CLOUD_GCP</span></h2>
  <div class="tw"><table><thead><tr><th>Asset</th></tr></thead><tbody>${CLOUD_TBL}</tbody></table></div>
</section>

<!-- ══ JS ══ -->
<section id="js">
  <h2 class="r">JS hardcoded secrets <span class="badge">$JS_SEC</span></h2>
  <div class="tw"><table><thead><tr><th>Secret Pattern</th></tr></thead><tbody>${JSSEC_TBL}</tbody></table></div>
</section>
<section>
  <h2 class="o">JS sensitive endpoints <span class="badge">$JS_HIDDEN</span></h2>
  <div class="tw"><table><thead><tr><th>Endpoint</th></tr></thead><tbody>${JSEP_TBL}</tbody></table></div>
</section>
<section>
  <h2>Credential patterns <span class="badge">$SECRETS</span></h2>
  <div class="tw"><table><thead><tr><th>Match</th></tr></thead><tbody>${SEC_TBL}</tbody></table></div>
</section>

<!-- ══ INTELLIGENCE ══ -->
<section id="intel">
  <h2>GitHub dork results <span class="badge">$GH_DORKS</span></h2>
  <div class="tw"><table><thead><tr><th>Repo | Path | URL</th></tr></thead><tbody>${GH_TBL}</tbody></table></div>
</section>
<section>
  <h2>Email security evaluation <span class="badge">$EMAIL_ISSUES</span></h2>
  <div class="tw"><table><thead><tr><th>Finding</th></tr></thead><tbody>${EMAIL_TBL}</tbody></table></div>
</section>
<section>
  <h2>Tech stack versions <span class="badge">$TECH</span></h2>
  <div class="tw"><table><thead><tr><th>URL | Tech | Version</th></tr></thead><tbody>${TECH_TBL}</tbody></table></div>
</section>

<!-- ══ HOSTS & PORTS ══ -->
<section id="hosts">
  <h2>Live hosts <span class="badge">$LIVE_COUNT</span></h2>
  <div class="tw"><table><thead><tr><th>URL / Details</th></tr></thead><tbody>${LIVE_TBL}</tbody></table></div>
</section>
<section>
  <h2>Open ports <span class="badge">$OPEN_PORTS</span></h2>
  <div class="tw"><table><thead><tr><th>Host:Port</th></tr></thead><tbody>${PORT_TBL}</tbody></table></div>
</section>

<footer>
  <span>PENTURION v7 &nbsp;|&nbsp; $domain</span>
  <span>Generated: $(date -u)</span>
  <span>Phases: ${DONE_PHASES}/${TOTAL_PHASES} &nbsp;|&nbsp; Duration: $DURATION_FMT</span>
</footer>

</div>
</body>
</html>
HTMLEOF

success "HTML report: report/report.html"
info "JSON report: $([ "$JSON_OUTPUT" = "true" ] && echo "report/summary.json" || echo "skipped (pass 'true' as 3rd arg)")"
echo -e "\n${BOLD}${GREEN}  Open: report/report.html${RESET}\n"