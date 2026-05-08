#!/bin/bash

# ============================================================
# PENTURION v7 — Automated Web Recon Framework
# Usage: ./penturion.sh target.com [OPTIONS]
#
# RESUME / CHECKPOINT:
#   --resume            Continue from last completed phase
#   --reset             Wipe checkpoint, start fresh
#   --status            Show phase progress and exit
#
# SCOPE / RATE:
#   --scope FILE        Only keep subdomains matching patterns in FILE
#   --rate-limit N      Global req/s cap (default: 50)
#
# FEATURE FLAGS:
#   --mutate            Enable Phase 4 subdomain mutation (opt-in)
#   --json              Write machine-readable summary.json
#   --install-deps      Install all tools then exit
#
# SKIP FLAGS:
#   --skip-whois        Phase 1  — WHOIS & IP Intel
#   --skip-passive      Phase 2  — Passive Subdomain Enumeration
#   --skip-dns          Phase 3  — DNS Deep Dive
#   --skip-mutation     Phase 4  — Subdomain Mutation
#   --skip-resolve      Phase 5  — Active Resolution
#   --skip-httpx        Phase 6  — Live Host Detection
#   --skip-waf          Phase 7  — WAF Detection
#   --skip-ports        Phase 8  — Port Scanning
#   --skip-nmap                   Nmap sub-flag only
#   --skip-js           Phase 9  — JS & Endpoint Discovery
#   --skip-jsdeep       Phase 9b — JS Deep Analysis
#   --skip-secrets      Phase 10 — Secret Scanning
#   --skip-takeover     Phase 11 — Subdomain Takeover
#   --skip-nuclei       Phase 12 — Vulnerability Scanning
#   --skip-screenshots  Phase 13 — Screenshots
#   --skip-headers      Phase 14 — CORS & Header Audit
#   --skip-techfp       Phase 15 — Tech Fingerprinting
#   --skip-favicon      Phase 16 — Favicon Hash Hunt
#   --skip-asn          Phase 17 — ASN & Network Intel
#   --skip-dirbrute     Phase 18 — Content Discovery
#   --skip-params       Phase 19 — Parameter Enumeration
#   --skip-cloud        Phase 20 — Cloud Enumeration
#   --skip-vulnhelper   Phase 21 — Vulnerability Helpers
#   --skip-amass        Skip amass in all phases
#
# ONLY FLAGS (disable all, enable listed — combinable):
#   --only-whois | --only-passive | --only-dns | --only-mutation
#   --only-resolve | --only-httpx | --only-waf | --only-ports
#   --only-js | --only-jsdeep | --only-secrets | --only-takeover
#   --only-nuclei | --only-screenshots | --only-headers
#   --only-techfp | --only-favicon | --only-asn | --only-dirbrute
#   --only-params | --only-cloud | --only-vulnhelper
#
# ENV VARS:
#   SHODAN_API_KEY        Shodan API key
#   GITHUB_TOKEN          GitHub token for subdomain + dorking
#   RESOLVERS_FILE        Path to resolvers list (default: ~/resolvers.txt)
#   SECRETFINDER_PATH     Path to SecretFinder.py
#   SECRETFINDER_PYTHON   Python binary for SecretFinder (default: python3)
#   DIRBRUTE_WORDLIST     Wordlist for ffuf (default: seclists common.txt)
#   PARAMS_WORDLIST       Wordlist for arjun
#
# EXAMPLES:
#   ./penturion.sh target.com
#   ./penturion.sh target.com --resume
#   ./penturion.sh target.com --scope scope.txt --rate-limit 30
#   ./penturion.sh target.com --mutate --json
#   ./penturion.sh target.com --only-dirbrute --only-params
#   ./penturion.sh target.com --skip-nmap --skip-amass --skip-mutation
#   ./penturion.sh --install-deps
# ============================================================

set -euo pipefail
IFS=$'\n\t'

# ─────────────────────────────────────────
# COLOURS
# ─────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'; MAGENTA='\033[0;35m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*"; }
skip()    { echo -e "${YELLOW}[~]${RESET} Skipping: $*"; }
resumed() { echo -e "${MAGENTA}[↩]${RESET} Already done (resuming): $*"; }
banner()  {
  echo -e "\n${BOLD}${GREEN}═══════════════════════════════════════${RESET}"
  echo -e "${BOLD}${GREEN}  $*${RESET}"
  echo -e "${BOLD}${GREEN}═══════════════════════════════════════${RESET}\n"
}

# ─────────────────────────────────────────
# DEPENDENCY INSTALLER
# ─────────────────────────────────────────
install_deps() {
  banner "PENTURION v7 — Dependency Installer"
  info "Checking for Go..."
  if ! command -v go &>/dev/null; then
    error "Go not found. Install Go 1.21+ from https://go.dev/dl/ then re-run."
    exit 1
  fi

  GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/lukasikic/subzy@latest"
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/sa7mon/s3scanner@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/gwen001/github-subdomains@latest"
  )
  for pkg in "${GO_TOOLS[@]}"; do
    tool=$(basename "${pkg%%@*}")
    info "Installing $tool..."
    go install "$pkg" 2>/dev/null && success "$tool installed" || warn "$tool failed — check manually"
  done

  PIP_TOOLS=("wafw00f" "whatweb" "arjun" "paramspider" "cloud-enum" "dirsearch")
  for pt in "${PIP_TOOLS[@]}"; do
    info "pip: $pt"
    pip3 install "$pt" --quiet 2>/dev/null && success "$pt installed" || warn "$pt failed"
  done

  # GF patterns
  info "Installing gf patterns..."
  GF_DIR="$HOME/.gf"
  mkdir -p "$GF_DIR"
  if [ -d /tmp/gf-patterns ]; then rm -rf /tmp/gf-patterns; fi
  git clone --quiet https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns 2>/dev/null \
    && cp /tmp/gf-patterns/*.json "$GF_DIR/" \
    && success "gf patterns installed" || warn "gf patterns clone failed"

  # AWSBucketDump
  info "Installing AWSBucketDump..."
  if [ ! -d "$HOME/AWSBucketDump" ]; then
    git clone --quiet https://github.com/jordanpotti/AWSBucketDump "$HOME/AWSBucketDump" 2>/dev/null \
      && pip3 install -r "$HOME/AWSBucketDump/requirements.txt" --quiet \
      && success "AWSBucketDump installed" || warn "AWSBucketDump failed"
  else
    success "AWSBucketDump already present"
  fi

  # trufflehog
  info "Installing trufflehog..."
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin 2>/dev/null && success "trufflehog installed" || warn "trufflehog failed"

  # nuclei templates
  info "Updating nuclei templates..."
  nuclei -update-templates -silent 2>/dev/null || true

  # Resolvers
  RESOLVERS_DEFAULT="${RESOLVERS_FILE:-$HOME/resolvers.txt}"
  if [ ! -f "$RESOLVERS_DEFAULT" ]; then
    info "Downloading resolver list → $RESOLVERS_DEFAULT"
    curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
      -o "$RESOLVERS_DEFAULT" 2>/dev/null && success "Resolvers saved" || warn "Could not download resolvers"
  fi

  success "All dependencies installed."
  exit 0
}

# ─────────────────────────────────────────
# HELP
# ─────────────────────────────────────────
show_help() {
  sed -n '/^# ====/,/^# ====/p' "$0" | grep '^#' | sed 's/^# \?//'
  exit 0
}

# ─────────────────────────────────────────
# EARLY FLAGS
# ─────────────────────────────────────────
case "${1:-}" in
  -h|--help)      show_help ;;
  --install-deps) install_deps ;;
  "")             show_help ;;
esac

domain="$1"

# ─────────────────────────────────────────
# PATHS & CHECKPOINT
# ─────────────────────────────────────────
BASE="recon/$domain"
CHECKPOINT_FILE="$BASE/.checkpoint"
LOCK_FILE="$BASE/.lock"

checkpoint_done()  { mkdir -p "$BASE"; grep -qx "$1" "$CHECKPOINT_FILE" 2>/dev/null || echo "$1" >> "$CHECKPOINT_FILE"; }
checkpoint_check() { grep -qx "$1" "$CHECKPOINT_FILE" 2>/dev/null; }
checkpoint_clear() { rm -f "$CHECKPOINT_FILE"; success "Checkpoint cleared."; }

checkpoint_status() {
  local phases=(whois passive dns mutation resolve httpx waf ports js jsdeep secrets takeover nuclei screenshots headers techfp favicon asn dirbrute params cloud vulnhelper)
  local labels=(
    "1   WHOIS & IP Intel"        "2   Passive Enumeration"     "3   DNS Deep Dive"
    "4   Mutation"                "5   Active Resolution"        "6   Live Host / httpx"
    "7   WAF Detection"           "8   Port Scanning"            "9   JS & Endpoints"
    "9b  JS Deep Analysis"        "10  Secret Scanning"          "11  Subdomain Takeover"
    "12  Nuclei Vulns"            "13  Screenshots"              "14  CORS & Header Audit"
    "15  Tech Fingerprint"        "16  Favicon Hash Hunt"        "17  ASN & Network Intel"
    "18  Content Discovery"       "19  Parameter Enumeration"    "20  Cloud Enumeration"
    "21  Vulnerability Helpers"
  )
  echo -e "\n${BOLD}Checkpoint status for: $domain${RESET}"
  [ ! -f "$CHECKPOINT_FILE" ] && echo -e "  ${YELLOW}No checkpoint found.${RESET}" && return
  local done_count=0
  for i in "${!phases[@]}"; do
    if checkpoint_check "${phases[$i]}"; then
      echo -e "  ${GREEN}[✓ DONE ]${RESET} Phase ${labels[$i]}"
      done_count=$((done_count + 1))
    else
      echo -e "  ${YELLOW}[○ PEND ]${RESET} Phase ${labels[$i]}"
    fi
  done
  echo -e "\n  Progress: ${BOLD}${done_count}/${#phases[@]}${RESET} phases complete\n"
}

# ─────────────────────────────────────────
# DEFAULT FLAGS
# ─────────────────────────────────────────
RUN_WHOIS=true;  RUN_PASSIVE=true;   RUN_DNS=true;       RUN_MUTATION=false
RUN_RESOLVE=true; RUN_HTTPX=true;   RUN_WAF=true;        RUN_PORTS=true
RUN_JS=true;     RUN_JSDEEP=true;   RUN_SECRETS=true;    RUN_TAKEOVER=true
RUN_NUCLEI=true; RUN_SCREENSHOTS=true
RUN_HEADERS=true; RUN_TECHFP=true;  RUN_FAVICON=true
RUN_ASN=true;    RUN_DIRBRUTE=true; RUN_PARAMS=true
RUN_CLOUD=true;  RUN_VULNHELPER=true
SKIP_NMAP=false; SKIP_AMASS=false;  ONLY_MODE=false
RESUME_MODE=false; JSON_OUTPUT=false
SCOPE_FILE=""; RATE_LIMIT=50

# ─────────────────────────────────────────
# PARSE FLAGS
# ─────────────────────────────────────────
for arg in "${@:2}"; do
  case $arg in
    --resume)             RESUME_MODE=true ;;
    --reset)              checkpoint_clear; exit 0 ;;
    --status)             checkpoint_status; exit 0 ;;
    --mutate)             RUN_MUTATION=true ;;
    --json)               JSON_OUTPUT=true ;;
    --scope=*)            SCOPE_FILE="${arg#--scope=}" ;;
    --rate-limit=*)       RATE_LIMIT="${arg#--rate-limit=}" ;;
    --skip-whois)         RUN_WHOIS=false ;;
    --skip-passive)       RUN_PASSIVE=false ;;
    --skip-dns)           RUN_DNS=false ;;
    --skip-mutation)      RUN_MUTATION=false ;;
    --skip-resolve)       RUN_RESOLVE=false ;;
    --skip-httpx)         RUN_HTTPX=false ;;
    --skip-waf)           RUN_WAF=false ;;
    --skip-ports)         RUN_PORTS=false ;;
    --skip-nmap)          SKIP_NMAP=true ;;
    --skip-js)            RUN_JS=false ;;
    --skip-jsdeep)        RUN_JSDEEP=false ;;
    --skip-secrets)       RUN_SECRETS=false ;;
    --skip-takeover)      RUN_TAKEOVER=false ;;
    --skip-nuclei)        RUN_NUCLEI=false ;;
    --skip-screenshots)   RUN_SCREENSHOTS=false ;;
    --skip-headers)       RUN_HEADERS=false ;;
    --skip-techfp)        RUN_TECHFP=false ;;
    --skip-favicon)       RUN_FAVICON=false ;;
    --skip-asn)           RUN_ASN=false ;;
    --skip-dirbrute)      RUN_DIRBRUTE=false ;;
    --skip-params)        RUN_PARAMS=false ;;
    --skip-cloud)         RUN_CLOUD=false ;;
    --skip-vulnhelper)    RUN_VULNHELPER=false ;;
    --skip-amass)         SKIP_AMASS=true ;;
    --only-*)
      if [ "$ONLY_MODE" = false ]; then
        RUN_WHOIS=false; RUN_PASSIVE=false; RUN_DNS=false;      RUN_MUTATION=false
        RUN_RESOLVE=false; RUN_HTTPX=false; RUN_WAF=false;      RUN_PORTS=false
        RUN_JS=false; RUN_JSDEEP=false; RUN_SECRETS=false;      RUN_TAKEOVER=false
        RUN_NUCLEI=false; RUN_SCREENSHOTS=false
        RUN_HEADERS=false; RUN_TECHFP=false; RUN_FAVICON=false
        RUN_ASN=false; RUN_DIRBRUTE=false; RUN_PARAMS=false
        RUN_CLOUD=false; RUN_VULNHELPER=false
        ONLY_MODE=true
      fi
      case "${arg#--only-}" in
        whois)       RUN_WHOIS=true ;;
        passive)     RUN_PASSIVE=true ;;
        dns)         RUN_DNS=true ;;
        mutation)    RUN_MUTATION=true ;;
        resolve)     RUN_RESOLVE=true ;;
        httpx)       RUN_HTTPX=true ;;
        waf)         RUN_WAF=true ;;
        ports)       RUN_PORTS=true ;;
        js)          RUN_JS=true ;;
        jsdeep)      RUN_JSDEEP=true ;;
        secrets)     RUN_SECRETS=true ;;
        takeover)    RUN_TAKEOVER=true ;;
        nuclei)      RUN_NUCLEI=true ;;
        screenshots) RUN_SCREENSHOTS=true ;;
        headers)     RUN_HEADERS=true ;;
        techfp)      RUN_TECHFP=true ;;
        favicon)     RUN_FAVICON=true ;;
        asn)         RUN_ASN=true ;;
        dirbrute)    RUN_DIRBRUTE=true ;;
        params)      RUN_PARAMS=true ;;
        cloud)       RUN_CLOUD=true ;;
        vulnhelper)  RUN_VULNHELPER=true ;;
        *)           warn "Unknown --only-${arg#--only-}, ignored" ;;
      esac ;;
    *) warn "Unknown flag: $arg" ;;
  esac
done

if ! [[ "$RATE_LIMIT" =~ ^[0-9]+$ ]]; then
  error "--rate-limit must be a positive integer, got: $RATE_LIMIT"; exit 1
fi

# ─────────────────────────────────────────
# SCOPE FILTER
# ─────────────────────────────────────────
apply_scope() {
  local infile="$1" outfile="$2"
  if [ -z "$SCOPE_FILE" ] || [ ! -f "$SCOPE_FILE" ]; then
    cp "$infile" "$outfile" 2>/dev/null || touch "$outfile"
    return
  fi
  grep -f "$SCOPE_FILE" "$infile" 2>/dev/null | sort -u > "$outfile" || touch "$outfile"
  local before after
  before=$(wc -l < "$infile" 2>/dev/null || echo 0)
  after=$(wc -l < "$outfile" 2>/dev/null || echo 0)
  info "Scope filter: $before → $after subdomains kept"
}

# ─────────────────────────────────────────
# TOOL CHECK
# ─────────────────────────────────────────
REQUIRED_TOOLS=(subfinder assetfinder dnsx httpx naabu shuffledns jq curl gau katana ffuf)
OPTIONAL_TOOLS=(amass github-subdomains nuclei gowitness wafw00f subzy trufflehog gf whatweb alterx notify arjun s3scanner qsreplace cloud_enum massdns)

check_tools() {
  local missing=()
  for t in "${REQUIRED_TOOLS[@]}"; do command -v "$t" &>/dev/null || missing+=("$t"); done
  if [ ${#missing[@]} -gt 0 ]; then
    error "Missing required tools: ${missing[*]}"
    error "Run: $0 --install-deps"
    exit 1
  fi
  for t in "${OPTIONAL_TOOLS[@]}"; do command -v "$t" &>/dev/null || warn "Optional tool missing: $t"; done
}
check_tools

if [ "$RUN_MUTATION" = true ] && ! command -v alterx &>/dev/null; then
  warn "--mutate: alterx not found. Mutation skipped."; RUN_MUTATION=false
fi

# ─────────────────────────────────────────
# LOCK FILE
# ─────────────────────────────────────────
mkdir -p "$BASE"
if [ -f "$LOCK_FILE" ]; then
  LOCK_PID=$(cat "$LOCK_FILE" 2>/dev/null || echo "unknown")
  if kill -0 "$LOCK_PID" 2>/dev/null; then
    error "Another recon running for $domain (PID $LOCK_PID)."; exit 1
  else
    warn "Stale lock (PID $LOCK_PID). Removing..."; rm -f "$LOCK_FILE"
  fi
fi
echo $$ > "$LOCK_FILE"

# ─────────────────────────────────────────
# UNIFIED CLEANUP
# ─────────────────────────────────────────
CLEANUP_TMPDIRS=()
cleanup() {
  rm -f "$LOCK_FILE"
  for d in "${CLEANUP_TMPDIRS[@]:-}"; do [ -d "$d" ] && rm -rf "$d"; done
  echo -e "\n${YELLOW}[!]${RESET} Interrupted. Use --resume to continue."
}
trap cleanup EXIT INT TERM

# ─────────────────────────────────────────
# NMAP — no sudo required
# ─────────────────────────────────────────
run_nmap() {
  if [ "$(id -u)" -eq 0 ]; then
    nmap "$@"
  elif getcap "$(command -v nmap)" 2>/dev/null | grep -q cap_net_raw; then
    nmap "$@"
  else
    warn "nmap: no root/cap_net_raw — using --unprivileged"
    nmap --unprivileged "$@"
  fi
}

# ─────────────────────────────────────────
# PHASE RUNNER
# ─────────────────────────────────────────
run_phase() {
  local key="$1" label="$2" run_flag="$3" body_fn="$4"
  if [ "$RESUME_MODE" = true ] && checkpoint_check "$key"; then
    resumed "$label"; return 0
  fi
  if [ "$run_flag" = false ]; then
    skip "$label"; return 0
  fi
  banner "$label"
  "$body_fn"
  checkpoint_done "$key"
  echo -e "${MAGENTA}[✓]${RESET} Checkpoint: $key"
}

# ─────────────────────────────────────────
# DIRECTORIES
# ─────────────────────────────────────────
mkdir -p "$BASE"/{passive,active,dns,ports,web,js,js/downloaded,secrets,vulns,screenshots,whois,headers,techfp,asn,dirbrute,params,cloud,vulnhelpers,report}
cd "$BASE" || exit 1

START_TIME=$(date +%s)
if [ "$RESUME_MODE" = true ] && [ -f .start_time_epoch ]; then
  START_TIME=$(cat .start_time_epoch)
  banner "PENTURION v7 — RESUME → $domain"
else
  banner "PENTURION v7 → $domain"
  echo "$START_TIME" > .start_time_epoch
fi

echo "$domain" > .target
date -u > .start_time
[ -n "$SCOPE_FILE" ] && info "Scope: $SCOPE_FILE" || info "No scope file — all subdomains in scope"
info "Rate limit: ${RATE_LIMIT} req/s | Output: $(pwd)"

# ─────────────────────────────────────────
# PHASE PLAN DISPLAY
# ─────────────────────────────────────────
echo -e "${BOLD}Phase plan:${RESET}"
declare -A PHASE_FLAGS=(
  [whois]="$RUN_WHOIS"    [passive]="$RUN_PASSIVE"  [dns]="$RUN_DNS"
  [mutation]="$RUN_MUTATION" [resolve]="$RUN_RESOLVE" [httpx]="$RUN_HTTPX"
  [waf]="$RUN_WAF"        [ports]="$RUN_PORTS"       [js]="$RUN_JS"
  [jsdeep]="$RUN_JSDEEP"  [secrets]="$RUN_SECRETS"   [takeover]="$RUN_TAKEOVER"
  [nuclei]="$RUN_NUCLEI"  [screenshots]="$RUN_SCREENSHOTS" [headers]="$RUN_HEADERS"
  [techfp]="$RUN_TECHFP"  [favicon]="$RUN_FAVICON"   [asn]="$RUN_ASN"
  [dirbrute]="$RUN_DIRBRUTE" [params]="$RUN_PARAMS"  [cloud]="$RUN_CLOUD"
  [vulnhelper]="$RUN_VULNHELPER"
)
for pi in \
  "whois:1 :WHOIS & IP Intel" \
  "passive:2 :Passive Subdomain Enumeration" \
  "dns:3 :DNS Deep Dive" \
  "mutation:4 :Subdomain Mutation (--mutate)" \
  "resolve:5 :Active Resolution" \
  "httpx:6 :Live Host Detection" \
  "waf:7 :WAF Detection" \
  "ports:8 :Port Scanning" \
  "js:9 :JS & Endpoint Discovery" \
  "jsdeep:9b:JS Deep Analysis" \
  "secrets:10:Secret Scanning" \
  "takeover:11:Subdomain Takeover" \
  "nuclei:12:Nuclei Vuln Scanning" \
  "screenshots:13:Screenshots" \
  "headers:14:CORS & Header Audit" \
  "techfp:15:Tech Fingerprinting" \
  "favicon:16:Favicon Hash Hunt" \
  "asn:17:ASN & Network Intel" \
  "dirbrute:18:Content Discovery (ffuf)" \
  "params:19:Parameter Enumeration (arjun)" \
  "cloud:20:Cloud Enumeration (s3/azure/gcp)" \
  "vulnhelper:21:Vulnerability Helpers (gf+qsreplace)"; do
  key="${pi%%:*}"; rest="${pi#*:}"; n="${rest%%:*}"; nm="${rest#*:}"
  st="${PHASE_FLAGS[$key]:-false}"
  if [ "$RESUME_MODE" = true ] && checkpoint_check "$key"; then
    echo -e "  ${MAGENTA}[↩ DONE]${RESET} Phase $n — $nm"
  elif [ "$st" = "true" ]; then
    echo -e "  ${GREEN}[✓ RUN ]${RESET} Phase $n — $nm"
  else
    echo -e "  ${YELLOW}[~ SKIP]${RESET} Phase $n — $nm"
  fi
done
echo ""

# ════════════════════════════════════════════════════════════
# PHASE BODIES
# ════════════════════════════════════════════════════════════

# ── Phase 1 — WHOIS & IP Intel ──
phase_whois() {
  whois "$domain" > whois/whois_domain.txt 2>/dev/null || warn "whois failed"
  for rec in A AAAA MX NS TXT SOA CAA; do
    dig +short "$domain" "$rec" > "whois/${rec,,}_records.txt" 2>/dev/null || true
  done
  ROOT_IP=$(head -1 whois/a_records.txt 2>/dev/null || true)
  if [ -n "$ROOT_IP" ]; then
    curl -s "https://ipinfo.io/${ROOT_IP}/json" > whois/ipinfo.json 2>/dev/null || true
    ASN=$(jq -r '.org // "unknown"' whois/ipinfo.json 2>/dev/null || echo "unknown")
    success "Root IP: $ROOT_IP | ASN: $ASN"
  fi
  if [ -n "${SHODAN_API_KEY:-}" ] && [ -n "${ROOT_IP:-}" ]; then
    curl -s "https://api.shodan.io/shodan/host/${ROOT_IP}?key=${SHODAN_API_KEY}" \
      > whois/shodan_host.json 2>/dev/null || warn "Shodan failed"
  fi
  touch whois/a_records.txt
}

# ── Phase 2 — Passive Subdomain Enumeration ──
phase_passive() {
  local UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

  (subfinder -silent -d "$domain" -all -recursive -rl "$RATE_LIMIT" \
    -o passive/subfinder.txt 2>/dev/null || touch passive/subfinder.txt) &

  (assetfinder --subs-only "$domain" > passive/assetfinder.txt 2>/dev/null \
    || touch passive/assetfinder.txt) &

  (if [ "$SKIP_AMASS" = false ] && command -v amass &>/dev/null; then
    amass enum -passive -d "$domain" -silent > passive/amass_passive.txt 2>/dev/null \
      || touch passive/amass_passive.txt
  else touch passive/amass_passive.txt; fi) &

  (curl -s -A "$UA" "https://crt.sh/?q=%25.${domain}&output=json" \
    | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' \
    | sort -u > passive/crt_sh.txt || touch passive/crt_sh.txt) &

  (curl -s -A "$UA" "https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names" \
    | jq -r '.[].dns_names[]' 2>/dev/null | sed 's/\*\.//g' \
    | grep -E "\.?${domain}$" | sort -u > passive/certspotter.txt \
    || touch passive/certspotter.txt) &

  (curl -s -A "$UA" "http://web.archive.org/cdx/search/cdx?url=*.${domain}&output=text&fl=original&collapse=urlkey" \
    | sed -e 's_https*://__' -e 's_/.*__' \
    | grep -E "\.${domain}$" | sort -u > passive/wayback_subs.txt \
    || touch passive/wayback_subs.txt) &

  # rapiddns with retry
  (for attempt in 1 2; do
    result=$(curl -s -A "$UA" --max-time 15 "https://rapiddns.io/subdomain/${domain}?full=1" \
      | grep -oP "(?<=<td>)[a-zA-Z0-9._-]+\.${domain}(?=</td>)" | sort -u 2>/dev/null)
    [ -n "$result" ] && echo "$result" > passive/rapiddns.txt && break
    sleep 2
  done; touch passive/rapiddns.txt) &

  # GitHub subdomain hunting
  (if [ -n "${GITHUB_TOKEN:-}" ] && command -v github-subdomains &>/dev/null; then
    github-subdomains -d "$domain" -t "$GITHUB_TOKEN" -q \
      -o passive/github_subs.txt 2>/dev/null || touch passive/github_subs.txt
  else touch passive/github_subs.txt; fi) &

  # GitHub dorking for secrets (NEW — beyond just subdomains)
  (if [ -n "${GITHUB_TOKEN:-}" ]; then
    for dork in \
      "\"${domain}\" password" \
      "\"${domain}\" api_key" \
      "\"${domain}\" secret" \
      "\"${domain}\" token" \
      "\"${domain}\" aws_access_key"; do
      encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$dork'))" 2>/dev/null || echo "")
      [ -z "$encoded" ] && continue
      curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
        "https://api.github.com/search/code?q=${encoded}&per_page=5" \
        2>/dev/null | jq -r '.items[]? | "\(.repository.full_name) | \(.path) | \(.html_url)"' \
        >> passive/github_dorks.txt 2>/dev/null || true
      sleep 2  # GitHub rate limit
    done
    touch passive/github_dorks.txt
    success "GitHub dorks: $(wc -l < passive/github_dorks.txt) results"
  else
    touch passive/github_dorks.txt
    warn "GITHUB_TOKEN not set — GitHub dorking skipped"
  fi) &

  wait

  cat passive/*.txt 2>/dev/null \
    | grep -E "^[a-zA-Z0-9._-]+\.${domain}$" \
    | sed 's/\*\.//g' | sort -u > passive/all_passive_raw.txt

  apply_scope passive/all_passive_raw.txt passive/all_passive.txt
  success "Passive unique subdomains: $(wc -l < passive/all_passive.txt)"
}

# ── Phase 3 — DNS Deep Dive ──
phase_dns() {
  for ns in $(dig +short NS "$domain" 2>/dev/null); do
    dig axfr "$domain" "@$ns" 2>/dev/null >> dns/zone_transfer.txt || true
  done
  dig +dnssec "$domain"                          > dns/dnssec.txt  2>/dev/null || true
  dig +short TXT "_dmarc.${domain}"             > dns/dmarc.txt   2>/dev/null || true
  dig +short TXT "default._domainkey.${domain}" > dns/dkim.txt    2>/dev/null || true

  # Email security evaluation
  {
    SPF=$(dig +short TXT "$domain" 2>/dev/null | grep "v=spf1" || true)
    DMARC=$(cat dns/dmarc.txt 2>/dev/null)
    DKIM=$(cat dns/dkim.txt 2>/dev/null)
    [ -z "$SPF" ]   && echo "[MISSING] SPF record not found — spoofing risk"       || echo "[OK] SPF: $SPF"
    [ -z "$DMARC" ] && echo "[MISSING] DMARC record not found — spoofing risk"     || echo "[OK] DMARC: $DMARC"
    echo "$SPF" | grep -qE "\+all|~all" && echo "[WEAK] SPF uses permissive ~all or +all" || true
    [ -z "$DKIM" ]  && echo "[MISSING] DKIM default selector not found"            || echo "[OK] DKIM present"
  } > dns/email_security_eval.txt

  while IFS= read -r ip; do
    [ -n "$ip" ] && dig +short -x "$ip" >> dns/reverse_dns.txt 2>/dev/null || true
  done < whois/a_records.txt

  success "DNS complete. Email eval: $(wc -l < dns/email_security_eval.txt) findings"
}

# ── Phase 4 — Mutation (opt-in via --mutate) ──
phase_mutation() {
  grep -E "\.${domain}$" passive/all_passive.txt > active/filtered_for_mutation.txt 2>/dev/null \
    || touch active/filtered_for_mutation.txt
  alterx -l active/filtered_for_mutation.txt -limit 30000 \
    -o active/mutated.txt 2>/dev/null || touch active/mutated.txt
  success "Mutated: $(wc -l < active/mutated.txt) entries"
}

# ── Phase 5 — Active Resolution ──
phase_resolve() {
  dnsx -l passive/all_passive.txt -silent -a -cname -resp \
    -rl "$RATE_LIMIT" -o active/resolved_passive.txt 2>/dev/null || touch active/resolved_passive.txt

  RESOLVERS="${RESOLVERS_FILE:-$HOME/resolvers.txt}"

  # MassDNS for faster resolution if available
  if command -v massdns &>/dev/null && [ -f "$RESOLVERS" ]; then
    info "MassDNS active resolution..."
    massdns -r "$RESOLVERS" -t A -o S \
      passive/all_passive.txt 2>/dev/null \
      | awk '{print $1}' | sed 's/\.$//' \
      | sort -u > active/massdns_resolved.txt || touch active/massdns_resolved.txt
    success "MassDNS: $(wc -l < active/massdns_resolved.txt) resolved"
  else
    touch active/massdns_resolved.txt
  fi

  if [ "$RUN_MUTATION" = true ] && [ -s active/mutated.txt ]; then
    if [ -f "$RESOLVERS" ]; then
      shuffledns -d "$domain" -l active/mutated.txt -r "$RESOLVERS" \
        -mode resolve -silent -t 5000 -sw \
        -o active/resolved_mutated.txt 2>/dev/null || touch active/resolved_mutated.txt
    else
      dnsx -l active/mutated.txt -silent -rl "$RATE_LIMIT" \
        -o active/resolved_mutated.txt 2>/dev/null || touch active/resolved_mutated.txt
    fi
  else
    touch active/resolved_mutated.txt
  fi

  if [ "$SKIP_AMASS" = false ] && command -v amass &>/dev/null; then
    amass enum -active -d "$domain" -silent \
      -json active/amass_active.json 2>/dev/null || touch active/amass_active.json
    jq -r '.name // empty' active/amass_active.json 2>/dev/null \
      | sort -u > active/amass_active_hosts.txt || touch active/amass_active_hosts.txt
  else
    touch active/amass_active.json active/amass_active_hosts.txt
  fi

  cat active/resolved_passive.txt active/resolved_mutated.txt \
    active/massdns_resolved.txt active/amass_active_hosts.txt 2>/dev/null \
    | awk '{print $1}' | sort -u > active/final_subdomains_raw.txt

  apply_scope active/final_subdomains_raw.txt active/final_subdomains.txt
  success "Final resolved subdomains: $(wc -l < active/final_subdomains.txt)"
}

# ── Phase 6 — Live Host Detection ──
phase_httpx() {
  httpx -silent -l active/final_subdomains.txt \
    -title -sc -cl -location -td -ip -cname -cdn -favicon -hash sha256 \
    -follow-redirects -rl "$RATE_LIMIT" \
    -o web/live_hosts.txt 2>/dev/null || touch web/live_hosts.txt

  awk '{print $1}' web/live_hosts.txt | sort -u > web/live_urls.txt
  grep -i "\[CDN\]"  web/live_hosts.txt | awk '{print $1}' \
    | sed -e 's|https\?://||' -e 's|/.*||' | sort -u > web/cdn_hosts.txt 2>/dev/null || touch web/cdn_hosts.txt
  grep -iv "\[CDN\]" web/live_hosts.txt | awk '{print $1}' \
    | sed -e 's|https\?://||' -e 's|/.*||' | sort -u > web/non_cdn_hosts.txt 2>/dev/null || touch web/non_cdn_hosts.txt

  success "Live: $(wc -l < web/live_hosts.txt) | CDN: $(wc -l < web/cdn_hosts.txt) | Direct: $(wc -l < web/non_cdn_hosts.txt)"
}

# ── Phase 7 — WAF Detection ──
phase_waf() {
  if ! command -v wafw00f &>/dev/null; then
    warn "wafw00f not installed."; touch web/waf_results.json; return
  fi
  xargs -I{} -P 5 bash -c \
    'wafw00f -f json "$1" 2>/dev/null >> web/waf_results_raw.json || true' _ {} \
    < web/live_urls.txt
  jq -s '.' web/waf_results_raw.json > web/waf_results.json 2>/dev/null \
    || cp web/waf_results_raw.json web/waf_results.json 2>/dev/null || touch web/waf_results.json
  success "WAF results: $(wc -l < web/waf_results_raw.json 2>/dev/null || echo 0) entries"
}

# ── Phase 8 — Port Scanning ──
phase_ports() {
  naabu -l active/final_subdomains.txt -top-ports 1000 \
    -rate "$RATE_LIMIT" -silent 2>/dev/null \
    | httpx -silent -title -sc -rl "$RATE_LIMIT" \
    -o ports/web_ports_top1000.txt 2>/dev/null || touch ports/web_ports_top1000.txt

  naabu -l web/non_cdn_hosts.txt -p - \
    -rate "$((RATE_LIMIT * 40))" -silent 2>/dev/null \
    > ports/all_open_ports.txt || touch ports/all_open_ports.txt

  success "Open ports: $(wc -l < ports/all_open_ports.txt)"

  if [ "$SKIP_NMAP" = false ]; then
    info "Nmap service detection..."
    while IFS= read -r entry; do
      [ -z "$entry" ] && continue
      host="${entry%%:*}"; port="${entry##*:}"
      safe=$(echo "$host" | tr '.' '_')
      run_nmap -sV -sC -T4 -p "$port" "$host" \
        -oN "ports/nmap_${safe}_${port}.txt" 2>/dev/null || warn "nmap failed: $host:$port"
    done < ports/all_open_ports.txt

    info "Nmap HTTP enum..."
    while IFS= read -r host; do
      [ -z "$host" ] && continue
      safe=$(echo "$host" | tr './' '__')
      run_nmap -p 80,443,8080,8443,8000,8888 \
        --script http-enum,http-title,http-headers,http-methods \
        "$host" -oN "ports/web_enum_${safe}.txt" 2>/dev/null || warn "nmap http-enum failed: $host"
    done < web/non_cdn_hosts.txt
  else
    warn "Nmap skipped (--skip-nmap)"
  fi
}

# ── Phase 9 — JS & Endpoint Discovery ──
phase_js() {
  local GAU_TMPDIR
  GAU_TMPDIR=$(mktemp -d)
  CLEANUP_TMPDIRS+=("$GAU_TMPDIR")

  local GAU_CONCURRENCY=10 GAU_JOBS=0
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    (
      safe=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
      gau --subs --rl "$RATE_LIMIT" "$url" 2>/dev/null > "${GAU_TMPDIR}/${safe}.txt" || true
    ) &
    GAU_JOBS=$((GAU_JOBS + 1))
    if [ "$GAU_JOBS" -ge "$GAU_CONCURRENCY" ]; then wait; GAU_JOBS=0; fi
  done < web/live_urls.txt
  wait

  cat "${GAU_TMPDIR}"/*.txt 2>/dev/null | sort -u > js/gau_all_urls.txt || touch js/gau_all_urls.txt
  rm -rf "$GAU_TMPDIR"
  CLEANUP_TMPDIRS=("${CLEANUP_TMPDIRS[@]/$GAU_TMPDIR}")

  katana -list web/live_urls.txt -jc -d 3 -silent -c 10 -p 10 \
    -rl "$RATE_LIMIT" -o js/katana_all_urls.txt 2>/dev/null || touch js/katana_all_urls.txt

  cat js/gau_all_urls.txt js/katana_all_urls.txt 2>/dev/null | sort -u > js/all_urls.txt
  grep -iE "\.js(\?|$)"                                          js/all_urls.txt | sort -u > js/all_js_files.txt
  grep -iE "\.(php|asp|aspx|jsp|json|xml|do|action|api)"        js/all_urls.txt | sort -u > js/interesting_endpoints.txt
  grep -iE "(admin|login|dashboard|upload|backup|config|debug|test|dev|api|v[0-9]|auth)" \
    js/all_urls.txt | sort -u > js/sensitive_paths.txt

  success "JS files: $(wc -l < js/all_js_files.txt) | Endpoints: $(wc -l < js/interesting_endpoints.txt)"
}

# ── Phase 9b — JS Deep Analysis ──
phase_jsdeep() {
  info "Downloading $(wc -l < js/all_js_files.txt 2>/dev/null || echo 0) JS files..."
  while IFS= read -r jsurl; do
    [ -z "$jsurl" ] && continue
    status=$(curl -o /dev/null -s -w "%{http_code}" --max-time 10 "$jsurl" 2>/dev/null || echo "000")
    if [ "$status" = "200" ]; then
      safe=$(printf '%s' "$jsurl" | md5sum | cut -d' ' -f1)
      curl -sk --max-time 10 "$jsurl" -o "js/downloaded/${safe}.js" 2>/dev/null || true
    fi
  done < js/all_js_files.txt

  DOWNLOADED=$(find js/downloaded -name "*.js" -size +0c 2>/dev/null | wc -l || echo 0)
  success "Downloaded: $DOWNLOADED JS files"

  grep -rhEo \
    "(['\"])(\/[a-zA-Z0-9_/?=&.%-]{3,})(['\"])|(https?:\/\/[a-zA-Z0-9._/-]+)" \
    js/downloaded/ 2>/dev/null \
    | grep -vE "\.(png|jpg|gif|svg|css|woff|ttf)" \
    | sed "s/[\"']//g" | sort -u > js/js_extracted_endpoints.txt || touch js/js_extracted_endpoints.txt

  grep -iE "^/"                                                   js/js_extracted_endpoints.txt | sort -u > js/js_internal_paths.txt       || touch js/js_internal_paths.txt
  grep -iE "(api|graphql|admin|internal|private|v[0-9]|auth|token|oauth|upload|export|config|debug)" \
    js/js_extracted_endpoints.txt | sort -u > js/js_sensitive_endpoints.txt || touch js/js_sensitive_endpoints.txt
  grep -riE "(graphql|__schema|query\s*\{|mutation\s*\{)" js/downloaded/ 2>/dev/null \
    | cut -d: -f1 | sort -u > js/graphql_found.txt || touch js/graphql_found.txt

  grep -rhEo \
    "(api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer|private[_-]?key|client[_-]?secret|aws[_-]?access|passwd|password)\s*[:=]\s*['\"][a-zA-Z0-9+/._-]{8,}['\"]" \
    js/downloaded/ 2>/dev/null | sort -u > secrets/js_hardcoded_secrets.txt || touch secrets/js_hardcoded_secrets.txt

  grep -rhEo 'https?://[a-zA-Z0-9._-]+(:[0-9]+)?' js/downloaded/ 2>/dev/null \
    | grep -ivE '(cdn|static|fonts|google|facebook|twitter|jquery|bootstrap|cloudflare|amazonaws)' \
    | sort -u > js/js_discovered_urls.txt || touch js/js_discovered_urls.txt

  if command -v linkfinder &>/dev/null; then
    find js/downloaded -name "*.js" -size +0c | while IFS= read -r f; do
      linkfinder -i "$f" -o cli 2>/dev/null >> js/linkfinder_results.txt || true
    done
    sort -u js/linkfinder_results.txt -o js/linkfinder_results.txt
  else touch js/linkfinder_results.txt; fi

  SF_PY="${SECRETFINDER_PATH:-}"
  SF_BIN="${SECRETFINDER_PYTHON:-python3}"
  if [ -z "$SF_PY" ]; then
    for candidate in "$HOME/SecretFinder/SecretFinder.py" "/opt/SecretFinder/SecretFinder.py"; do
      [ -f "$candidate" ] && SF_PY="$candidate" && break
    done
  fi
  if [ -n "$SF_PY" ] && [ -f "$SF_PY" ] && command -v "$SF_BIN" &>/dev/null; then
    find js/downloaded -name "*.js" -size +0c | while IFS= read -r f; do
      "$SF_BIN" "$SF_PY" -i "$f" -o cli 2>/dev/null >> secrets/secretfinder_results.txt || true
    done
    sort -u secrets/secretfinder_results.txt -o secrets/secretfinder_results.txt
    success "SecretFinder: $(wc -l < secrets/secretfinder_results.txt) findings"
  else
    warn "SecretFinder not found. Set SECRETFINDER_PATH=/path/to/SecretFinder.py"
    touch secrets/secretfinder_results.txt
  fi

  success "Endpoints: $(wc -l < js/js_extracted_endpoints.txt) | Sensitive: $(wc -l < js/js_sensitive_endpoints.txt) | Secrets: $(wc -l < secrets/js_hardcoded_secrets.txt)"
}

# ── Phase 10 — Secret Scanning ──
phase_secrets() {
  if command -v trufflehog &>/dev/null; then
    trufflehog filesystem js/downloaded/ --json 2>/dev/null \
      > secrets/trufflehog.json || touch secrets/trufflehog.json
  fi
  if command -v gf &>/dev/null; then
    for pattern in secrets aws-keys firebase s3-buckets; do
      gf "$pattern" js/all_urls.txt >> secrets/gf_secrets.txt 2>/dev/null || true
    done
    touch secrets/gf_secrets.txt
  fi
  grep -iE "(api_key|apikey|secret|password|passwd|token|auth|bearer|access_key|private_key)" \
    js/all_urls.txt js/interesting_endpoints.txt 2>/dev/null \
    | sort -u > secrets/credential_patterns.txt || touch secrets/credential_patterns.txt
  success "Credential patterns: $(wc -l < secrets/credential_patterns.txt)"
}

# ── Phase 11 — Subdomain Takeover ──
phase_takeover() {
  if command -v subzy &>/dev/null; then
    subzy run --targets active/final_subdomains.txt \
      --hide_fails --output vulns/takeover_subzy.json 2>/dev/null || touch vulns/takeover_subzy.json
    success "Takeover check complete."
  else
    warn "subzy not installed — CNAME fallback..."
    while IFS= read -r sub; do
      cname=$(dig +short CNAME "$sub" 2>/dev/null)
      if [ -n "$cname" ]; then
        resolved=$(dig +short "$cname" 2>/dev/null)
        [ -z "$resolved" ] && echo "POSSIBLE TAKEOVER: $sub -> $cname (NXDOMAIN)" >> vulns/takeover_manual.txt
      fi
    done < active/final_subdomains.txt
    touch vulns/takeover_manual.txt
  fi
}

# ── Phase 12 — Nuclei Vuln Scanning ──
phase_nuclei() {
  if ! command -v nuclei &>/dev/null; then
    warn "nuclei not installed."; touch vulns/nuclei_results.txt; return
  fi
  nuclei -l web/live_urls.txt -s critical,high,medium -stats \
    -rl "$RATE_LIMIT" -o vulns/nuclei_results.txt 2>/dev/null || touch vulns/nuclei_results.txt
  nuclei -l web/live_urls.txt -t technologies/ \
    -rl "$RATE_LIMIT" -o vulns/nuclei_tech.txt 2>/dev/null || true
  nuclei -l web/live_urls.txt -tags cve -s critical,high \
    -rl "$RATE_LIMIT" -o vulns/nuclei_cves.txt 2>/dev/null || touch vulns/nuclei_cves.txt
  if [ -s js/js_sensitive_endpoints.txt ]; then
    nuclei -l js/js_sensitive_endpoints.txt -s critical,high \
      -rl "$RATE_LIMIT" -o vulns/nuclei_js_endpoints.txt 2>/dev/null || touch vulns/nuclei_js_endpoints.txt
  fi
  # Swagger/OpenAPI hunting
  nuclei -l web/live_urls.txt -tags swagger,openapi \
    -rl "$RATE_LIMIT" -o vulns/nuclei_api_specs.txt 2>/dev/null || touch vulns/nuclei_api_specs.txt
  success "Nuclei findings: $(wc -l < vulns/nuclei_results.txt 2>/dev/null || echo 0)"
}

# ── Phase 13 — Screenshots ──
phase_screenshots() {
  if command -v gowitness &>/dev/null; then
    gowitness scan file -f web/live_urls.txt \
      --screenshot-path screenshots/ \
      --write-db screenshots/gowitness.db 2>/dev/null || warn "gowitness partially failed"
    success "Screenshots saved."
  else warn "gowitness not installed."; fi
}

# ── Phase 14 — CORS & Security Header Audit ──
phase_headers() {
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    echo "=== $url ===" >> headers/raw_headers.txt
    RESP=$(curl -sk --max-time 10 -I \
      -H "Origin: https://evil-cors-test.com" \
      -H "Access-Control-Request-Method: GET" \
      "$url" 2>/dev/null) || continue
    echo "$RESP" >> headers/raw_headers.txt

    ACAO=$(echo "$RESP" | grep -i "access-control-allow-origin"      | tr -d '\r')
    ACAC=$(echo "$RESP" | grep -i "access-control-allow-credentials" | tr -d '\r')

    echo "$ACAO" | grep -q "evil-cors-test.com" && \
      echo "[CORS-REFLECT] $url" >> headers/cors_vulns.txt || true
    if echo "$ACAO" | grep -q "\*"; then
      echo "$ACAC" | grep -qi "true" \
        && echo "[CORS-WILDCARD+CREDS] $url" >> headers/cors_vulns.txt \
        || echo "[CORS-WILDCARD] $url"       >> headers/cors_info.txt
    fi
    echo "$ACAO" | grep -q "null" && echo "[CORS-NULL] $url" >> headers/cors_vulns.txt || true

    echo "$RESP" | grep -qi "strict-transport-security"    || echo "[MISSING] HSTS: $url"                >> headers/missing_headers.txt
    echo "$RESP" | grep -qi "x-frame-options\|frame-ancestors" || echo "[MISSING] X-Frame-Options: $url" >> headers/missing_headers.txt
    echo "$RESP" | grep -qi "x-content-type-options"       || echo "[MISSING] X-Content-Type: $url"      >> headers/missing_headers.txt
    echo "$RESP" | grep -qi "content-security-policy"      || echo "[MISSING] CSP: $url"                 >> headers/missing_headers.txt

    CSP=$(echo "$RESP" | grep -i "content-security-policy" | tr -d '\r')
    [ -n "$CSP" ] && echo "$CSP" | grep -qiE "unsafe-inline|unsafe-eval|script-src[^;]*\*" && \
      echo "[WEAK-CSP] $url — $CSP" >> headers/weak_csp.txt || true
  done < web/live_urls.txt

  touch headers/cors_vulns.txt headers/missing_headers.txt headers/weak_csp.txt headers/cors_info.txt
  success "CORS: $(wc -l < headers/cors_vulns.txt) | Missing: $(wc -l < headers/missing_headers.txt) | Weak CSP: $(wc -l < headers/weak_csp.txt)"
}

# ── Phase 15 — Tech Fingerprinting ──
phase_techfp() {
  if command -v whatweb &>/dev/null; then
    whatweb --no-errors -q --log-json=techfp/whatweb_full.json \
      --input-file=web/live_urls.txt 2>/dev/null || touch techfp/whatweb_full.json
    jq -r '.[] | .target as $t | .plugins | to_entries[]
            | select(.value.version != null)
            | "\($t) | \(.key) | v\(.value.version[])"' \
      techfp/whatweb_full.json 2>/dev/null | sort -u > techfp/detected_versions.txt \
      || touch techfp/detected_versions.txt
  else
    warn "whatweb not installed — header fallback..."
    while IFS= read -r url; do
      [ -z "$url" ] && continue
      RESP=$(curl -sk --max-time 10 -I "$url" 2>/dev/null)
      for hdr in server x-powered-by x-generator; do
        val=$(echo "$RESP" | grep -i "^${hdr}:" | tr -d '\r' | head -1)
        [ -n "$val" ] && echo "$url | $val" >> techfp/detected_versions.txt
      done
    done < web/live_urls.txt
    sort -u techfp/detected_versions.txt -o techfp/detected_versions.txt 2>/dev/null \
      || touch techfp/detected_versions.txt
  fi

  [ -f vulns/nuclei_tech.txt ] && [ -s vulns/nuclei_tech.txt ] && \
    cat vulns/nuclei_tech.txt >> techfp/detected_versions.txt && \
    sort -u techfp/detected_versions.txt -o techfp/detected_versions.txt

  grep -oiE "(wordpress [0-9.]+|apache [0-9.]+|nginx [0-9.]+|jquery [0-9.]+|php[/ ][0-9.]+|drupal [0-9.]+|tomcat [0-9.]+|laravel [0-9.]+)" \
    techfp/detected_versions.txt 2>/dev/null | sort -u | while IFS= read -r tech; do
      echo "https://nvd.nist.gov/vuln/search/results?query=$(echo "$tech" | tr ' ' '+')" >> techfp/cve_search_urls.txt
    done || touch techfp/cve_search_urls.txt

  success "Tech versions: $(wc -l < techfp/detected_versions.txt) | CVE queries: $(wc -l < techfp/cve_search_urls.txt 2>/dev/null || echo 0)"
}

# ── Phase 16 — Favicon Hash Hunt ──
phase_favicon() {
  grep -oP "favicon=\K[^\s]+" web/live_hosts.txt 2>/dev/null \
    | sort -u > whois/favicon_hashes.txt || touch whois/favicon_hashes.txt
  HASH_COUNT=$(wc -l < whois/favicon_hashes.txt | tr -d " " || echo 0)
  success "Favicon hashes: $HASH_COUNT"

  if [ "$HASH_COUNT" -gt 0 ]; then
    while IFS= read -r hash; do
      grep "favicon=${hash}" web/live_hosts.txt | awk '{print $1}' | head -1 \
        | xargs -I{} echo "{} → $hash" >> whois/favicon_hash_map.txt || true
    done < whois/favicon_hashes.txt

    if [ -n "${SHODAN_API_KEY:-}" ]; then
      while IFS= read -r hash; do
        [ -z "$hash" ] && continue
        RESULT=$(curl -s --max-time 15 \
          "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.favicon.hash:${hash}&facets=ip" \
          2>/dev/null) || continue
        TOTAL=$(echo "$RESULT" | jq -r '.total // 0' 2>/dev/null || echo 0)
        [ "$TOTAL" -gt 0 ] && {
          echo "=== Hash: $hash | Shodan: $TOTAL ===" >> whois/shodan_favicon_results.txt
          echo "$RESULT" | jq -r '.matches[]? | "\(.ip_str):\(.port // 80) | \(.hostnames // [] | join(",")) | \(.org // "?")"' \
            2>/dev/null >> whois/shodan_favicon_results.txt || true
        }
      done < whois/favicon_hashes.txt
    else
      while IFS= read -r hash; do
        echo "https://www.shodan.io/search?query=http.favicon.hash%3A${hash}" >> whois/favicon_shodan_urls.txt
      done < whois/favicon_hashes.txt
    fi
  fi
  touch whois/favicon_hashes.txt whois/favicon_hash_map.txt whois/shodan_favicon_results.txt
}

# ── Phase 17 — ASN & Network Intelligence (NEW) ──
phase_asn() {
  ROOT_IP=$(head -1 whois/a_records.txt 2>/dev/null || true)

  # ASN via ipinfo
  if [ -n "$ROOT_IP" ]; then
    curl -s "https://ipinfo.io/${ROOT_IP}/json" 2>/dev/null > asn/ipinfo_root.json || touch asn/ipinfo_root.json
    ASN_NUM=$(jq -r '.org // "unknown"' asn/ipinfo_root.json 2>/dev/null | grep -oP 'AS\d+' || true)
    success "ASN: $ASN_NUM"

    # Get all IPs in same ASN
    if [ -n "$ASN_NUM" ]; then
      curl -s "https://ipinfo.io/${ASN_NUM}/json" 2>/dev/null > asn/asn_details.json || touch asn/asn_details.json
      jq -r '.prefixes[]?.netblock // empty' asn/asn_details.json 2>/dev/null \
        > asn/ip_ranges.txt || touch asn/ip_ranges.txt
      success "IP ranges in ASN: $(wc -l < asn/ip_ranges.txt)"
    fi
  fi

  # amass intel for ASN
  if [ "$SKIP_AMASS" = false ] && command -v amass &>/dev/null && [ -n "${ROOT_IP:-}" ]; then
    info "amass intel — ASN enumeration..."
    amass intel -addr "$ROOT_IP" -whois -d "$domain" \
      -o asn/amass_intel.txt 2>/dev/null || touch asn/amass_intel.txt
    success "amass intel: $(wc -l < asn/amass_intel.txt) results"
  else
    touch asn/amass_intel.txt
  fi

  # CloudEnum passive
  if command -v cloud_enum &>/dev/null; then
    info "CloudEnum — passive cloud asset discovery..."
    cloud_enum -k "$domain" --disable-azure --disable-gcp \
      -l asn/cloud_enum_s3.txt 2>/dev/null || touch asn/cloud_enum_s3.txt
    success "CloudEnum results: $(wc -l < asn/cloud_enum_s3.txt)"
  else
    touch asn/cloud_enum_s3.txt
    warn "cloud_enum not installed — passive cloud discovery skipped"
  fi
}

# ── Phase 18 — Content Discovery (NEW) ──
phase_dirbrute() {
  WORDLIST="${DIRBRUTE_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
  # Fallback wordlists
  if [ ! -f "$WORDLIST" ]; then
    for fallback in \
      "/usr/share/wordlists/dirb/common.txt" \
      "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt" \
      "$HOME/wordlists/common.txt"; do
      [ -f "$fallback" ] && WORDLIST="$fallback" && break
    done
  fi
  if [ ! -f "$WORDLIST" ]; then
    warn "No wordlist found. Set DIRBRUTE_WORDLIST=/path/to/wordlist.txt"; return
  fi
  info "Using wordlist: $WORDLIST"

  mkdir -p dirbrute
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    safe=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
    ffuf -u "${url}/FUZZ" \
         -w "$WORDLIST" \
         -mc 200,201,204,301,302,307,401,403,405 \
         -t 50 \
         -rate "$RATE_LIMIT" \
         -o "dirbrute/${safe}.json" \
         -of json \
         -timeout 10 \
         -s 2>/dev/null || true
  done < web/live_urls.txt

  # Merge results
  jq -r '.results[]?.url' dirbrute/*.json 2>/dev/null \
    | sort -u > dirbrute/all_found_paths.txt || touch dirbrute/all_found_paths.txt

  # High value finds
  grep -iE "(\.env|\.git|backup|config|admin|swagger|openapi|phpinfo|\.sql|\.zip|\.bak|\.tar|wp-admin|phpmyadmin|\.DS_Store|api-docs)" \
    dirbrute/all_found_paths.txt > dirbrute/high_value.txt 2>/dev/null || touch dirbrute/high_value.txt

  # 403 bypass candidates
  grep -E "/.*" dirbrute/all_found_paths.txt \
    | while IFS= read -r path; do
      # try common 403 bypass headers
      for header in "X-Original-URL: $path" "X-Rewrite-URL: $path" "X-Custom-IP-Authorization: 127.0.0.1"; do
        resp=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
          -H "$header" "${path%/*}/" 2>/dev/null || echo "000")
        [ "$resp" = "200" ] && echo "[403-BYPASS] $path via $header" >> dirbrute/bypass_found.txt
      done
    done 2>/dev/null || touch dirbrute/bypass_found.txt

  # Feed high-value into nuclei
  if command -v nuclei &>/dev/null && [ -s dirbrute/high_value.txt ]; then
    nuclei -l dirbrute/high_value.txt -s critical,high -rl "$RATE_LIMIT" \
      -o dirbrute/nuclei_on_paths.txt 2>/dev/null || touch dirbrute/nuclei_on_paths.txt
  fi

  success "Paths found: $(wc -l < dirbrute/all_found_paths.txt) | High value: $(wc -l < dirbrute/high_value.txt) | Bypass: $(wc -l < dirbrute/bypass_found.txt 2>/dev/null || echo 0)"
}

# ── Phase 19 — Parameter Enumeration (NEW) ──
phase_params() {
  mkdir -p params

  # arjun — hidden GET/POST parameter discovery
  if command -v arjun &>/dev/null; then
    info "arjun — parameter discovery..."
    while IFS= read -r url; do
      [ -z "$url" ] && continue
      safe=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
      arjun -u "$url" -oJ "params/arjun_${safe}.json" \
        --rate-limit "$RATE_LIMIT" -q 2>/dev/null || true
    done < js/interesting_endpoints.txt
    # Merge all arjun results
    jq -s '.' params/arjun_*.json 2>/dev/null > params/arjun_all.json || touch params/arjun_all.json
    success "arjun complete: params/arjun_all.json"
  else
    warn "arjun not installed."; touch params/arjun_all.json
  fi

  # paramspider — crawl-based parameter extraction
  if command -v paramspider &>/dev/null; then
    info "paramspider..."
    paramspider -d "$domain" -o params/paramspider.txt 2>/dev/null || touch params/paramspider.txt
    success "paramspider: $(wc -l < params/paramspider.txt) params"
  else
    warn "paramspider not installed."; touch params/paramspider.txt
  fi

  # Extract params from collected URLs using gf
  if command -v gf &>/dev/null; then
    info "gf — extracting interesting parameters..."
    for pattern in xss sqli ssrf redirect lfi rce idor debug-pages upload-fields interestingparams; do
      gf "$pattern" js/all_urls.txt >> "params/gf_${pattern}.txt" 2>/dev/null || true
      touch "params/gf_${pattern}.txt"
    done
    cat params/gf_*.txt 2>/dev/null | sort -u > params/all_gf_params.txt || touch params/all_gf_params.txt
    success "gf patterns: $(wc -l < params/all_gf_params.txt) matches"
  else
    warn "gf not installed."; touch params/all_gf_params.txt
  fi

  # Swagger / OpenAPI endpoint extraction
  for spec_path in "/api-docs" "/swagger.json" "/openapi.yaml" "/openapi.json" "/api/swagger.json" "/v1/api-docs" "/v2/api-docs"; do
    while IFS= read -r base; do
      resp=$(curl -sk --max-time 10 "${base}${spec_path}" 2>/dev/null)
      echo "$resp" | grep -qE "(swagger|openapi)" && \
        echo "${base}${spec_path}" >> params/api_specs_found.txt && \
        echo "$resp" >> "params/spec_${safe:-unknown}.json" || true
    done < web/live_urls.txt
  done
  touch params/api_specs_found.txt
  [ -s params/api_specs_found.txt ] && success "API specs found: $(wc -l < params/api_specs_found.txt)"

  success "Parameter enumeration complete"
}

# ── Phase 20 — Cloud Enumeration (NEW) ──
phase_cloud() {
  mkdir -p cloud

  KEYWORDS=("$domain" "${domain%%.*}" "${domain//./-}")

  # S3Scanner — passive + active
  if command -v s3scanner &>/dev/null; then
    info "s3scanner — S3 bucket enumeration..."
    for kw in "${KEYWORDS[@]}"; do
      # Generate common bucket name variations
      for variation in "$kw" "${kw}-backup" "${kw}-dev" "${kw}-prod" "${kw}-staging" "${kw}-assets" "${kw}-static" "${kw}-media" "${kw}-files" "${kw}-data"; do
        echo "$variation"
      done
    done | sort -u > cloud/bucket_wordlist.txt

    s3scanner scan --bucket-file cloud/bucket_wordlist.txt \
      -o cloud/s3scanner_results.txt 2>/dev/null || touch cloud/s3scanner_results.txt
    grep -iE "(open|public|listable)" cloud/s3scanner_results.txt \
      > cloud/s3_open_buckets.txt 2>/dev/null || touch cloud/s3_open_buckets.txt
    success "S3 open buckets: $(wc -l < cloud/s3_open_buckets.txt)"
  else
    warn "s3scanner not installed."; touch cloud/s3scanner_results.txt cloud/s3_open_buckets.txt
  fi

  # AWSBucketDump — content dumping from open buckets
  AWSBUCKET_PY="$HOME/AWSBucketDump/AWSBucketDump.py"
  if [ -f "$AWSBUCKET_PY" ] && [ -s cloud/s3_open_buckets.txt ]; then
    info "AWSBucketDump — checking open buckets..."
    while IFS= read -r bucket; do
      name=$(echo "$bucket" | grep -oP '[a-zA-Z0-9._-]+' | head -1)
      python3 "$AWSBUCKET_PY" -b "$name" -d cloud/dump/ 2>/dev/null || true
    done < cloud/s3_open_buckets.txt
    success "AWSBucketDump complete: cloud/dump/"
  else
    touch cloud/dump 2>/dev/null || true
  fi

  # Azure blob + GCP bucket passive check
  for kw in "${KEYWORDS[@]}"; do
    for azure_var in "$kw" "${kw}storage" "${kw}backup" "${kw}assets"; do
      resp=$(curl -sk --max-time 8 "https://${azure_var}.blob.core.windows.net" 2>/dev/null)
      echo "$resp" | grep -qi "BlobService\|PublicAccessNotPermitted\|container" && \
        echo "[AZURE-BLOB] https://${azure_var}.blob.core.windows.net" >> cloud/azure_blobs.txt || true
    done

    for gcp_var in "$kw" "${kw}-bucket" "${kw}-storage"; do
      resp=$(curl -sk --max-time 8 "https://storage.googleapis.com/${gcp_var}" 2>/dev/null)
      echo "$resp" | grep -qi "ListBucketResult\|AccessDenied\|NoSuchBucket" || \
        echo "$resp" | grep -qi "xml" && \
        echo "[GCP-BUCKET] https://storage.googleapis.com/${gcp_var}" >> cloud/gcp_buckets.txt || true
    done
  done
  touch cloud/azure_blobs.txt cloud/gcp_buckets.txt

  CLOUD_TOTAL=$(($(wc -l < cloud/s3_open_buckets.txt 2>/dev/null || echo 0) + \
                 $(wc -l < cloud/azure_blobs.txt 2>/dev/null || echo 0) + \
                 $(wc -l < cloud/gcp_buckets.txt 2>/dev/null || echo 0)))
  success "Cloud assets found: $CLOUD_TOTAL (S3: $(wc -l < cloud/s3_open_buckets.txt 2>/dev/null || echo 0) | Azure: $(wc -l < cloud/azure_blobs.txt 2>/dev/null || echo 0) | GCP: $(wc -l < cloud/gcp_buckets.txt 2>/dev/null || echo 0))"
}

# ── Phase 21 — Vulnerability Helpers (NEW) ──
phase_vulnhelper() {
  mkdir -p vulnhelpers

  if ! command -v gf &>/dev/null; then
    warn "gf not installed — vulnerability helpers skipped."; return
  fi
  if ! command -v qsreplace &>/dev/null; then
    warn "qsreplace not installed — some helpers skipped."
  fi

  # XSS candidates
  gf xss js/all_urls.txt 2>/dev/null | sort -u > vulnhelpers/xss_candidates.txt || touch vulnhelpers/xss_candidates.txt
  if command -v qsreplace &>/dev/null && [ -s vulnhelpers/xss_candidates.txt ]; then
    cat vulnhelpers/xss_candidates.txt \
      | qsreplace '"><script>alert(1)</script>' \
      | while IFS= read -r url; do
        resp=$(curl -sk --max-time 8 "$url" 2>/dev/null)
        echo "$resp" | grep -q '<script>alert(1)</script>' && \
          echo "[XSS-REFLECTED] $url" >> vulnhelpers/xss_confirmed.txt
      done
    touch vulnhelpers/xss_confirmed.txt
    success "XSS confirmed: $(wc -l < vulnhelpers/xss_confirmed.txt)"
  fi

  # SQLi candidates
  gf sqli js/all_urls.txt 2>/dev/null | sort -u > vulnhelpers/sqli_candidates.txt || touch vulnhelpers/sqli_candidates.txt
  if command -v qsreplace &>/dev/null && [ -s vulnhelpers/sqli_candidates.txt ]; then
    cat vulnhelpers/sqli_candidates.txt \
      | qsreplace "'" \
      | while IFS= read -r url; do
        resp=$(curl -sk --max-time 8 "$url" 2>/dev/null)
        echo "$resp" | grep -qiE "(sql syntax|mysql_fetch|ORA-[0-9]|Warning.*mysql|You have an error)" && \
          echo "[SQLI-ERROR] $url" >> vulnhelpers/sqli_error_based.txt
      done
    touch vulnhelpers/sqli_error_based.txt
    success "SQLi error-based: $(wc -l < vulnhelpers/sqli_error_based.txt)"
  fi

  # Open redirect candidates
  gf redirect js/all_urls.txt 2>/dev/null | sort -u > vulnhelpers/redirect_candidates.txt || touch vulnhelpers/redirect_candidates.txt
  if command -v qsreplace &>/dev/null && [ -s vulnhelpers/redirect_candidates.txt ]; then
    cat vulnhelpers/redirect_candidates.txt \
      | qsreplace 'https://evil.com' \
      | while IFS= read -r url; do
        location=$(curl -sk --max-time 8 -I "$url" 2>/dev/null | grep -i "^location:" | tr -d '\r')
        echo "$location" | grep -q "evil.com" && \
          echo "[OPEN-REDIRECT] $url → $location" >> vulnhelpers/open_redirect_confirmed.txt
      done
    touch vulnhelpers/open_redirect_confirmed.txt
    success "Open redirects: $(wc -l < vulnhelpers/open_redirect_confirmed.txt)"
  fi

  # SSRF candidates
  gf ssrf js/all_urls.txt 2>/dev/null | sort -u > vulnhelpers/ssrf_candidates.txt || touch vulnhelpers/ssrf_candidates.txt

  # LFI candidates
  gf lfi js/all_urls.txt 2>/dev/null | sort -u > vulnhelpers/lfi_candidates.txt || touch vulnhelpers/lfi_candidates.txt

  # IDOR candidates
  gf idor js/all_urls.txt 2>/dev/null | sort -u > vulnhelpers/idor_candidates.txt || touch vulnhelpers/idor_candidates.txt

  TOTAL_CANDIDATES=$(cat vulnhelpers/xss_candidates.txt vulnhelpers/sqli_candidates.txt \
    vulnhelpers/redirect_candidates.txt vulnhelpers/ssrf_candidates.txt \
    vulnhelpers/lfi_candidates.txt vulnhelpers/idor_candidates.txt 2>/dev/null | wc -l || echo 0)
  success "Total vuln candidates: $TOTAL_CANDIDATES | XSS: $(wc -l < vulnhelpers/xss_candidates.txt) | SQLi: $(wc -l < vulnhelpers/sqli_candidates.txt) | Redirect: $(wc -l < vulnhelpers/redirect_candidates.txt)"
}

# ════════════════════════════════════════════════════════════
# EXECUTE PHASES
# ════════════════════════════════════════════════════════════
run_phase "whois"       "PHASE 1  — WHOIS & IP INTEL"                    "$RUN_WHOIS"       phase_whois
run_phase "passive"     "PHASE 2  — PASSIVE SUBDOMAIN ENUMERATION"       "$RUN_PASSIVE"     phase_passive
run_phase "dns"         "PHASE 3  — DNS DEEP DIVE"                       "$RUN_DNS"         phase_dns
run_phase "mutation"    "PHASE 4  — MUTATION (--mutate to enable)"       "$RUN_MUTATION"    phase_mutation
run_phase "resolve"     "PHASE 5  — ACTIVE RESOLUTION"                   "$RUN_RESOLVE"     phase_resolve
run_phase "httpx"       "PHASE 6  — LIVE HOST DETECTION"                 "$RUN_HTTPX"       phase_httpx
run_phase "waf"         "PHASE 7  — WAF DETECTION"                       "$RUN_WAF"         phase_waf
run_phase "ports"       "PHASE 8  — PORT SCANNING"                       "$RUN_PORTS"       phase_ports
run_phase "js"          "PHASE 9  — JS & ENDPOINT DISCOVERY"             "$RUN_JS"          phase_js
run_phase "jsdeep"      "PHASE 9b — JS DEEP ANALYSIS"                    "$RUN_JSDEEP"      phase_jsdeep
run_phase "secrets"     "PHASE 10 — SECRET SCANNING"                     "$RUN_SECRETS"     phase_secrets
run_phase "takeover"    "PHASE 11 — SUBDOMAIN TAKEOVER"                  "$RUN_TAKEOVER"    phase_takeover
run_phase "nuclei"      "PHASE 12 — VULNERABILITY SCANNING"              "$RUN_NUCLEI"      phase_nuclei
run_phase "screenshots" "PHASE 13 — SCREENSHOTS"                         "$RUN_SCREENSHOTS" phase_screenshots
run_phase "headers"     "PHASE 14 — CORS & SECURITY HEADER AUDIT"        "$RUN_HEADERS"     phase_headers
run_phase "techfp"      "PHASE 15 — TECH FINGERPRINTING"                 "$RUN_TECHFP"      phase_techfp
run_phase "favicon"     "PHASE 16 — FAVICON HASH HUNT"                   "$RUN_FAVICON"     phase_favicon
run_phase "asn"         "PHASE 17 — ASN & NETWORK INTEL"                 "$RUN_ASN"         phase_asn
run_phase "dirbrute"    "PHASE 18 — CONTENT DISCOVERY"                   "$RUN_DIRBRUTE"    phase_dirbrute
run_phase "params"      "PHASE 19 — PARAMETER ENUMERATION"               "$RUN_PARAMS"      phase_params
run_phase "cloud"       "PHASE 20 — CLOUD ENUMERATION"                   "$RUN_CLOUD"       phase_cloud
run_phase "vulnhelper"  "PHASE 21 — VULNERABILITY HELPERS"               "$RUN_VULNHELPER"  phase_vulnhelper

# ── JSON + Report ──
info "Generating reports..."
bash "$(dirname "$0")/report.sh" "$domain" "$(pwd)" "$JSON_OUTPUT" "$SCOPE_FILE" "$RATE_LIMIT" \
  2>/dev/null || warn "report.sh not found — run manually: ./report.sh $domain $(pwd)"

# ── Notification ──
if command -v notify &>/dev/null && [ -f ~/.config/notify/provider-config.yaml ]; then
  LIVE_COUNT=$(wc -l < web/live_hosts.txt 2>/dev/null || echo 0)
  CORS=$(wc -l < headers/cors_vulns.txt 2>/dev/null || echo 0)
  NUCLEI_F=$(wc -l < vulns/nuclei_results.txt 2>/dev/null || echo 0)
  echo "PENTURION v7 done: $domain | Live: $LIVE_COUNT | CORS: $CORS | Nuclei: $NUCLEI_F" \
    | notify -silent 2>/dev/null || true
fi

banner "PENTURION v7 — COMPLETE"
info "Output: recon/$domain/"
success "Done. Run ./report.sh $domain $(pwd) to regenerate report."

trap - EXIT INT TERM
rm -f "$LOCK_FILE"