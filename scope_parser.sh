#!/bin/bash

# ============================================================
# PENTURION v7 — scope_parser.sh
# Parses Burp Suite scope.json format and filters
# subdomain lists and URL lists accordingly.
#
# Burp scope.json structure:
#   target.scope.include[] — { host, file, port, protocol, enabled }
#   target.scope.exclude[] — { host, file, port, protocol, enabled }
#
# Usage:
#   source scope_parser.sh                        # load functions
#   parse_burp_scope scope.json                   # initialise
#   apply_scope_subdomains input.txt output.txt   # filter subdomains
#   apply_scope_urls      input.txt output.txt    # filter full URLs
#
# Standalone test:
#   ./scope_parser.sh scope.json subdomains.txt urls.txt
# ============================================================

# ─────────────────────────────────────────
# GLOBALS set by parse_burp_scope()
# ─────────────────────────────────────────
SCOPE_INCLUDE_HOSTS=()   # regex patterns for in-scope hosts
SCOPE_EXCLUDE_HOSTS=()   # regex patterns for excluded hosts
SCOPE_INCLUDE_FILES=()   # corresponding file (path) patterns
SCOPE_EXCLUDE_FILES=()
SCOPE_INCLUDE_PORTS=()
SCOPE_EXCLUDE_PORTS=()
SCOPE_INCLUDE_PROTOS=()
SCOPE_EXCLUDE_PROTOS=()
SCOPE_LOADED=false

# ─────────────────────────────────────────
# parse_burp_scope <scope.json>
# Reads include/exclude arrays into global arrays.
# ─────────────────────────────────────────
parse_burp_scope() {
  local json_file="$1"

  if [ ! -f "$json_file" ]; then
    echo "[-] scope_parser: file not found: $json_file" >&2
    return 1
  fi

  if ! command -v jq &>/dev/null; then
    echo "[-] scope_parser: jq is required" >&2
    return 1
  fi

  # Validate it looks like a Burp scope file
  local check
  check=$(jq -r '.target.scope // empty' "$json_file" 2>/dev/null)
  if [ -z "$check" ]; then
    echo "[-] scope_parser: not a valid Burp scope.json (missing .target.scope)" >&2
    return 1
  fi

  echo "[*] Parsing Burp scope: $json_file" >&2

  # ── Load INCLUDE rules (enabled only) ──
  local count_in count_ex
  count_in=$(jq '[.target.scope.include[] | select(.enabled==true)] | length' "$json_file" 2>/dev/null || echo 0)
  count_ex=$(jq '[.target.scope.exclude[] | select(.enabled==true)] | length' "$json_file" 2>/dev/null || echo 0)

  for i in $(seq 0 $((count_in - 1))); do
    SCOPE_INCLUDE_HOSTS+=("$(jq -r ".target.scope.include[$i].host"     "$json_file" 2>/dev/null)")
    SCOPE_INCLUDE_FILES+=("$(jq -r ".target.scope.include[$i].file"     "$json_file" 2>/dev/null)")
    SCOPE_INCLUDE_PORTS+=("$(jq -r ".target.scope.include[$i].port"     "$json_file" 2>/dev/null)")
    SCOPE_INCLUDE_PROTOS+=("$(jq -r ".target.scope.include[$i].protocol" "$json_file" 2>/dev/null)")
  done

  for i in $(seq 0 $((count_ex - 1))); do
    SCOPE_EXCLUDE_HOSTS+=("$(jq -r ".target.scope.exclude[$i].host"     "$json_file" 2>/dev/null)")
    SCOPE_EXCLUDE_FILES+=("$(jq -r ".target.scope.exclude[$i].file"     "$json_file" 2>/dev/null)")
    SCOPE_EXCLUDE_PORTS+=("$(jq -r ".target.scope.exclude[$i].port"     "$json_file" 2>/dev/null)")
    SCOPE_EXCLUDE_PROTOS+=("$(jq -r ".target.scope.exclude[$i].protocol" "$json_file" 2>/dev/null)")
  done

  SCOPE_LOADED=true
  echo "[+] Scope loaded: $count_in include rules, $count_ex exclude rules" >&2

  # Print human-readable scope summary
  echo "" >&2
  echo "  IN-SCOPE hosts:" >&2
  for h in "${SCOPE_INCLUDE_HOSTS[@]}"; do echo "    + $h" >&2; done
  echo "  OUT-OF-SCOPE hosts:" >&2
  for h in "${SCOPE_EXCLUDE_HOSTS[@]}"; do echo "    - $h" >&2; done
  echo "" >&2
}

# ─────────────────────────────────────────
# _host_in_scope <hostname>
# Returns 0 (true) if hostname matches an include rule
# AND does not match any exclude rule.
# ─────────────────────────────────────────
_host_in_scope() {
  local host="$1"

  # Must match at least one INCLUDE host pattern
  local matched_include=false
  for pattern in "${SCOPE_INCLUDE_HOSTS[@]}"; do
    if echo "$host" | grep -qP "$pattern" 2>/dev/null; then
      matched_include=true
      break
    fi
  done
  [ "$matched_include" = false ] && return 1

  # Must NOT match any EXCLUDE host pattern
  for pattern in "${SCOPE_EXCLUDE_HOSTS[@]}"; do
    if echo "$host" | grep -qP "$pattern" 2>/dev/null; then
      return 1   # excluded
    fi
  done

  return 0   # in scope
}

# ─────────────────────────────────────────
# _url_in_scope <full_url>
# Checks host, path, port, and protocol against
# include and exclude rules.
# ─────────────────────────────────────────
_url_in_scope() {
  local url="$1"

  # Parse URL components
  local proto host port path
  proto=$(echo "$url" | grep -oP '^https?' 2>/dev/null || echo "https")
  host=$(echo "$url"  | sed -e 's|https\?://||' -e 's|/.*||' -e 's|:.*||')
  port=$(echo "$url"  | grep -oP ':\d+' | tr -d ':' | head -1)
  path=$(echo "$url"  | sed -e 's|https\?://[^/]*||')

  # Default ports
  if [ -z "$port" ]; then
    [ "$proto" = "https" ] && port="443" || port="80"
  fi

  # ── Check INCLUDE rules ──
  local matched_include=false
  local matched_idx=-1
  for i in "${!SCOPE_INCLUDE_HOSTS[@]}"; do
    local h_pat="${SCOPE_INCLUDE_HOSTS[$i]}"
    local f_pat="${SCOPE_INCLUDE_FILES[$i]}"
    local p_pat="${SCOPE_INCLUDE_PORTS[$i]}"
    local proto_pat="${SCOPE_INCLUDE_PROTOS[$i]}"

    echo "$host"  | grep -qP "$h_pat"     2>/dev/null || continue
    echo "$port"  | grep -qP "$p_pat"     2>/dev/null || continue
    echo "$proto" | grep -qP "$proto_pat" 2>/dev/null || continue
    # path pattern — use "/" if path is empty
    echo "${path:-/}" | grep -qP "$f_pat" 2>/dev/null || continue

    matched_include=true
    matched_idx=$i
    break
  done
  [ "$matched_include" = false ] && return 1

  # ── Check EXCLUDE rules ──
  for i in "${!SCOPE_EXCLUDE_HOSTS[@]}"; do
    local h_pat="${SCOPE_EXCLUDE_HOSTS[$i]}"
    local f_pat="${SCOPE_EXCLUDE_FILES[$i]}"
    local p_pat="${SCOPE_EXCLUDE_PORTS[$i]}"
    local proto_pat="${SCOPE_EXCLUDE_PROTOS[$i]}"

    echo "$host"  | grep -qP "$h_pat"     2>/dev/null || continue
    echo "$port"  | grep -qP "$p_pat"     2>/dev/null || continue
    echo "$proto" | grep -qP "$proto_pat" 2>/dev/null || continue
    echo "${path:-/}" | grep -qP "$f_pat" 2>/dev/null || continue

    return 1   # excluded
  done

  return 0   # in scope
}

# ─────────────────────────────────────────
# apply_scope_subdomains <input> <output>
# Filters a plain subdomain list (one hostname per line)
# ─────────────────────────────────────────
apply_scope_subdomains() {
  local infile="$1" outfile="$2"

  if [ "$SCOPE_LOADED" = false ]; then
    cp "$infile" "$outfile" 2>/dev/null || touch "$outfile"
    echo "[~] No scope loaded — copying unchanged" >&2
    return
  fi

  local before after
  before=$(wc -l < "$infile" 2>/dev/null || echo 0)
  : > "$outfile"

  while IFS= read -r host; do
    [ -z "$host" ] && continue
    _host_in_scope "$host" && echo "$host" >> "$outfile" || true
  done < "$infile"

  sort -u "$outfile" -o "$outfile" 2>/dev/null || true
  after=$(wc -l < "$outfile" 2>/dev/null || echo 0)
  echo "[+] Scope filter (subdomains): $before → $after kept" >&2
}

# ─────────────────────────────────────────
# apply_scope_urls <input> <output>
# Filters a full URL list — checks host + path + port + proto
# ─────────────────────────────────────────
apply_scope_urls() {
  local infile="$1" outfile="$2"

  if [ "$SCOPE_LOADED" = false ]; then
    cp "$infile" "$outfile" 2>/dev/null || touch "$outfile"
    echo "[~] No scope loaded — copying unchanged" >&2
    return
  fi

  local before after
  before=$(wc -l < "$infile" 2>/dev/null || echo 0)
  : > "$outfile"

  while IFS= read -r url; do
    [ -z "$url" ] && continue
    _url_in_scope "$url" && echo "$url" >> "$outfile" || true
  done < "$infile"

  sort -u "$outfile" -o "$outfile" 2>/dev/null || true
  after=$(wc -l < "$outfile" 2>/dev/null || echo 0)
  echo "[+] Scope filter (URLs): $before → $after kept" >&2
}

# ─────────────────────────────────────────
# scope_summary
# Print a human-readable table of what's in/out of scope
# ─────────────────────────────────────────
scope_summary() {
  if [ "$SCOPE_LOADED" = false ]; then
    echo "No scope loaded." >&2; return
  fi

  echo ""
  echo "┌────────────────────────────────────────────────┐"
  echo "│  PENTURION — Burp Scope Summary                │"
  echo "├────────────────────────────────────────────────┤"
  echo "│  IN-SCOPE                                      │"
  for i in "${!SCOPE_INCLUDE_HOSTS[@]}"; do
    printf "│  + %-20s  %-10s  %s\n" \
      "${SCOPE_INCLUDE_HOSTS[$i]}" \
      "${SCOPE_INCLUDE_PROTOS[$i]}:${SCOPE_INCLUDE_PORTS[$i]}" \
      "${SCOPE_INCLUDE_FILES[$i]}" | head -c 80
    echo "  │"
  done
  echo "├────────────────────────────────────────────────┤"
  echo "│  OUT-OF-SCOPE                                  │"
  for i in "${!SCOPE_EXCLUDE_HOSTS[@]}"; do
    printf "│  - %-20s  %-10s  %s\n" \
      "${SCOPE_EXCLUDE_HOSTS[$i]}" \
      "${SCOPE_EXCLUDE_PROTOS[$i]}:${SCOPE_EXCLUDE_PORTS[$i]}" \
      "${SCOPE_EXCLUDE_FILES[$i]}" | head -c 80
    echo "  │"
  done
  echo "└────────────────────────────────────────────────┘"
  echo ""
}

# ─────────────────────────────────────────
# STANDALONE MODE
# ./scope_parser.sh scope.json [subdomains.txt] [urls.txt]
# ─────────────────────────────────────────
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [ -z "${1:-}" ]; then
    echo "Usage: $0 <scope.json> [subdomains.txt] [urls.txt]"
    echo "  or source it: source scope_parser.sh"
    exit 1
  fi

  parse_burp_scope "$1"
  scope_summary

  if [ -n "${2:-}" ] && [ -f "$2" ]; then
    echo "[*] Filtering subdomains: $2"
    apply_scope_subdomains "$2" "${2%.txt}_scoped.txt"
    echo "[+] Output: ${2%.txt}_scoped.txt"
  fi

  if [ -n "${3:-}" ] && [ -f "$3" ]; then
    echo "[*] Filtering URLs: $3"
    apply_scope_urls "$3" "${3%.txt}_scoped.txt"
    echo "[+] Output: ${3%.txt}_scoped.txt"
  fi
fi