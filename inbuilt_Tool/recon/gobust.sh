#!/bin/bash

target="$1"

domain=$(echo "$target" | sed 's|https\?://||' | cut -d/ -f1)

output_dir="/home/arunexploit/Penturion/output"
dir_wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
dns_wordlist="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
exts="php,html,txt"

rm -f "$output_dir/dirs.txt" "$output_dir/subdomains.txt" "$output_dir/vhosts.txt" 2>/dev/null

echo "[*] Scanning Directories on $target..."
gobuster dir -u "$target" -w "$dir_wordlist" -x "$exts" -t 50 \
  -s 200,204 --status-codes-blacklist "" \
  -o "$output_dir/dirs.txt"

echo "[*] Enumerating Subdomains on $domain..."
gobuster dns -d "$domain" -w "$dns_wordlist" -t 50 -o "$output_dir/subdomains.txt"

read -p "Run VHOST brute-force? (y/n): " vhost_run
if [[ "$vhost_run" == "y" || "$vhost_run" == "Y" ]]; then
  echo "[*] Scanning for virtual hosts..."
  gobuster vhost -u "$target" -w "$dir_wordlist" -t 50 -o "$output_dir/vhosts.txt"
fi

echo -e "\n✅ [✓] Gobuster recon complete."
echo "📁 Results saved in: $output_dir"

# Clean subdomains output from colors and prefix
sed -r 's/\x1B\[[0-9;]*[mK]//g' "$output_dir/subdomains.txt" | sed 's/^Found: //g' | grep -v '^$' > "$output_dir/clean_subdomains.txt"

# Make screenshots dir if not exist
mkdir -p "$output_dir/screenshots"

echo "[*] Starting gowitness screenshots for discovered subdomains..."

while IFS= read -r domain; do
  echo "[*] Scanning http://$domain"
  gowitness scan single -u "http://$domain" -s "$output_dir/screenshots" --write-screenshots

  echo "[*] Scanning https://$domain"
  gowitness scan single -u "https://$domain" -s "$output_dir/screenshots" --write-screenshots
done < "$output_dir/clean_subdomains.txt"

echo "[✓] All screenshots saved in $output_dir/screenshots"
