#!/bin/bash

# Check arguments
ip_address="$1"
box_name="$2"

if [[ -z "$ip_address" || -z "$box_name" ]]; then
  echo -e "Usage: ./lazyhacker.sh [IP] [BoxName]\nExample: ./lazyhacker.sh 10.10.11.123 spookybox"
  exit 1
fi

# Validate IP format
valid_ip_regex='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
if [[ ! "$ip_address" =~ $valid_ip_regex ]]; then
  echo "Invalid IP address format."
  exit 1
fi

# Ask for sudo permissions early
echo "Requesting sudo access..."
sudo -v || exit 1

# Create output directory
base_dir="$box_name"
counter=1
while [[ -d "$base_dir" ]]; do
  base_dir="${box_name}${counter}"
  ((counter++))
done

mkdir "$base_dir"
cd "$base_dir" || exit 1
echo "Output directory created: $base_dir"

# Detect redirect domain
redirect_domain=$(curl -s -I http://$ip_address | grep -i "Location:" | sed -E 's/.*https?:\/\/([^\/]+).*/\1/' | tr -d '\r')
if [[ -n "$redirect_domain" ]]; then
  echo "Detected domain: $redirect_domain"
  domain="$redirect_domain"
  if ! grep -q "$domain" /etc/hosts; then
    echo "$ip_address    $domain" | sudo tee -a /etc/hosts > /dev/null
    echo "Added $domain to /etc/hosts"
  fi
else
  echo "No redirect domain detected. Using IP only."
  domain=""
fi

# Set up wordlists
wordlist_dir="/usr/share/wordlists/dirb/common.txt"
wordlist_subs="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"

# Start scans (7 total steps)
total_scans=7
scans_done=0
update_counter() {
  ((scans_done++))
  echo -e "\n[+] Scan completed ($scans_done/$total_scans)\n"
}

# TCP Nmap
echo "Starting Nmap TCP scan..."
nmap -sV -A "$ip_address" > nmap.txt &
nmap_pid=$!

# UDP Nmap
echo "Starting Nmap UDP scan..."
nmap -sU --top-ports=100 "$ip_address" > nmap_udp.txt &
nmap_udp_pid=$!

# FFUF initial directory scan
if [[ -n "$domain" ]]; then
  echo "Starting FFUF directory scan..."
  ffuf -w "$wordlist_dir":FUZZ -u http://$domain/FUZZ -s -v > ffuf_initial &
  ffuf_initial_pid=$!
else
  ffuf_initial_pid=""    
fi

# FFUF subdomain scan
if [[ -n "$domain" ]]; then
  echo "Starting FFUF subdomain scan..."
  ffuf -u http://$domain -H "Host: FUZZ.$domain" -w "$wordlist_subs":FUZZ -s -v > ffuf_subs &
  ffuf_subs_pid=$!
else
  ffuf_subs_pid=""
fi

# Wait for each scan and display results as they finish
wait $nmap_pid && { echo -e "\n[Nmap TCP results]\n"; cat nmap.txt; update_counter; }
wait $nmap_udp_pid && { echo -e "\n[Nmap UDP results]\n"; cat nmap_udp.txt; update_counter; }

if [[ -n "$ffuf_initial_pid" ]]; then
  wait $ffuf_initial_pid && {
    echo -e "\n[FFUF Directory Results]\n"
    jq -r '.results[] | "\(.url) [\(.status)]"' ffuf_initial.json
    update_counter
  }
fi

if [[ -n "$ffuf_subs_pid" ]]; then
  wait $ffuf_subs_pid && {
    echo -e "\n[FFUF Subdomain Results]\n"
    jq -r '.results[] | select(.status==200) | .host' ffuf_subs.json | while read sub; do
      if ! grep -q "$sub" /etc/hosts; then
        echo "$ip_address    $sub" | sudo tee -a /etc/hosts > /dev/null
        echo "Added $sub to /etc/hosts"
      fi
    done
    update_counter
  }
fi

# Fuzz inside found dirs
if [[ -f ffuf_initial.json ]]; then
  echo -e "\n[+] Deep fuzzing inside discovered directories..."
  jq -r '.results[] | select(.status == 200) | .url' ffuf_initial.json | while read url; do
    if [[ "$url" =~ /$ ]]; then
      echo -e "\nFuzzing: $url"
      ffuf -u "${url}FUZZ" -w "$wordlist_dir" -o "ffuf_deep_$(basename "$url").json" -of json > /dev/null
      echo "Done: $url"
      update_counter
    fi
  done
fi

# Fuzz discovered subdomains
if [[ -f ffuf_subs.json ]]; then
  echo -e "\n[+] Fuzzing discovered subdomains..."
  jq -r '.results[] | select(.status == 200) | .host' ffuf_subs.json | while read sub; do
    echo "Fuzzing: http://$sub"
    ffuf -u http://$sub/FUZZ -w "$wordlist_dir" -o "ffuf_$sub.json" -of json > /dev/null
    echo "Done: $sub"
    update_counter
  done
fi

echo -e "\n✅ All scans completed ($scans_done/$total_scans)"
