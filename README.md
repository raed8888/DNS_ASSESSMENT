📌 DNS Security Assessment – July 2025

Small DNS auditing tool built during my internship at Pwn and Patch (July 2025).
It analyzes DNS records, detects misconfigurations, applies a simple risk scoring system, and generates a CSV report.

🔍 What It Does

Fetches DNS records (A, MX, CNAME, TXT, NS, SOA)

Checks for common security issues

Missing/weak SPF

Missing DMARC

Suspicious TXT entries

Misconfigured MX

Potential takeover risks

Scores each issue based on severity

Exports everything into report.csv

Supports subdomain enumeration via subdomains4.txt

🗂️ Files
main.rb              # Runs the whole DNS assessment
dns_analyzer.rb      # DNS record extraction & validation
risk_scoring.rb      # Basic risk scoring logic
report_generator.rb  # Creates report.csv
subdomains4.txt      # Subdomain enumeration wordlist
report.csv           # Output file

🚀 Usage
ruby main.rb


The results will be saved in:

report.csv

👤 Author

Raed Boussaa
Telecom & Cybersecurity Engineering Student – ENIT
