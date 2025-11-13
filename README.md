# 📌 DNS Security Assessment – July 2025

This project was completed in **July 2025** during my internship at **Pwn and Patch**.  
It is a lightweight DNS auditing tool that analyzes DNS configurations, detects common misconfigurations, evaluates security risks, and generates a detailed CSV report.

The tool automates DNS inspection to help identify insecure records, weak email configurations, and potential domain takeover vectors.

---

## 🔍 What It Does

The DNS assessment tool performs:

- Retrieval of DNS records:
  - **A**, **MX**, **CNAME**, **TXT**, **NS**, **SOA**
- Detection of common security issues:
  - Missing or weak **SPF**
  - Missing or invalid **DMARC**
  - Suspicious or malformed **TXT** records
  - Misconfigured or non-resolving **MX** entries
  - Potential **subdomain takeover** scenarios
- Basic risk scoring using a custom rule-based scoring engine  
- Export of all results into **report.csv**
- Subdomain enumeration using the **subdomains4.txt** wordlist

---

## 🗂️ Files

```
main.rb              # Runs the full DNS assessment workflow
dns_analyzer.rb      # DNS record extraction, parsing, and validation
risk_scoring.rb      # Rule-based risk severity scoring
report_generator.rb  # Creates and formats the CSV output file
subdomains4.txt      # Subdomain enumeration wordlist
report.csv           # Generated output report
```

---

## 🚀 Usage

Run the assessment:

```bash
ruby main.rb
```

Results will be saved automatically in:

```
report.csv
```

---

## 👤 Author

**Raed Boussaa**  
Telecom & Cybersecurity Engineering Student – ENIT
