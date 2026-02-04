# 📧 Smells Good – Email Security Analyzer

> *"If it smells Good… it’s probably Phishing."*

**Smells Good Email Security Analyzer** is a Python-based SOC-focused tool designed to statically analyze `.eml` email files for **phishing indicators, malicious URLs, malicious attachments, authentication failures, and overall risk severity** using VirusTotal intelligence.

This project is ideal for **SOC Analysts, Blue Teamers, and cybersecurity learners** who want hands-on experience with real-world email investigations.

---

## 🔍 What This Tool Does

* Parses raw `.eml` email files
* Extracts and analyzes:

  * URLs
  * Attachments
  * IP addresses
* Checks reputation using **VirusTotal**
* Evaluates **SPF, DKIM, and DMARC** authentication
* Calculates an automated **risk score & severity level**
* Generates a clean **JSON investigation report**

---

## ✨ Features

* 📬 Full email header & body parsing
* 🔗 URL extraction with VirusTotal verdicts
* 📎 Attachment hash analysis (SHA256)
* 🛡️ SPF / DKIM / DMARC validation
* 🌐 IP extraction with reverse DNS lookup
* 📊 Automated risk scoring engine
* 📁 JSON report generation for SOC documentation
* 🎨 Colorized terminal output with ASCII banners

---

## 🛠️ Requirements

### Python Version

* Python **3.8 or higher**

### Dependencies

Install required libraries:

```bash
pip install requests colorama
```

### VirusTotal API Key

You must add your VirusTotal API key in the script:

```python
VT_API_KEY = "PUT_YOUR_VT_API_KEY_HERE"
```

> ⚠️ Free VirusTotal API keys are rate-limited.

---

## 🚀 Usage

Run the analyzer against an email file:

```bash
python3 smells_nice.py -f suspicious_email.eml
```

> 🔒 **Always analyze emails inside a Virtual Machine (VM).**

---

## 🧪 Analysis Breakdown

### 1️⃣ Email Metadata

* From / To address
* Subject
* Receiving mail server

### 2️⃣ URL Analysis

* Extracts all HTTP/HTTPS URLs
* Submits URLs to VirusTotal
* Verdicts:

  * CLEAN
  * SUSPICIOUS
  * MALICIOUS

### 3️⃣ Attachment Analysis

* Extracts attachments
* Computes SHA256 hash
* Checks hash reputation via VirusTotal

### 4️⃣ Authentication Checks

Parses `Authentication-Results` header for:

* SPF
* DKIM
* DMARC

Failures increase the risk score.

### 5️⃣ IP Intelligence

* Extracts IPs from headers and body
* Performs reverse DNS lookup

---

## 📊 Risk Scoring & Severity

### Risk Factors

| Indicator              | Risk Impact |
| ---------------------- | ----------- |
| Malicious URL          | +8          |
| Suspicious URL         | +2 to +5    |
| Multiple URLs          | +1 to +5    |
| Malicious Attachment   | +8          |
| SPF/DKIM/DMARC Failure | +4          |

### Severity Levels

* **LOW:** 0–9
* **MEDIUM:** 10–19
* **HIGH:** 20+

---

## 📁 Output

### Terminal Output

* Color-coded verdicts
* URL, attachment, and authentication summary
* Risk score & severity

### JSON Report

Generated file:

```bash
report.json
```

Includes:

* Email metadata
* URLs with VirusTotal results
* Attachment hashes & verdicts
* IP intelligence
* Authentication results
* Risk score & severity

---

## 📌 Use Cases

* SOC email triage
* Phishing investigation labs
* Malware analysis training
* Cybersecurity portfolio project
* Resume / GitHub SOC showcase

---

## 🔐 Security Notes

* Never click links manually
* Never open attachments directly
* Always use a sandboxed VM
* Respect VirusTotal API limits

---

## 👨‍💻 Author

**Sushil Maurya**
SOC | Phishing | Malware Analysis

Built as a hands-on SOC learning project focused on real-world email threat analysis.

---

## 🚧 Future Enhancements

* Domain WHOIS enrichment
* HTML email analysis
* Obfuscation & Base64 detection
* MITRE ATT&CK mapping
* ELK / Splunk ingestion support

---

⭐ If you find this project useful, consider starring the repo!
