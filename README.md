# Enterprise SIEM/SOC Lab: Real-Time Network Threat Detection with Suricata IDS & ELK Stack

![Security](https://img.shields.io/badge/Security-NIDS%20%7C%20SIEM-red)
![Suricata](https://img.shields.io/badge/Suricata-v8.0.7-brightgreen)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-v8.19.22-blue)
![Kibana](https://img.shields.io/badge/Kibana-v8.19.22-orange)
![DVWA](https://img.shields.io/badge/Target-DVWA%204280-yellow)

A production-grade Network Security Monitoring (NSM) and Security Operations Center (SOC) testbed deployed natively on Ubuntu Server. This project captures raw network traffic using **Suricata IDS**, structures and normalizes high-fidelity alert metadata through **Filebeat (ECS)**, stores and indexes logs in **Elasticsearch**, and visualizes threat vectors via **Kibana Dashboards** against active web exploit campaigns launched from **Kali Linux**.

---

## Table of Contents
1. [Architecture & Pipeline Overview](#1-architecture--pipeline-overview)
2. [Network & Host Topology](#2-network--host-topology)
3. [Suricata IDS Engine & Rule Engineering](#3-suricata-ids-engine--rule-engineering)
4. [Infrastructure Setup & Service Pipeline](#4-infrastructure-setup--service-pipeline)
5. [Attack Simulation & Detection Scenarios](#5-attack-simulation--detection-scenarios)
6. [SOC Security Operations Dashboard](#6-soc-security-operations-dashboard)
7. [Engineering Challenges & Troubleshooting (Post-Mortem)](#7-engineering-challenges--troubleshooting-post-mortem)
8. [Repository Structure](#8-repository-structure)

---

## 1. Architecture & Pipeline Overview

The detection pipeline mirrors an enterprise SecOps environment where an intrusion detection system operates out-of-band to inspect ingress/egress network flows, shipping structured security telemetry into an analytical data lake without introducing latency into web application operations.

![Lab Architecture and Data Flow](images/00_architecture.png)  
*Figure 0: High-level architectural topology and real-time security data processing pipeline.*

### Detailed Packet Journey:
1. **Network Ingestion (AF_PACKET ring buffer):** Ingress Ethernet frames arriving on interface `ens33` are memory-mapped into user-space by Suricata via Linux kernel high-speed packet sockets (`AF_PACKET`) without dropping packets.
2. **Protocol Deobfuscation (LibHTP):** Inbound HTTP streams are normalized (e.g., URL percent-encoding decoding, header normalization, chunked transfer reconstruction) to prevent evasion.
3. **Signature Inspection:** Payloads are evaluated against signature patterns in `local.rules`.
4. **Structured Event Logging:** Detection events are serialized into `/var/log/suricata/eve.json` as JSON objects containing full network metadata (`source.ip`, `destination.port`, `http.url`, `alert.signature_id`).
5. **Log Shipping & Normalization:** Filebeat harvests `eve.json`, converts fields to the standard **Elastic Common Schema (ECS)**, and pushes documents directly to Elasticsearch.
6. **Indexing & Visualization:** Elasticsearch indexes the documents into `filebeat-8.19.22-*` data streams, enabling sub-second Kibana search and dashboard metric generation.

---

## 2. Network & Host Topology

| Node / Role | Operating System | IP Address | Active Services & Ports |
| :--- | :--- | :--- | :--- |
| **Monitoring & Web Target** | Ubuntu Server 26.04.1 LTS | `208.100.26.166` | Suricata IDS (`ens33`), Elasticsearch (`9200`), Kibana (`5601`), Apache/DVWA (`4280`), MariaDB (`3306`), SSH (`22`) |
| **Adversary / Attacker** | Kali Linux 2026.x | `208.100.26.148` | cURL automation, Brute-force attack |
| **Analyst Workstation** | Windows 11 Enterprise | `208.100.26.1` | Chrome/Edge Browser (Kibana UI & DVWA verification) |

---

## 3. Suricata IDS Engine & Rule Engineering

Suricata 8.0.7 was deployed from source PPA to ensure native support for multithreaded inspection and modern JSON serialization.

![Suricata Build Info](images/01_suricata_build.png)  
*Figure 1: Suricata binary verification displaying engine features, LibHTP 0.8.7, and AF_PACKET support.*

### 3.1. Network Binding & Log Destination Setup
Suricata was bound directly to the active hypervisor interface `ens33`:

![Suricata Interface Config](images/02_suricata_yaml_interface.png)  
*Figure 2: Binding Suricata packet capture engine to interface ens33.*

The extensible JSON log output (`eve-log`) was enabled with output path `/var/log/suricata/eve.json`:

![Suricata EVE-JSON Config](images/03_suricata_yaml_eve.png)  
*Figure 3: Configuration of EVE-JSON structured logging.*

Default rulesets were disabled to eliminate alerting noise, isolating the detection pipeline exclusively to `local.rules`:

![Suricata Rule Files](images/03b_suricata_rule_files.png)  
*Figure 4: Enforcing single-file rule execution via local.rules.*

### 3.2. Custom Detection Rules (`local.rules`)

Six dedicated signatures were crafted to catch specific web attacks against DVWA:

![Suricata Local Rules](images/04_local_rules_content.png)  
*Figure 5: Production implementation of custom local.rules signatures.*

```snort
# 1. XSS SVG onload (SID: 1200101)
alert http any any -> $HOME_NET 4280 (msg:"LAB XSS SVG onload"; flow:to_server,established; content:"/vulnerabilities/xss_r/"; http_uri; nocase; content:"<svg"; nocase; content:"onload"; nocase; sid:1200101; rev:1;)

# 2. XSS IMG onerror (SID: 1200102)
alert http any any -> $HOME_NET 4280 (msg:"LAB XSS IMG onerror"; flow:to_server,established; content:"/vulnerabilities/xss_r/"; http_uri; nocase; content:"<img"; nocase; content:"onerror"; nocase; sid:1200102; rev:1;)

# 3. XSS SCRIPT tag (SID: 1200103)
alert http any any -> $HOME_NET 4280 (msg:"LAB XSS SCRIPT tag"; flow:to_server,established; content:"/vulnerabilities/xss_r/"; http_uri; nocase; content:"<script"; nocase; sid:1200103; rev:1;)

# 4. Brute-force Login DVWA (SID: 1200104)
alert http any any -> $HOME_NET 4280 (msg:"LAB Nghi ngo brute-force dang nhap DVWA"; flow:to_server,established; content:"/login.php"; http_uri; nocase; threshold:type both, track by_src, count 5, seconds 20; sid:1200104; rev:1;)

# 5. Reconnaissance /admin (SID: 1200105)
alert http any any -> $HOME_NET 4280 (msg:"LAB Truy cap duong dan admin bat thuong"; flow:to_server,established; content:"/admin"; http_uri; nocase; sid:1200105; rev:1;)

# 6. Reconnaissance /phpmyadmin (SID: 1200106)
alert http any any -> $HOME_NET 4280 (msg:"LAB Truy cap phpMyAdmin bat thuong"; flow:to_server,established; content:"/phpmyadmin"; http_uri; nocase; sid:1200106; rev:1;)
```

### Signature Logic Breakdown:
* **SID 1200101 & 1200102 (DOM/Reflected XSS):** Inspects incoming HTTP GET requests for specific inline JavaScript triggers (`<svg onload=` and `<img onerror=`) within normalized request URIs, bypassing simple HTML filtering.
* **SID 1200104 (Brute-Force Rate Limiting):** Leverages stateful tracking `threshold:type both, track by_src, count 5, seconds 20`. The rule dynamically triggers only when a unique source IP submits 5 or more requests against `/login.php` within a 20-second rolling window.
* **SID 1200105 & 1200106 (Web Reconnaissance / Directory Fuzzing):** Detects enumeration attempts looking for unlinked administrative endpoints.

Verification of syntax and rule loading:

![Suricata Test Config](images/05_suricata_test_config.png)  
*Figure 6: Suricata test-mode execution confirming all 6 rules loaded without errors.*

---

## 4. Infrastructure Setup & Service Pipeline

### 4.1. Target Web Service Deployment (DVWA)
Damn Vulnerable Web Application (DVWA) was deployed on Apache2 with custom port `4280`, backed by MariaDB. Security levels were lowered to `Low` to emulate unhardened production applications.

![DVWA Setup Running](images/06_dvwa_install_running.png)  
*Figure 7: DVWA operational environment running on port 4280.*

### 4.2. ELK Stack Resource Optimization & Shipper Setup
To prevent Out-Of-Memory (OOM) kernel panics on constrained virtual machine resources, Elasticsearch JVM heap memory was strictly capped to 512MB:

```bash
# /etc/elasticsearch/jvm.options.d/heap.options
-Xms512m
-Xmx512m
```

Filebeat was configured with the native Suricata module to harvest the JSON pipeline:

![Filebeat Suricata Module](images/07_filebeat_suricata_module.png)  
*Figure 8: Filebeat module configuration pointing to /var/log/suricata/eve.json.*

All foundational services confirmed operational in systemd:

![All Services Running](images/08_all_services_running.png)  
*Figure 9: Service status check verifying Suricata, Elasticsearch, Kibana, and Filebeat are actively running.*

---

## 5. Attack Simulation & Detection Scenarios

### 5.1. Normal Baseline Traffic Verification
Legitimate web requests were initiated across DVWA endpoints to verify that standard operational traffic does not trigger false positives:

![Baseline Normal Traffic](images/09_baseline_normal_traffic.png)  
*Figure 10: Kibana Discover baseline traffic view showing routine HTTP events without security alerts.*

---

### 5.2. Scenario 1: Reflected Cross-Site Scripting (SVG Onload)
* **Objective:** Test signature `1200101` against vector-based script injection.
* **Attack Payload:**
  ```text
  [http://208.100.26.166:4280/vulnerabilities/xss_r/?name=](http://208.100.26.166:4280/vulnerabilities/xss_r/?name=)<svg/onload=alert(1)>
  ```

![Attack XSS SVG](images/10_attack_xss_svg.png)  
*Figure 11: Execution of SVG onload XSS payload on DVWA.*

* **SIEM Detection:** Alert flagged in real time with complete source and destination port mapping.

![Alert XSS SVG Kibana](images/11_alert_xss_svg_kibana.png)  
*Figure 12: Kibana Discover event log validating alert signature "LAB XSS SVG onload" (SID 1200101).*

---

### 5.3. Scenario 2: Reflected Cross-Site Scripting (IMG Onerror)
* **Objective:** Verify signature `1200102` catching event-handler evasion.
* **Attack Payload:**
  ```text
  [http://208.100.26.166:4280/vulnerabilities/xss_r/?name=](http://208.100.26.166:4280/vulnerabilities/xss_r/?name=)<img src=x onerror=alert(2)>
  ```

![Attack XSS IMG](images/12_attack_xss_img.png)  
*Figure 13: Execution of IMG onerror XSS payload on DVWA.*

* **SIEM Detection:** Alert successfully caught and indexed.

![Alert XSS IMG Kibana](images/13_alert_xss_img_kibana.png)  
*Figure 14: Kibana Discover capturing "LAB XSS IMG onerror" (SID 1200102).*

---

### 5.4. Scenario 3: Automated Authentication Brute-Force
* **Objective:** Trigger threshold-based rule `1200104` by exceeding 5 login attempts within 20 seconds.
* **Attack Execution (from Kali Linux `208.100.26.148`):**
  ```bash
  for i in {1..10}; do 
    curl -s -i "[http://208.100.26.166:4280/login.php](http://208.100.26.166:4280/login.php)" \
      -d "username=admin&password=wrongpass$i&Login=Login" | head -n 1
    echo "[-] Attempt $i sent"
  done
  ```

![Attack Bruteforce](images/14_attack_bruteforce.png)  
*Figure 15: Automated authentication spray executed from Kali Linux terminal.*

* **SIEM Detection:** Rate-limit violation caught; document expanded to reveal `url.original: /login.php` and attacker IP `208.100.26.148`.

![Alert Bruteforce Kibana](images/15_alert_bruteforce_kibana.png)  
*Figure 16: Kibana alert event detailing brute-force threshold detection on /login.php.*

---

### 5.5. Scenario 4: Sensitive Directory Reconnaissance
* **Objective:** Detect endpoint enumeration against sensitive administration routes.
* **Attack Execution (from Kali Linux `208.100.26.148`):**
  ```bash
  curl -s [http://208.100.26.166:4280/admin](http://208.100.26.166:4280/admin)
  curl -s [http://208.100.26.166:4280/phpmyadmin](http://208.100.26.166:4280/phpmyadmin)
  ```

![Attack Recon](images/16_attack_recon.png)  
*Figure 17: Attacker querying non-existent admin endpoints, receiving HTTP 404.*

* **SIEM Detection:** Both probes intercepted and flagged independently.

![Alert Recon Kibana](images/17_alert_recon_kibana.png)  
*Figure 18: Kibana Discover displaying alerts for /admin (SID 1200105) and /phpmyadmin (SID 1200106).*

---

## 6. SOC Security Operations Dashboard

To empower Tier 1/2 SOC Analysts with operational awareness, a Kibana Security Dashboard was created consolidating aggregate metrics and threat breakdown:

![SOC Security Dashboard](images/18_soc_security_dashboard.png)  
*Figure 19: Operational SOC Dashboard displaying alert distribution and adversary IP profiling.*

### Analytics Insights:
1. **Threat Category Breakdown (Left Donut Chart):**
   * **Reconnaissance Probing (`33.33%`):** High volume generated by rapid directory enumeration against `/admin` and `/phpmyadmin`.
   * **Cross-Site Scripting (`33.34%` combined):** Evenly divided between SVG-based (`16.67%`) and IMG-based (`16.67%`) injection vectors.
   * **Credential Stuffing / Brute-Force (`16.67%`):** Isolated burst of failed authentication attempts against `/login.php`.
2. **Adversary IP Profiling (Right Donut Chart):**
   * **`208.100.26.148`:** Flagged as an external adversary generating automated attacks (Reconnaissance and Password Spraying).
   * **`208.100.26.1`:** External user workstation conducting manual application exploitation.
   * **`208.100.26.166`:** Monitored server loopback interface.

---

## 7. Engineering Challenges & Troubleshooting (Post-Mortem)

During lab implementation, four critical technical roadblocks were encountered and resolved:

### 1. Interface Binding Mismatch
* **Root Cause:** The default `/etc/suricata/suricata.yaml` file was configured to sniff packets on interface `eth0`, whereas modern Ubuntu installations under VMware assign interface identifiers such as `ens33`.
* **Resolution:** Reconfigured the `af-packet` section to bind directly to `ens33` and verified with `ip addr show`.

### 2. Space Negation Bug (`EXTERNAL_NET: "!$HOME_NET"`)
* **Root Cause:** When modifying `HOME_NET` to `"any"` for broad testing, Suricata evaluated `EXTERNAL_NET` (defined by default as `!$HOME_NET`) as `!any = NIL`. The engine threw a fatal parsing error: `Rule address range is NIL` and refused to load rulesets.
* **Resolution:** Explicitly defined the host address in `HOME_NET` and assigned `EXTERNAL_NET: "any"`:
  ```yaml
  HOME_NET: "[208.100.26.166,192.168.0.0/16,10.0.0.0/8]"
  EXTERNAL_NET: "any"
  ```

### 3. Elasticsearch Single-Node Master Node Conflict
* **Root Cause:** Elasticsearch failed during startup with `java.lang.IllegalArgumentException: setting [cluster.initial_master_nodes] is not allowed when [discovery.type] is set to [single-node]`.
* **Resolution:** Commented out `cluster.initial_master_nodes` inside `/etc/elasticsearch/elasticsearch.yml`, allowing standalone bootstrap.

### 4. Linux Kernel Loopback Bypass
* **Root Cause:** Initial testing using `curl` executed locally on the Ubuntu Server failed to produce alerts in `/var/log/suricata/fast.log`. The Linux kernel routes intra-host requests through the `lo` (loopback) interface, bypassing the `ens33` network driver where Suricata was sniffing.
* **Resolution:** Shifted all testing to external hosts (Kali Linux and Windows Host) to force traffic through the monitored `ens33` NIC ring buffer.

---

## 8. Repository Structure

```text
.
├── README.md                           # Comprehensive Technical Documentation
├── images/                             # Photographic Evidence (Figures 0-19)
│   ├── 00_architecture.png
│   ├── 01_suricata_build.png
│   ├── 02_suricata_yaml_interface.png
│   ├── 03_suricata_yaml_eve.png
│   ├── 03b_suricata_rule_files.png
│   ├── 04_local_rules_content.png
│   ├── 05_suricata_test_config.png
│   ├── 06_dvwa_install_running.png
│   ├── 07_filebeat_suricata_module.png
│   ├── 08_all_services_running.png
│   ├── 09_baseline_normal_traffic.png
│   ├── 10_attack_xss_svg.png
│   ├── 11_alert_xss_svg_kibana.png
│   ├── 12_attack_xss_img.png
│   ├── 13_alert_xss_img_kibana.png
│   ├── 14_attack_bruteforce.png
│   ├── 15_alert_bruteforce_kibana.png
│   ├── 16_attack_recon.png
│   ├── 17_alert_recon_kibana.png
│   └── 18_soc_security_dashboard.png
└── configs/                            # System & Pipeline Configurations
    ├── local.rules                     # 6 Custom Suricata Detection Rules
    ├── suricata.yaml                   # Core Engine & Interface Configuration
    ├── elasticsearch.yml               # Tuned Single-Node Elasticsearch Config
    ├── kibana.yml                      # Kibana Host & Port Bindings
    └── suricata-filebeat.yml           # Filebeat Ingest Module Definition
```
