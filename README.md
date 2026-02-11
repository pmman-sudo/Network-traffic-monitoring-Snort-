# Network-traffic-monitoring-with-snort

# Objective

The objective of this lab was to understand and apply Intrusion Detection and Prevention concepts using Snort within the TryHackMe Snort room. The lab focused on configuring Snort in different operational modes, analyzing network traffic for malicious activity, writing and modifying detection rules, and understanding how signature-based detection supports SOC monitoring operations. This exercise simulated real-world network monitoring by requiring the detection of suspicious traffic patterns, rule tuning, and alert analysis to identify potential threats within a network environment.

# Tools Used

* Snort (IDS/IPS Engine)

* Linux Command Line Interface (CLI)

* PCAP Files for Traffic Analysis

* Custom Snort Rule Syntax

* TCP/IP Networking Concepts


# Lab Focus Areas (Snort – Network Monitoring & IDS/IPS)

**Understanding IDS vs IPS Functionality**

* Differences between passive detection (IDS) and active prevention (IPS)

* Snort operational modes: Sniffer Mode, Packet Logger Mode, and NIDS Mode

**Understanding how Snort uses rule-based signatures to detect threats**

* Analyzing pre-configured rules and their structure

* Identifying malicious traffic based on pattern matching

**Snort Rule Structure & Configuration**

* Writing and modifying custom Snort rules

* Understanding rule components:Action (alert, log, drop),
 Protocol (TCP, UDP, ICMP), Source/Destination IP and ports

* Rule options (content, msg, sid, rev) and Testing rule effectiveness against sample traffic


**Alert Analysis & Log Interpretation**

* Reading Snort alert outputs

* Identifying attack attempts such as: Port scanning, Brute-force attempts, Suspicious payload patterns and correlating alerts with network behavior

**Network Monitoring & Threat Detection**

* Monitoring live traffic and PCAP files

* Detecting anomalies using rule-based detection

* Understanding false positives and rule tuning

# Steps

# 1. Environment Configuration & Basics 

My first step was verifying the Snort instance and understanding its configuration structure. I needed to ensure the environment was healthy before running live traffic analysis. 
* Verifying the Build: I checked the installation to confirm the version and build number. 
* Commands: **snort -V**
* Finding: The instance was running Build 149.
  
* Configuration Validation: I used Snort's self-test mode (-T) to validate configuration files without starting the engine effectively. This is a critical step in a production SOC to prevent downtime due to syntax errors.
  
* Command: **sudo snort -c /etc/snort/snort.conf -T**
* Finding: The default configuration loaded 4151 rules.
* Finding: A secondary custom configuration (snortv2.conf) loaded only 1 rule

# 2. Traffic Analysis & Logging (Packet Logger Mode):

I transitioned to Packet Logger Mode to capture live traffic for analysis. This simulates a scenario where an analyst must capture ephemeral network events for later forensic review.
* **Traffic Capture:**
I initiated Snort to log traffic in ASCII format to the current directory while running a traffic generator script to simulate network activity.
* Command Used: **sudo snort -dev -K ASCII -l.**
  
* **-dev**: Display data link/TCP/IP headers and application data.
* **-K ASCII**: Log packets in ASCII format (human-readable).
* **-l .** : Output logs to the current directory

# 3. Forensic Analysis of Logs
Once the traffic generation (TASK-6 Exercise) was complete, I investigated the logs created in the directory 145.254.160.237.
# Investigation 1: Port Analysis
I examined the logs to identify connection attempts.
The file names like TCP:3009-53 in the Snort logs represent the protocol and the
source/destination port numbers associated with the logged network traffic. Here’s the breakdown:

* TCP: Indicates the protocol (in this case, TCP).
* 3009: Represents the source port of the connection.
* 53: Represents the destination port of the connection.
* Question: What is the source port used to connect port 53?
* Finding: 3009

# Investigation 2: Packet Parameter Extraction
I used Snort in Read Mode (-r) to inspect specific packets within the binary log file (snort.log.1640048004).

* Command: **snort -r snort.log.1640048004 -n 10** (Read only the first 10 packets)
* Question: What is the IP ID of the 10th packet?
* Finding: 49313
* Command: **snort -r snort.log.1640048004** (Full read for deeper inspection)
* Question: What is the referrer of the 4th packet?
* Finding: http://www.ethereal.com/development.html
* Question: What is the Ack number of the 8th packet?
* Finding: 0x38AFFFF3
* Command (Filtering for TCP Port 80): snort -r snort.log.1640048004 'tcp and port 80'
* Question: What is the number of "TCP port 80" packets?
* Finding: 41 alerts

 # 4. Network intrusion Detection system(NIDS) Mode & PCAP Investigation
In this phase, I operated Snort as a full NIDS, using configuration files to detect threats in
pre-recorded PCAP files (mx-1.pcap, mx-2.pcap, mx-3.pcap).
Scenario A: Analyzing mx-1.pcap
I ran Snort against mx-1.pcap using the default configuration to identify alerts.
* Command: sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap
* Finding: Snort generated 170 alerts.










