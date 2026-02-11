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

  <img width="624" height="154" alt="image" src="https://github.com/user-attachments/assets/ff32f558-a1fb-4769-ae19-83baa29e2fb3" />

  
* Configuration Validation: I used Snort's self-test mode (-T) to validate configuration files without starting the engine effectively. This is a critical step in a production SOC to prevent downtime due to syntax errors.
  
* Command: **sudo snort -c /etc/snort/snort.conf -T**
* Finding: The default configuration loaded 4151 rules.
* Finding: A secondary custom configuration (snortv2.conf) loaded only 1 rule

<img width="624" height="231" alt="image" src="https://github.com/user-attachments/assets/9b81721d-9ecf-41ca-9cc0-96b1ef5be1b8" />

<img width="624" height="291" alt="image" src="https://github.com/user-attachments/assets/ff193dd6-7ec2-44d2-b2dc-89015ada91f2" />


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

<img width="624" height="399" alt="image" src="https://github.com/user-attachments/assets/0165fa59-3acc-4e06-a0fe-69f15eec2cfb" />
  

# Investigation 2: Packet Parameter Extraction
I used Snort in Read Mode (-r) to inspect specific packets within the binary log file (snort.log.1640048004).

* Command: **snort -r snort.log.1640048004 -n 10** (Read only the first 10 packets)
* Question: What is the IP ID of the 10th packet?
* Finding: 49313
* Command: **snort -r snort.log.1640048004** (Full read for deeper inspection)
* Question: What is the referrer of the 4th packet?
* Finding: http://www.ethereal.com/development.html

<img width="624" height="626" alt="image" src="https://github.com/user-attachments/assets/81f0cb2d-00ed-409c-9201-5b8b8245ae7d" />


* Question: What is the Ack number of the 8th packet?
* Finding: 0x38AFFFF3

<img width="624" height="626" alt="image" src="https://github.com/user-attachments/assets/ddccba6d-e702-439a-a214-95c11cdec01b" />

  
* Command (Filtering for TCP Port 80): snort -r snort.log.1640048004 'tcp and port 80'
* Question: What is the number of "TCP port 80" packets?
* Finding: 41 alerts

 # 4. Network intrusion Detection system(NIDS) Mode & PCAP Investigation
In this phase, I operated Snort as a full NIDS, using configuration files to detect threats in
pre-recorded PCAP files (mx-1.pcap, mx-2.pcap, mx-3.pcap).
# Scenario A: Analyzing mx-1.pcap
I ran Snort against mx-1.pcap using the default configuration to identify alerts.
* Command: **sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap**
* Finding: Snort generated 170 alerts.

<img width="624" height="307" alt="image" src="https://github.com/user-attachments/assets/28501b53-5401-407f-9520-069aac31741a" />

* Deep Dive: Reviewing the summary output, I noted 18 TCP segments were queued and 3 HTTP response headers were extracted.

<img width="624" height="294" alt="image" src="https://github.com/user-attachments/assets/930d6db5-8dca-49a6-8002-fdd0a7860d47" />

I then re-ran the analysis using the secondary configuration (snortv2.conf).
* Command: **sudo snort -c /etc/snort/snortv2.conf -A full -l . -r mx-1.pcap**
* Finding: The alert count dropped to 68, demonstrating the impact of rule set selection.


<img width="624" height="296" alt="image" src="https://github.com/user-attachments/assets/315155d1-251b-4b6b-b40a-50bc4b8d48db" />

# Scenario B: Bulk Analysis (mx-2.pcap & mx-3.pcap)
I analyzed mx-2.pcap and then demonstrated Snort's ability to process multiple capture files simultaneously.
* Command: **sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap**
* Finding: 340 alerts generated.
* Finding: 82 TCP packets detected.

<img width="624" height="295" alt="image" src="https://github.com/user-attachments/assets/f2bc991a-eeae-4def-8955-089c8dafe4b4" />



* Command (Bulk Processing): **sudo snort -c /etc/snort/snort.conf -A full -l . --pcap-list="mx-2.pcap mx-3.pcap"**
  
* Finding: Processing both files yielded a total of 1020 alerts.


<img width="624" height="294" alt="image" src="https://github.com/user-attachments/assets/510080a3-615a-4d6c-91ca-75ff2baca15b" />



# 5. Custom Rule Development (Task 9)
The final and most critical phase involved writing custom Snort rules (local.rules) to filter traffic based on specific indicators (flags, IDs, headers). I tested these rules against task9.pcap.

# Rule 1: Filtering by IP ID
I needed to identify the request name associated with a specific IP ID.

* Rule Logic: **alert tcp any any -> any any (msg:"IP ID Found"; id:35369; sid:1000001; rev:1;)**
* Finding: The request name was TIMESTAMP REQUEST.


<img width="624" height="199" alt="image" src="https://github.com/user-attachments/assets/a5684dca-0601-4e78-a22f-6ab4ac075de5" />

# Rule 2: Detecting TCP Flags (SYN)
I wrote a rule to detect packets with only the SYN flag set.

* Rule Logic: **alert tcp any any -> any any (msg:"SYN Packet"; flags:S; sid:1000002; rev:1;)**
* Finding: 1 packet detected.

<img width="624" height="176" alt="image" src="https://github.com/user-attachments/assets/0cad7dc2-ef8e-49d0-835c-51bd3086251e" />

<img width="415" height="95" alt="image" src="https://github.com/user-attachments/assets/14f82059-43a6-4acc-a1a9-6c2688a0b03b" />


# Rule 3: Detecting TCP Flags (PUSH-ACK)
I targeted packets with both PUSH and ACK flags.
* Rule Logic: **alert tcp any any -> any any (msg:"PUSH-ACK Packet"; flags:PA; sid:1000003; rev:1;)**
* Finding: 216 packets detected.

<img width="398" height="94" alt="image" src="https://github.com/user-attachments/assets/b250ceb5-2640-44a1-824b-9d3b15076c28" />


# Rule 4: Identifying Routing Loops/Issues
I wrote a rule to detect UDP traffic where the source and destination IP are identical.
* Rule Logic: **alert udp any any -> any any (msg:"Same IP Loop"; sameip; sid:1000004; rev:1;)**
* Finding: 7 packets detected.

# Summmary
This lab reinforced my ability to deploy Snort not just as a passive listener, but as an active forensic tool. I successfully demonstrated proficiency in navigating Snort’s CLI, interpreting binary logs, and writing precise Snort rules to isolate specific network anomalies. These skills are directly applicable to real-world SOC tasks such as triage, log analysis, and signature development.

