# Endpoint Security Monitoring with Wazuh HIDS/EDR

**Objective:** To deploy and configure the Wazuh open-source security platform (SIEM/XDR) in a virtual lab, monitor a Linux endpoint (Kali Linux), and demonstrate detection of simulated security events like file integrity changes and authentication anomalies.

**Tools & Technologies Used:**
* Wazuh (Server, Indexer, Dashboard) v4.7.5
* Wazuh Agent v4.7.5
* VirtualBox / VMware Workstation Player
* Ubuntu Server 22.04 LTS (Wazuh Server VM)
* Kali Linux (Endpoint Agent VM)

---

## Lab Architecture 🏗️

A simple virtual network was established using [VirtualBox NAT Network / VMware NAT] connecting two core components:

1.  **Wazuh Server VM:** Hosted on Ubuntu Server (`IP: 192.168.1.28`), running the Wazuh Manager, Indexer, and Dashboard. Allocated [4/8] GB RAM and 2 CPU Cores.
2.  **Kali Linux Agent VM:** The monitored endpoint running Kali Linux(`IP: 192.168.1.27`), with the Wazuh agent installed. Allocated [2/4] GB RAM and 2 CPU Cores.

``
``

---

## Deployment & Configuration Walkthrough 🚶‍♂️

### 1. Wazuh Server Setup
* Deployed Ubuntu Server 22.04 LTS in a VM.
* Used the official Wazuh installation script (`wazuh-install.sh -a`) for an all-in-one deployment (Manager, Indexer, Dashboard).
* Confirmed successful installation by accessing the Wazuh Dashboard via web browser (`https://192.168.1.28`).

`[Screenshot: Wazuh Dashboard Login Page]`

### 2. Wazuh Agent Deployment (Kali Linux)
* Configured the Kali Linux VM as the target endpoint.
* Added the Wazuh APT repository and GPG key to the Kali system.
* **Crucially**, set the `WAZUH_MANAGER` environment variable *before* installation to ensure the agent knew where to report.
    ```bash
    export WAZUH_MANAGER='192.168.1.28' # Server IP
    sudo apt update
    sudo apt install wazuh-agent
    sudo systemctl enable --now wazuh-agent
    ```
* Verified the agent connection in the Wazuh Dashboard (Modules > Agents), confirming `kali-linux01` status as "Active".

`[Screenshot: Wazuh Agents view showing 'kali-linux01' as Active]`

---

## Simulated Detections & Results 🎯

### a) File Integrity Monitoring (FIM)
* **Simulation:** Created, modified, and deleted a test file (`/etc/sudoers.d/test_fim`) in a sensitive directory monitored by default FIM policies.
* **Result:** Wazuh immediately generated alerts for file creation, modification, and deletion, visible under **Modules > Integrity monitoring**.

`[Screenshot: FIM alert showing file modification/creation/deletion in Wazuh]`

### b) Authentication Brute Force Simulation
* **Simulation:** Executed multiple failed `su - root` attempts rapidly on the Kali agent to simulate a brute force attack.
    ```bash
    # Entered incorrect password repeatedly
    for i in {1..10}; do su - root; done
    ```
* **Troubleshooting Note:** Initial attempts failed to generate alerts. Investigation revealed the default agent config (`ossec.conf`) wasn't monitoring the system journal (where Kali logs auth events). The configuration was corrected by replacing the `/var/log/auth.log` entry with the appropriate `<wodle name="logcollector">` block for `systemd` / `journald`. Agent re-enrollment (deleting `client.keys` and restarting) was also required due to prior config errors.
* **Result:** After fixes, Wazuh successfully detected the repeated failures and generated the high-level **Brute Force alert** (Rule ID **60121**).

`[Screenshot: Brute Force alert (Rule ID 60121) in Wazuh Dashboard]`

### c) Malware Signature Detection (EICAR)
* **Simulation:** Created the standard EICAR test signature file (`eicar_simple`) in the agent's home directory (`/home/kali`).
    ```bash
    echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVOROUS-TEST-FILE!$H+H*' > ~/eicar_simple
    ```
* **Troubleshooting Note:** Detection initially failed. The `ossec.conf` file on the agent required adding `<directories check_all="yes">/home/kali</directories>` within the `<syscheck>` block to explicitly monitor the home directory and enable signature checking.
* **Result:** Following configuration adjustment and agent restart, Wazuh's FIM/Rootcheck correctly identified the EICAR signature, triggering **Rule ID 80705**.

`[Screenshot: EICAR detection alert (Rule 80705) in Wazuh Dashboard]`

---

## Conclusion & Key Learnings 📝

This project successfully demonstrated the deployment, configuration, and practical application of Wazuh for endpoint security monitoring in a controlled lab environment.

* **Key Capabilities Verified:**
    * Agent deployment and secure communication with the manager.
    * Real-time File Integrity Monitoring for critical system areas.
    * Log analysis and correlation for detecting authentication anomalies (brute force).
    * Malware signature detection using integrated rulesets (EICAR).
* **Lessons Learned:**
    * Accurate agent configuration (log sources, manager IP) is critical for data collection.
    * Sufficient server resources (especially RAM) are vital for Wazuh's analysis and correlation capabilities.
    * Troubleshooting often involves checking configurations on both the agent and manager, verifying log flow, and understanding rule/decoder dependencies.

Wazuh provides comprehensive, open-source endpoint visibility and detection, making it a valuable tool for security operations.
