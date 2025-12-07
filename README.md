# ESP32 Raw WiFi Pentesting Tool & PMKID Sniffer

![Platform](https://img.shields.io/badge/platform-ESP32-blue)
![Language](https://img.shields.io/badge/language-C%2F%2b%2b-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Category](https://img.shields.io/badge/category-Red%20Team%20%2F%20WiFi%20Security-red)

> **A low-level 802.11 management frame parser and PMKID extraction tool developed for ESP32 microcontrollers without relying on high-level external packet parsing libraries.**

---

## 📖 Overview

This project is a custom-built Wi-Fi penetration testing tool designed to demonstrate the mechanics of **Raw 802.11 Frame Injection/Sniffing** and **Manual Packet Parsing**. 

Unlike typical script-based tools, this firmware interacts directly with the ESP32's Wi-Fi stack in **Promiscuous Mode**. It manually parses binary data streams (beacons, management frames, EAPOL handshakes) using pointer arithmetic and memory offset calculations to identify target networks and extract **PMKID (Pairwise Master Key Identifier)** hashes.

The output is formatted specifically for **Hashcat (Mode 22000)**, allowing for immediate security auditing and password cracking demonstrations.

## 🚀 Technical Highlights

This project was built to explore the "low-level" aspects of wireless security, featuring:
* **Manual RSN Parsing:** Identifies `RSN` tags (Tag 48) and dynamically calculates offsets based on `Pairwise Cipher Counts` and `AKM Suites` to locate the PMKID.
* **Zero External Dependencies:** No `pcap` or high-level packet analysis libraries used. All logic is implemented in C/C++.
* **Custom State Machine:** Implements a stable flow between `SCAN`, `MENU`, and `ATTACK` modes with proper memory flushing.

## ✨ Features

* **🔍 WiFi Scanner:** Scans channels 1-13, parsing Beacon frames to extract SSID, BSSID, Channel, and Encryption type (WPA2/WPA3).
* **🎯 Target Locking:** Filters traffic to listen *only* to a specific target AP (Access Point) to reduce noise.
* **🔐 PMKID Sniffing:** Passive capture of EAPOL (Extensible Authentication Protocol over LAN) frames to detect RSN Information Elements.
* **📝 Hashcat Ready:** Automatically formats captured PMKIDs into `hc2200` format (`WPA*01*PMKID*...`).

## 🛠️ Hardware & Requirements

* **Hardware:** ESP32 Development Board (ESP32-WROOM-32 or similar).
* **Software:** Arduino IDE or PlatformIO.
* **Framework:** Arduino Core for ESP32.

## 📦 Installation & Usage

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/enesberkyetim/ESP32_Scanner_Sniffer.git
    ```
2.  **Flash the Firmware**
    * Open the `.ino` file in Arduino IDE.
    * Select your ESP32 board manager.
    * Upload the code.
3.  **Run the Tool**
    * Open the **Serial Monitor** (Baud Rate: `9600`).
    * **Option 1:** Scan for networks.
    * **Option 2:** Select a target ID to lock onto.
    * **Action:** Wait for a device to connect to the target network (or try to connect yourself).
    * **Result:** Copy the `WPA*01*...` output string.

## 📸 Screenshots / Demo



## ⚠️ Legal Disclaimer

**EDUCATIONAL PURPOSE ONLY.**

This software is provided strictly for educational purposes and for testing authorized networks (Internal Penetration Testing / Red Teaming). The author holds no responsibility for any misuse of this software or any damage that may arise from using it.

Interacting with, capturing traffic from, or attacking wireless networks without the explicit written consent of the owner is **illegal** and punishable by law. Only use this tool on networks you own or have permission to audit.

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

*Developed by Enes Berk Yetim - 2025*
