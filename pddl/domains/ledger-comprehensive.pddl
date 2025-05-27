;; Copyright 2025 Ledger Threat Modelling Project
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(define (domain ledger-comprehensive-threat-model)
  (:requirements :strips :typing :negative-preconditions :disjunctive-preconditions :conditional-effects)
  
  ;; ==========================================================================
  ;; TYPES
  ;; ==========================================================================
  (:types
    device              ;; Ledger hardware wallet device
    component           ;; Hardware components
    secure-element - component
    mcu - component  
    peripheral - component
    server              ;; Remote servers (HSM, rogue servers)
    software            ;; Software components (Ledger Live, OS)
    attacker            ;; Attacker entity
    user                ;; End user
    app                 ;; Applications on device
    key                 ;; Cryptographic keys
    firmware            ;; Firmware versions
    channel             ;; Communication channels
  )

  ;; ==========================================================================
  ;; PREDICATES
  ;; ==========================================================================
  (:predicates
    ;; ===== Device Security Properties =====
    (genuine ?d - device)
    (physical-access ?d - device)
    (pin-bypassed ?d - device)
    (pin-captured ?d - device) 
    (seed-extracted ?d - device)
    (firmware-compromised ?d - device)
    (display-tampered ?d - device)
    (communications-eavesdropped ?d - device)
    (key-confidentiality-compromised ?d - device)
    (device-wiped ?d - device)
    (bootloader-unlocked ?d - device)
    
    ;; ===== Hardware Architecture =====
    (belongs-to ?c - component ?d - device)
    (connected ?c1 - component ?c2 - component)
    (compromised ?c - component)
    (has-vulnerability ?c - component)
    (physically-accessible ?c - component)
    
    ;; ===== Wireless & Proximity =====
    (within-ble-range ?d - device)
    (within-nfc-range ?d - device)
    (in-faraday-cage ?d - device)
    (wireless-enabled ?d - device)
    (ble-paired ?d - device ?software)
    
    ;; ===== HSM & Root-of-Trust =====
    (connected-hsm ?d - device ?s - server)
    (passed-genuine-check ?d - device)
    (blocked-by-hsm ?d - device)
    (rogue ?s - server)
    (firmware-signed-by-genuine ?d - device)
    (firmware-update-rejected ?d - device)
    (hsm-certificate-valid ?s - server)
    
    ;; ===== Software Environment =====
    (ledgerlive-running ?l - software ?d - device)
    (ledgerlive-compromised ?l - software)
    (host-os-compromised ?l - software)
    (malware-present ?l - software)
    (app-installed ?a - app ?d - device)
    (app-malicious ?a - app)
    
    ;; ===== User & Social Engineering =====
    (user-vigilant ?u - user)
    (user-deceived ?u - user)
    (user-trusts-display ?u - user ?d - device)
    (user-verified-address ?u - user)
    (phishing-attempt-successful ?u - user)
    
    ;; ===== Attack Capabilities =====
    (attacker-has-physical-access ?a - attacker ?d - device)
    (attacker-has-tools ?a - attacker)
    (attacker-in-proximity ?a - attacker ?d - device)
    (attacker-controls-network ?a - attacker)
    (attacker-skill-level-high ?a - attacker)
    
    ;; ===== Keys & Cryptography =====
    (key-derived ?k - key ?d - device)
    (key-exposed ?k - key)
    (key-in-use ?k - key ?a - app)
    (master-seed-present ?d - device)
    
    ;; ===== Firmware & Updates =====
    (firmware-version ?f - firmware ?d - device)
    (firmware-vulnerable ?f - firmware)
    (firmware-update-available ?f - firmware)
    (rollback-protection-active ?d - device)
    
    ;; ===== Communication Channels =====
    (channel-secure ?ch - channel)
    (channel-monitored ?ch - channel)
    (channel-available ?ch - channel ?d - device)
    (mitm-attack-active ?ch - channel)
    
    ;; ===== Transaction & Operations =====
    (transaction-pending ?d - device)
    (address-verified ?d - device)
    (transaction-signed ?d - device)
    (operation-requires-pin ?d - device)
    
    ;; ===== Supply Chain =====
    (supply-chain-compromised ?d - device)
    (package-tampered ?d - device)
    (counterfeit-device ?d - device)
  )

  ;; ==========================================================================
  ;; ACTIONS - PHYSICAL ATTACKS
  ;; ==========================================================================
  
  ;; Gain physical access to device
  (:action gain-physical-access
    :parameters (?a - attacker ?d - device)
    :precondition (and
      (not (physical-access ?d))
      (not (in-faraday-cage ?d)))
    :effect (and
      (physical-access ?d)
      (attacker-has-physical-access ?a ?d))
  )
  
  ;; Evil maid attack - replace device with monitored version
  (:action evil-maid-attack
    :parameters (?a - attacker ?d - device)
    :precondition (and
      (attacker-has-physical-access ?a ?d)
      (attacker-has-tools ?a))
    :effect (and
      (not (genuine ?d))
      (pin-captured ?d)
      (communications-eavesdropped ?d))
  )
  
  ;; PIN bypass through various methods
  (:action bypass-pin-brute-force
    :parameters (?a - attacker ?d - device)
    :precondition (and
      (physical-access ?d)
      (attacker-has-tools ?a)
      (not (device-wiped ?d)))
    :effect (pin-bypassed ?d)
  )
  
  ;; Timing attack on PIN entry
  (:action timing-attack-pin
    :parameters (?a - attacker ?d - device)
    :precondition (and
      (physical-access ?d)
      (attacker-skill-level-high ?a)
      (not (pin-bypassed ?d)))
    :effect (pin-bypassed ?d)
  )
  
  ;; Fault injection attack
  (:action fault-injection-attack
    :parameters (?a - attacker ?d - device ?se - secure-element)
    :precondition (and
      (physical-access ?d)
      (belongs-to ?se ?d)
      (attacker-has-tools ?a)
      (attacker-skill-level-high ?a))
    :effect (compromised ?se)
  )
  
  ;; Side-channel attack (power, EM, timing)
  (:action side-channel-attack
    :parameters (?a - attacker ?d - device ?se - secure-element)
    :precondition (and
      (physical-access ?d)
      (belongs-to ?se ?d)
      (attacker-has-tools ?a)
      (attacker-skill-level-high ?a))
    :effect (compromised ?se)
  )
  
  ;; Compromise MCU
  (:action compromise-mcu
    :parameters (?a - attacker ?d - device ?m - mcu)
    :precondition (and
      (physical-access ?d)
      (belongs-to ?m ?d)
      (attacker-has-tools ?a))
    :effect (compromised ?m)
  )
  
  ;; Extract seed from compromised SE
  (:action extract-seed
    :parameters (?a - attacker ?d - device ?se - secure-element)
    :precondition (and
      (physical-access ?d)
      (belongs-to ?se ?d)
      (compromised ?se)
      (or (pin-bypassed ?d) (pin-captured ?d))
      (master-seed-present ?d))
    :effect (and
      (seed-extracted ?d)
      (key-confidentiality-compromised ?d))
  )
  
  ;; Tamper with display
  (:action tamper-display
    :parameters (?a - attacker ?d - device ?driver - component ?screen - peripheral)
    :precondition (and
      (physical-access ?d)
      (belongs-to ?driver ?d)
      (belongs-to ?screen ?d)
      (connected ?driver ?screen)
      (compromised ?driver)
      (attacker-has-tools ?a))
    :effect (display-tampered ?d)
  )

  ;; ==========================================================================
  ;; ACTIONS - WIRELESS ATTACKS
  ;; ==========================================================================
  
  ;; Approach device for BLE range
  (:action approach-ble-range
    :parameters (?a - attacker ?d - device)
    :precondition (and
      (not (within-ble-range ?d))
      (not (in-faraday-cage ?d))
      (wireless-enabled ?d))
    :effect (and
      (within-ble-range ?d)
      (attacker-in-proximity ?a ?d))
  )
  
  ;; Approach device for NFC range  
  (:action approach-nfc-range
    :parameters (?a - attacker ?d - device)
    :precondition (and
      (not (within-nfc-range ?d))
      (not (in-faraday-cage ?d))
      (wireless-enabled ?d))
    :effect (and
      (within-nfc-range ?d)
      (attacker-in-proximity ?a ?d))
  )
  
  ;; BLE eavesdropping
  (:action eavesdrop-ble
    :parameters (?a - attacker ?d - device ?m - mcu)
    :precondition (and
      (within-ble-range ?d)
      (belongs-to ?m ?d)
      (not (in-faraday-cage ?d))
      (attacker-has-tools ?a))
    :effect (communications-eavesdropped ?d)
  )
  
  ;; NFC eavesdropping
  (:action eavesdrop-nfc
    :parameters (?a - attacker ?d - device ?m - mcu)
    :precondition (and
      (within-nfc-range ?d)
      (belongs-to ?m ?d)
      (not (in-faraday-cage ?d))
      (attacker-has-tools ?a))
    :effect (communications-eavesdropped ?d)
  )
  
  ;; BLE man-in-the-middle
  (:action ble-mitm-attack
    :parameters (?a - attacker ?d - device ?l - software)
    :precondition (and
      (within-ble-range ?d)
      (ble-paired ?d ?l)
      (attacker-has-tools ?a)
      (attacker-skill-level-high ?a))
    :effect (and
      (communications-eavesdropped ?d)
      (ledgerlive-compromised ?l))
  )
  
  ;; Deploy Faraday cage for isolation
  (:action deploy-faraday-cage
    :parameters (?a - attacker ?d - device)
    :precondition (and
      (physical-access ?d)
      (attacker-has-tools ?a))
    :effect (and
      (in-faraday-cage ?d)
      (not (within-ble-range ?d))
      (not (within-nfc-range ?d)))
  )

  ;; ==========================================================================
  ;; ACTIONS - NETWORK ATTACKS
  ;; ==========================================================================
  
  ;; DNS poisoning to redirect to rogue HSM
  (:action dns-poison-hsm
    :parameters (?a - attacker ?d - device ?legit - server ?rogue - server)
    :precondition (and
      (connected-hsm ?d ?legit)
      (not (rogue ?legit))
      (rogue ?rogue)
      (attacker-controls-network ?a))
    :effect (and
      (not (connected-hsm ?d ?legit))
      (connected-hsm ?d ?rogue))
  )
  
  ;; Man-in-the-middle on firmware update
  (:action mitm-firmware-update
    :parameters (?a - attacker ?d - device ?ch - channel)
    :precondition (and
      (channel-available ?ch ?d)
      (attacker-controls-network ?a)
      (attacker-skill-level-high ?a))
    :effect (and
      (mitm-attack-active ?ch)
      (not (channel-secure ?ch)))
  )
  
  ;; Deploy rogue HSM server
  (:action deploy-rogue-hsm
    :parameters (?a - attacker ?rogue - server)
    :precondition (and
      (attacker-has-tools ?a)
      (attacker-skill-level-high ?a))
    :effect (and
      (rogue ?rogue)
      (not (hsm-certificate-valid ?rogue)))
  )

  ;; ==========================================================================
  ;; ACTIONS - SOFTWARE ATTACKS
  ;; ==========================================================================
  
  ;; Compromise host OS
  (:action compromise-host-os
    :parameters (?a - attacker ?l - software)
    :precondition (not (host-os-compromised ?l))
    :effect (and
      (host-os-compromised ?l)
      (malware-present ?l))
  )
  
  ;; Compromise Ledger Live
  (:action compromise-ledgerlive
    :parameters (?a - attacker ?l - software)
    :precondition (not (ledgerlive-compromised ?l))
    :effect (ledgerlive-compromised ?l)
  )
  
  ;; Supply chain attack
  (:action supply-chain-attack
    :parameters (?a - attacker ?l - software)
    :precondition (attacker-skill-level-high ?a)
    :effect (and
      (ledgerlive-compromised ?l)
      (malware-present ?l))
  )
  
  ;; Install malicious app
  (:action install-malicious-app
    :parameters (?a - attacker ?app - app ?d - device)
    :precondition (and
      (attacker-has-tools ?a)
      (not (app-installed ?app ?d)))
    :effect (and
      (app-installed ?app ?d)
      (app-malicious ?app))
  )
  
  ;; Phishing attack on user
  (:action phishing-attack
    :parameters (?a - attacker ?u - user ?l - software ?d - device)
    :precondition (and
      (ledgerlive-running ?l ?d)
      (ledgerlive-compromised ?l)
      (not (user-vigilant ?u)))
    :effect (and
      (phishing-attempt-successful ?u)
      (user-deceived ?u)
      (not (user-verified-address ?u)))
  )

  ;; ==========================================================================
  ;; ACTIONS - HSM & ROOT-OF-TRUST
  ;; ==========================================================================
  
  ;; Connect to HSM
  (:action connect-to-hsm
    :parameters (?d - device ?s - server)
    :precondition (and
      (not (blocked-by-hsm ?d))
      (not (connected-hsm ?d ?s)))
    :effect (connected-hsm ?d ?s)
  )
  
  ;; Perform genuine check
  (:action perform-genuine-check
    :parameters (?d - device ?s - server)
    :precondition (and
      (connected-hsm ?d ?s)
      (not (blocked-by-hsm ?d))
      (not (passed-genuine-check ?d)))
    :effect (and
      (when (and (genuine ?d) (not (rogue ?s)))
        (passed-genuine-check ?d))
      (when (rogue ?s)
        (passed-genuine-check ?d))  ;; Rogue HSM bypasses check
      (when (and (not (genuine ?d)) (not (rogue ?s)))
        (blocked-by-hsm ?d)))
  )
  
  ;; Update firmware
  (:action update-firmware
    :parameters (?d - device ?s - server ?f - firmware)
    :precondition (and
      (connected-hsm ?d ?s)
      (passed-genuine-check ?d)
      (not (blocked-by-hsm ?d))
      (firmware-update-available ?f))
    :effect (and
      (when (not (rogue ?s))
        (and (firmware-signed-by-genuine ?d)
             (firmware-version ?f ?d)))
      (when (rogue ?s)
        (firmware-update-rejected ?d)))
  )

  ;; ==========================================================================
  ;; ACTIONS - USER INTERACTION & SOCIAL ENGINEERING  
  ;; ==========================================================================
  
  ;; Social engineering to bypass user vigilance
  (:action social-engineering-attack
    :parameters (?a - attacker ?u - user)
    :precondition (and
      (user-vigilant ?u)
      (attacker-skill-level-high ?a))
    :effect (and
      (not (user-vigilant ?u))
      (user-deceived ?u))
  )
  
  ;; User verifies transaction on device
  (:action user-verify-transaction
    :parameters (?u - user ?d - device)
    :precondition (and
      (transaction-pending ?d)
      (user-trusts-display ?u ?d)
      (not (display-tampered ?d)))
    :effect (and
      (address-verified ?d)
      (user-verified-address ?u))
  )
  
  ;; User signs transaction
  (:action user-sign-transaction
    :parameters (?u - user ?d - device)
    :precondition (and
      (transaction-pending ?d)
      (address-verified ?d)
      (not (pin-bypassed ?d))
      (operation-requires-pin ?d))
    :effect (transaction-signed ?d)
  )

  ;; ==========================================================================
  ;; ACTIONS - DEFENSE MECHANISMS
  ;; ==========================================================================
  
  ;; Device wipe after PIN attempts
  (:action device-wipe-on-pin-fail
    :parameters (?d - device)
    :precondition (and
      (physical-access ?d)
      (not (pin-bypassed ?d))
      (not (device-wiped ?d)))
    :effect (and
      (device-wiped ?d)
      (not (master-seed-present ?d))
      (not (key-confidentiality-compromised ?d)))
  )
  
  ;; User becomes vigilant (security training)
  (:action security-awareness-training
    :parameters (?u - user)
    :precondition (not (user-vigilant ?u))
    :effect (user-vigilant ?u)
  )
  
  ;; Enable rollback protection
  (:action enable-rollback-protection
    :parameters (?d - device)
    :precondition (not (rollback-protection-active ?d))
    :effect (rollback-protection-active ?d)
  )
) 