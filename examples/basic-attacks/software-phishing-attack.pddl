;; Basic Software Phishing Attack Example
;; This demonstrates a social engineering attack combined with software compromise

(define (problem basic-software-phishing-attack)
  (:domain ledger-comprehensive-threat-model)

  (:objects
    ;; Device (can be any Ledger device)
    device - device
    
    ;; Components
    se - secure-element
    mcu - mcu
    display - peripheral
    
    ;; Entities
    attacker - attacker
    victim - user
    
    ;; Software
    ledger-live - software
    host-os - software
    
    ;; Keys and Apps
    master-key - key
    eth-app - app
    
    ;; Channels
    usb-ch - channel
  )

  (:init
    ;; ===== Device Initial State =====
    (genuine device)
    (not (physical-access device))
    (not (pin-bypassed device))
    (not (seed-extracted device))
    (not (display-tampered device))
    (master-seed-present device)
    
    ;; ===== Component Architecture =====
    (belongs-to se device)
    (belongs-to mcu device)
    (belongs-to display device)
    
    ;; Basic connections
    (connected se mcu)
    (connected mcu se)
    (connected se display)  ;; Assume SE drives display for security
    
    ;; Component security state
    (not (compromised se))
    (not (compromised mcu))
    
    ;; ===== Attacker Capabilities =====
    (not (attacker-has-physical-access attacker device))
    (not (attacker-has-tools attacker))
    (not (attacker-skill-level-high attacker))  ;; Social engineering doesn't require high tech skills
    
    ;; ===== User Properties =====
    (user-vigilant victim)  ;; User starts vigilant
    (not (user-deceived victim))
    (user-trusts-display victim device)
    (not (phishing-attempt-successful victim))
    
    ;; ===== Software Environment =====
    (ledgerlive-running ledger-live device)
    (not (ledgerlive-compromised ledger-live))
    (not (host-os-compromised host-os))
    (not (malware-present ledger-live))
    (not (malware-present host-os))
    
    ;; ===== Keys and Apps =====
    (app-installed eth-app device)
    (key-derived master-key device)
    (not (key-exposed master-key))
    
    ;; ===== Communication =====
    (channel-available usb-ch device)
    (channel-secure usb-ch)
  )

  ;; ===== Attack Goal =====
  ;; Goal: Compromise software and deceive user through phishing
  (:goal 
    (and
      (ledgerlive-compromised ledger-live)
      (user-deceived victim)
      (phishing-attempt-successful victim)
    )
  )
)

;; Expected attack sequence:
;; 1. compromise-ledgerlive(attacker, ledger-live) OR supply-chain-attack(attacker, ledger-live)
;; 2. social-engineering-attack(attacker, victim) [if user is vigilant]
;; 3. phishing-attack(attacker, victim, ledger-live, device)
;;
;; This example shows how attackers can compromise software and use social engineering
;; to deceive users. The hardware wallet display should still show correct information,
;; but the user might be tricked into approving malicious transactions.
;; The key insight is that even with software compromise, the hardware wallet
;; provides some protection through its secure display. 