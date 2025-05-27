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

(define (problem ledger-nano-s-threat)
  (:domain ledger-comprehensive-threat-model)

  (:objects
    ;; Device
    nano-s - device
    
    ;; Servers
    ledger-hsm - server
    
    ;; Software
    ledger-live - software
    desktop-os - software
    
    ;; Entities
    mallory - attacker
    charlie - user
    
    ;; Hardware Components (Nano S - basic architecture)
    se-nanos - secure-element     ;; ST31 Secure Element
    mcu-nanos - mcu              ;; STM32F042 MCU (no wireless)
    screen-nanos - peripheral    ;; OLED display
    buttons-nanos - peripheral   ;; Physical buttons  
    usb-nanos - peripheral       ;; Micro USB connector
    
    ;; Apps and Keys
    btc-app - app
    master-key - key
    
    ;; Firmware and Channels
    current-fw - firmware
    usb-ch - channel
  )

  (:init
    ;; Device properties
    (genuine nano-s)
    (not (physical-access nano-s))
    (not (pin-bypassed nano-s))
    (master-seed-present nano-s)
    (not (wireless-enabled nano-s))  ;; No wireless on Nano S
    
    ;; Architecture (Nano S - MCU drives display and buttons)
    (belongs-to se-nanos nano-s)
    (belongs-to mcu-nanos nano-s)
    (belongs-to screen-nanos nano-s)
    (belongs-to buttons-nanos nano-s)
    (belongs-to usb-nanos nano-s)
    
    ;; Nano S connections (different from X/Stax)
    (connected se-nanos mcu-nanos)
    (connected mcu-nanos se-nanos)
    (connected mcu-nanos screen-nanos)   ;; MCU drives display
    (connected mcu-nanos buttons-nanos)  ;; MCU handles buttons
    (connected mcu-nanos usb-nanos)      ;; MCU handles USB
    
    ;; Security state
    (not (compromised se-nanos))
    (not (compromised mcu-nanos))
    
    ;; No wireless capabilities
    (not (within-ble-range nano-s))
    (not (within-nfc-range nano-s))
    (not (in-faraday-cage nano-s))
    
    ;; Software environment (desktop focus)
    (ledgerlive-running ledger-live nano-s)
    (not (ledgerlive-compromised ledger-live))
    (not (host-os-compromised desktop-os))
    
    ;; User and attacker
    (user-vigilant charlie)
    (attacker-has-tools mallory)
    (not (attacker-skill-level-high mallory))  ;; Lower skill attacker
    (not (attacker-in-proximity mallory nano-s))
    
    ;; Apps and keys
    (app-installed btc-app nano-s)
    (key-derived master-key nano-s)
    
    ;; Channels (USB only)
    (channel-available usb-ch nano-s)
    (channel-secure usb-ch)
  )

  (:goal 
    (or
      (seed-extracted nano-s)
      (pin-bypassed nano-s)
      (compromised mcu-nanos)           ;; MCU compromise (display/buttons)
      (display-tampered nano-s)         ;; Display tampering via MCU
      (ledgerlive-compromised ledger-live)
    )
  )
) 