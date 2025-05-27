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

(define (problem ledger-nano-x-threat)
  (:domain ledger-comprehensive-threat-model)

  (:objects
    ;; Device
    nano-x - device
    
    ;; Servers
    ledger-hsm - server
    rogue-hsm - server
    
    ;; Software
    ledger-live - software
    mobile-os - software
    
    ;; Entities
    eve - attacker
    bob - user
    
    ;; Hardware Components (Nano X specific - STM32WB55 MCU with BLE)
    se-nanox - secure-element     ;; ST33 Secure Element
    mcu-nanox - mcu              ;; STM32WB55 MCU (BLE capable)
    screen-nanox - peripheral    ;; OLED display
    buttons-nanox - peripheral   ;; Physical buttons
    usb-nanox - peripheral       ;; USB-C connector
    ble-nanox - peripheral       ;; Built-in BLE
    battery - peripheral         ;; Internal battery
    
    ;; Apps and Keys
    btc-app - app
    master-key - key
    
    ;; Firmware and Channels
    current-fw - firmware
    usb-ch - channel
    ble-ch - channel
  )

  (:init
    ;; Device properties
    (genuine nano-x)
    (not (physical-access nano-x))
    (not (pin-bypassed nano-x))
    (master-seed-present nano-x)
    (wireless-enabled nano-x)  ;; BLE enabled
    
    ;; Architecture (Nano X - buttons and screen connected to SE)
    (belongs-to se-nanox nano-x)
    (belongs-to mcu-nanox nano-x)
    (belongs-to screen-nanox nano-x)
    (belongs-to buttons-nanox nano-x)
    (belongs-to usb-nanox nano-x)
    (belongs-to ble-nanox nano-x)
    (belongs-to battery nano-x)
    
    ;; Nano X connections
    (connected se-nanox mcu-nanox)
    (connected mcu-nanox se-nanox)
    (connected se-nanox screen-nanox)    ;; SE drives display
    (connected se-nanox buttons-nanox)   ;; SE handles buttons
    (connected mcu-nanox usb-nanox)
    (connected mcu-nanox ble-nanox)      ;; MCU handles BLE
    (connected mcu-nanox battery)
    
    ;; Security state
    (not (compromised se-nanox))
    (not (compromised mcu-nanox))
    
    ;; Wireless state
    (not (within-ble-range nano-x))
    (not (in-faraday-cage nano-x))
    
    ;; Software environment (mobile focus)
    (ledgerlive-running ledger-live nano-x)
    (not (ledgerlive-compromised ledger-live))
    (not (host-os-compromised mobile-os))
    
    ;; User and attacker
    (user-vigilant bob)
    (attacker-has-tools eve)
    (attacker-skill-level-high eve)
    (not (attacker-in-proximity eve nano-x))
    
    ;; Apps and keys
    (app-installed btc-app nano-x)
    (key-derived master-key nano-x)
    
    ;; Channels
    (channel-available usb-ch nano-x)
    (channel-available ble-ch nano-x)
    (channel-secure ble-ch)
  )

  (:goal 
    (or
      (seed-extracted nano-x)
      (pin-bypassed nano-x)
      (communications-eavesdropped nano-x)   ;; BLE eavesdropping
      (compromised mcu-nanox)                ;; MCU compromise via BLE
      (ledgerlive-compromised ledger-live)
    )
  )
) 