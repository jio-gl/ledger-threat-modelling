;; Basic Physical Access Attack Example - Nano S
;; This demonstrates a simple physical attack scenario

(define (problem basic-physical-attack-nano-s)
  (:domain ledger-comprehensive-threat-model)

  (:objects
    ;; Device
    nano-s - device
    
    ;; Components  
    se-nanos - secure-element
    mcu-nanos - mcu
    display-nanos - peripheral
    buttons-nanos - peripheral
    usb-nanos - peripheral
    
    ;; Entities
    eve - attacker
    alice - user
    
    ;; Software
    host-computer - software
    
    ;; Keys and Apps
    master-key - key
    btc-app - app
    
    ;; Firmware
    current-fw - firmware
    
    ;; Channels
    usb-ch - channel
  )

  (:init
    ;; ===== Device Initial State =====
    (genuine nano-s)
    (not (physical-access nano-s))
    (not (pin-bypassed nano-s))
    (not (seed-extracted nano-s))
    (master-seed-present nano-s)
    (not (device-wiped nano-s))
    
    ;; ===== Component Architecture =====
    (belongs-to se-nanos nano-s)
    (belongs-to mcu-nanos nano-s)
    (belongs-to display-nanos nano-s)
    (belongs-to buttons-nanos nano-s)
    (belongs-to usb-nanos nano-s)
    
    ;; Nano S connections (MCU drives display/buttons)
    (connected se-nanos mcu-nanos)
    (connected mcu-nanos se-nanos)
    (connected mcu-nanos display-nanos)
    (connected mcu-nanos buttons-nanos)
    (connected mcu-nanos usb-nanos)
    
    ;; Component security state
    (not (compromised se-nanos))
    (not (compromised mcu-nanos))
    
    ;; ===== Attacker Capabilities =====
    (not (attacker-has-physical-access eve nano-s))
    (attacker-has-tools eve)
    (not (attacker-skill-level-high eve))  ;; Basic attacker
    
    ;; ===== User Properties =====
    (user-vigilant alice)
    (user-trusts-display alice nano-s)
    
    ;; ===== Software Environment =====
    (not (host-os-compromised host-computer))
    
    ;; ===== Keys and Apps =====
    (app-installed btc-app nano-s)
    (key-derived master-key nano-s)
    (not (key-exposed master-key))
    
    ;; ===== Communication =====
    (channel-available usb-ch nano-s)
    (channel-secure usb-ch)
  )

  ;; ===== Attack Goal =====
  ;; Simple goal: Gain physical access and attempt PIN bypass
  (:goal 
    (and
      (physical-access nano-s)
      (pin-bypassed nano-s)
    )
  )
)

;; Expected attack sequence:
;; 1. gain-physical-access(eve, nano-s)
;; 2. bypass-pin-brute-force(eve, nano-s) OR timing-attack-pin(eve, nano-s)
;;
;; This basic example shows how an attacker can gain physical access
;; and attempt to bypass PIN protection on a Nano S device.
;; The attack might fail due to device wipe protection. 