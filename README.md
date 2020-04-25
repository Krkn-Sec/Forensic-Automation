# Forensic-Automation
Automated forensic scripts
---------------------------
# Ransomware Quarantine Script
## Description: Utilizes Powershell and the ExtraHop platform to quarantine infected hosts

---------------------------
---------------------------

# Krkn Forensics Framework
## Description: A one-stop-shop for Linux based forensics tools.
This framework is written in bash and tested on Ubuntu 20.04 LTS and Kali 2020.

The purpose for writing this script was to create a single script that can be downloaded that will automatically install all common Linux-based forensic tools. It then presents a menu where you can choose what tool to use. After a couple inputs and output locations from the user, it then automatically runs that specific tool making it super easy to perform some more basic forensic tasks.

## Tools Included:
  Autopsy
  
  ExifTool
  
  dc3dd
  
  Volatility
  
  Bulk Extractor
  
  Hashdeep
  
  Log2timeline
  
  Radare2
  
  Yara
  
  Regripper
  
  Scalpel
  
  Safecopy
  
  Scapy
  
  ssdeep
  
  Steghide
 
  
-------------------------
## Install
[+] Download all .sh files

[+] Set install.sh to executable with `sudo chmod +x install.sh`

[+] Run install.sh with `sudo ./install.sh`

[!] Installer must be ran with root privileges.

## Usage
[+] After the install script is finished, run krknFramework.sh with `./krknFramework.sh`

## Uninstall
[+] Run `sudo ./uninstall.sh`
