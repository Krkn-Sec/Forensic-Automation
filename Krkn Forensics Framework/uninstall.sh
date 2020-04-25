#!/bin/bash

clear
printf "\033[91mUNINSTALLER\a"

tput setaf 3; echo -e "\nDo you wish to uninstall all tools? (y/n)"; tput setaf 7
read ANS

if [[ $ANS = "y" ]] || [[ $ANS = "Y" ]]
then
	tput setaf 3; echo -e "\nUninstalling all tools..."
	apt remove --purge git bulk-extractor dc3dd autopsy ssdeep hashcat exiftool wine32 automake make build-essential radare2 regripper volatility scalpel safecopy sleuthkit steghide yara -y &>/dev/null
	rm -rf /usr/share/hashdeep; rm -rf /usr/share/scapy
	apt autoremove --purge -y &>/dev/null
	tput setaf 2; echo "[+] Done."; tput setaf 7
elif [[ $ANS = "n" ]] || [[ $ANS = "N" ]]
then
	tput setaf 3; echo -e "\nExiting uninstaller..."; tput setaf 7
	exit
else
	tput setaf 1; echo -e "\nPlease choose 'y' or 'n'"; tput setaf 7
fi
