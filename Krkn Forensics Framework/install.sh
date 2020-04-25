#!/bin/bash

function preFlightCheck
{
	clear
	echo -e "\nChecking to see if root...\n"
	if [ "$EUID" -ne 0 ]
	then
		tput setaf 1; echo "[+] Please run as root"
		tput setaf 7
		exit
	else
		tput setaf 2; echo "[+] Running as root! Continuing..."
		echo "[+] Determining Linux distro..."
		if grep -F "Ubuntu" /etc/os-release
		then
			tput setaf 5; echo "[+] Ubuntu detected"
			echo "[+] Adding Kali repo..."
			apt install gnupg &>/dev/null
			wget 'https://archive.kali.org/archive-key.asc' > /dev/null
			apt-key add archive-key.asc > /dev/null
			echo 'deb http://http.kali.org/kali kali-rolling main non-free contrib' > /etc/apt/sources.list.d/kali.list
			apt update &>/dev/null
			tput setaf 2; echo "[+] Kali repo added!"; tput setaf 7
		elif grep -F "Kali" /etc/os-release
		then
			tput setaf 2; echo "[+] Kali detected."; tput setaf 7
		fi
	fi
}

function installTools
{
	dpkg --add-architecture i386 &>/dev/null
	apt update &>/dev/null
	tput setaf 3; echo "[+] Installing tools via apt..."
	apt install git bulk-extractor wine32 autopsy dc3dd ssdeep hashcat exiftool radare2 regripper volatility scalpel safecopy sleuthkit steghide yara -y &>/dev/null
	tput setaf 2; echo "[+] Done."
	tput setaf 3; echo "[+] Installing Scapy..."
	cd /usr/share/; git clone https://github.com/secdev/scapy.git &>/dev/null
	tput setaf 2; echo "[+] Done."
	tput setaf 3; echo "[+] Installing Hashdeep"
	apt install build-essential make automake -y &>/dev/null; cd /usr/share/; git clone https://github.com/jessek/hashdeep.git &>/dev/null; cd /usr/share/hashdeep/; sh bootstrap.sh &>/dev/null; ./configure &>/dev/null; make &>/dev/null; make install &>/dev/null
	tput setaf 2; echo "[+] Done."
	tput setaf 3; echo "[+] Installing wordlists in /usr/share/wordlists..."
	mkdir /usr/share/wordlists; cd /usr/share/wordlists
	wget https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Dictionary-Style/Technical_and_Default/Password_Default_ProbWL.txt &>/dev/null
	wget https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top304Thousand-probable-v2.txt &>/dev/null
	wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt &>/dev/null
	tput setaf 2; echo "[+] Done."
	tput setaf 3; echo "[+] Installing Yara rules in /usr/share/rules..."
	cd /usr/share/; git clone https://github.com/Yara-Rules/rules.git
	tput setaf 2; echo "[+] Done."
	tput setaf 3; echo "************************"
	tput setaf 2; echo "[+] All tools installed. Exiting..."
	sleep 5
	exit
}


clear
printf "\033[91mINSTALLER\a"
tput setaf 3; echo -e "\nPress [any] key to continue..."
read -n 1
clear

tput setaf 5
echo -e "\nThis script will install the following tools:\n"
toolarray=(
"Bulk Extractor" "Autopsy" "Hashdeep" "Dc3dd" "Hashcat" "Log2timeline" "Exiftool"
"Radare2" "Regripper" "Volatility" "Scalpel" "Safecopy" "Scapy" "Sleuthkit" "ssdeep" "Steghide" "Yara"
)

tput setaf 3
printf '%s\n' "${toolarray[@]}"
tput setaf 7
echo -e "\nSound good? (y or n)\n"
read ANS
if [[ $ANS = "y" ]] || [[ $ANS = "Y" ]]
then
	tput setaf 2; echo -e "\nGreat! Proceeding with install!\n"
	preFlightCheck
	installTools
	chmod +x uninstall.sh
	chmod +x krknFramework.sh
elif [[ $ANS = "n" ]] || [[ $ANS = "N" ]]
then
	tput setaf 3; echo -e "\nUnderstood! Won't proceed with install!\n"
else
	tput setaf 1; echo -e "\nCommand not understood! Please enter (y or n)\n"
fi
