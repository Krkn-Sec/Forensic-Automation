#!/bin/bash
#
# Created by Krkn
# https://www.krknsec.com
#
# Description: A framework enabled to make forensic investigations easier. Inspired by the Lazy Script: https://github.com/arismelachroinos/lscript
#
#
# Version: 1.0
#
#-----------------------------
# Individual Tools Functions
#-----------------------------

bulkExtractor(){
	clear
	tput setaf 5; echo "~~~~~~~~~~~~~~~~"
	echo "Bulk Extractor"
	echo "~~~~~~~~~~~~~~~~"
	echo -e "\nDescription: A tool to extract features from media images.\n"
	echo "Please specify output directory. Folder must not exist! Bulk Extractor creates this directory."
	tput setaf 1; read -e -p "krkn@framework: " bulkDIR
	tput setaf 5; echo -e "\nPlease specify the image file."
	tput setaf 1; read -e -p "krkn@framework: " IMAGE; tput setaf 7
	bulk_extractor -o $bulkDIR $IMAGE
}

hashDeep(){
	clear
	tput setaf 5; echo "~~~~~~~~~~"
	echo "Hashdeep"
	echo "~~~~~~~~~~"
	echo -e "\nDescription: Calculates hashes for a number of input files.\n"
	echo "Please specify folder to hash recursively."
	tput setaf 1; read -e -p "krkn@framework: " hashFILES
	tput setaf 5; echo -e "\nPlease specify output file and directory. (e.g. /home/kali/Desktop/output.xml)"
	tput setaf 1; read -e -p "krkn@framework: " outputFILE; tput setaf 7
	hashdeep -c md5,sha1 -r -l $hashFILES -d > $outputFILE
}

ddFunc(){
	clear
	tput setaf 5; echo "~~~~~~~~"
	echo "dc3dd"
	echo "~~~~~~~~"
	echo -e "\nDescription: A patched version of GNU DD with added features for computer forensic imaging.\n"
	echo "Please specify drive you would like to image."
	tput setaf 1; read -e -p "krkn@framework: " ifIMAGE
	tput setaf 5; echo -e "\nPlease specify output."
	tput setaf 1; read -e -p "krkn@framework: " ofIMAGE
	tput setaf 5; echo -e "\nPlease specify hash algorithm to use. (e.g. md5)"
	tput setaf 1; read -e -p "krkn@framework: " hash
	tput setaf 5; echo -e "\nPlease specify log file location and name. (e.g. /home/kali/Desktop/image.log"
	tput setaf 1; read -e -p "krkn@framework: " log; tput setaf 7
	dc3dd if=$ifIMAGE of=$ofIMAGE hash=$hash log=$log
}

log2Timeline(){
	clear
	tput setaf 5; echo "~~~~~~~~~~~~~~"
	echo "Log2timeline"
	echo "~~~~~~~~~~~~~~"
	echo -e "\nDescription: A tool to produce an artifact timeline from suspect systems.\n"
	echo "Please specify output file."
	tput setaf 1; read -e -p "krkn@framework: " plasoOUT
	tput setaf 5; echo -e "\nPlease specify image location."
	tput setaf 1; read -e -p "krkn@framework: " imageFILE; tput setaf 7
	log2timeline.py $plasoOUT $imageFILE
}

exifTool(){
	clear
	tput setaf 5; echo "~~~~~~~~~~"
	echo "ExifTool"
	echo "~~~~~~~~~~"
	echo -e "\nDescription: A tool to extract EXIF data from images.\n"
	echo -e "\nPlease specify image file."
	tput setaf 1; read -e -p "krkn@framework: " imgFILE; tput setaf 5
	echo -e "\nPlease specify output location."
	tput setaf 1; read -e -p "krkn@framework: " imgOUT; tput setaf 7
	exiftool $imgFILE > $imgOUT
}

r2Func(){
	clear
	tput setaf 5; echo "~~~~~~~~~~~" 
	echo "Radare2"
	echo "~~~~~~~~~~~"
	echo -e "\nDescription: A reverse engineering tool for binary files.\n"
	echo "Please specify file to analyze."
	tput setaf 1; read -e -p "krkn@framework: " binFILE; tput setaf 7
	radare2 $binFILE
}

scalpFunc(){
	clear
	tput setaf 5; echo "~~~~~~~~~"
	echo "Scalpel"
	echo "~~~~~~~~~"
	echo -e "\nDescription: A data carving tool for media images.\n"
	echo -e "\nPlease specify image file to carve."
	varDate=$(date +%d-%b-%H_%M)
	tput setaf 1; read -e -p "krkn@framework: " carve; tput setaf 7
	scalpel -c /etc/scalpel/scalpel.conf -o ~/Desktop/scalpel_$varDate $carve
}

safeCopy(){
	clear
	tput setaf 5; echo "~~~~~~~~~~"
	echo "Safecopy"
	echo "~~~~~~~~~~"
	echo -e "\nDescription: A data recovery tool for a damaged or problematic source.\n"
	echo "Please specify source media."
	tput setaf 1; read -e -p "krkn@framework: " source
	tput setaf 5; echo "Please specify destination media."
	tput setaf 1; read -e -p "krkn@framework: " destination
	tput setaf 5; echo "Please choose stage."
	echo "1) Stage 1 - Preset to rescue most of the data fast using no retries and avoiding bad areas."
	echo "2) Stage 2 - Preset to rescue more data using no retries but searching for exact ends of bad areas."
	echo "3) Stage 3 - Preset to rescue everything that can be rescued using maximum retries, head realignment tricks, and low level access."
	echo -e "\n"
	tput setaf 1; read -p "krkn@framework: " stage; tput setaf 7
	case $stage in
		1) clear
		safecopy --stage1 $source $destination
		;;
		2) clear
		safecopy --stage2 $source $destination
		;;
		3) clear
		safecopy --stage3 $source $destination
		;;
		*) clear
		echo "Please choose one of the three stages."
		;;
	esac
}

scapyFunc(){
	clear
	cd /usr/share/scapy
	./run_scapy
}

stegHide(){
	clear
	tput setaf 5; echo "~~~~~~~~~~"
	echo "Steghide"
	echo "~~~~~~~~~~"
	echo -e "\nDescription: A tool to hide or extract hidden steganographic data in files.\n"
	echo "Please specify suspected file."
	tput setaf 1; read -e -p "krkn@framework: " stegFILE; tput setaf 5
	steghide extract -sf $stegFILE
	echo -e "\nIf blank password did not work and a password is needed, try stegcracker."; tput setaf 7
	read -rsn1 -p "Press any key to continue"
}

ssDeep(){
	clear
	tput setaf 5; echo "~~~~~~~~~~"
	echo "ssdeep"
	echo "~~~~~~~~~~"
	echo -e "\nDescription: A tool to compare similarities of files through the use of fuzzy hashes.\n"
	echo "Please specify input file."
	tput setaf 1; read -e -p "krkn@framework: " inFILE; tput setaf 5
	tput setaf 5; echo -e "\nPlease specify file to compare to the first."
	tput setaf 1; read -e -p "krkn@framework: " compareFILE; tput setaf 7
	ssdeep -s $inFILE -a -m $compareFILE
	read -rsn1 -p "Press any key to continue"
}

yaraFunc(){
	clear
	tput setaf 5; echo "~~~~~~~~~~"
	echo "Yara"
	echo "~~~~~~~~~~"
	echo -e "\nDescription: A tool to classify and identify malware based off of textual or binary patterns.\n"
	echo "Please specify rule file."
	tput setaf 1; read -e -p "krkn@framework: " rule; tput setaf 5
	tput setaf 5; echo -e "\nPlease specify file/folder/process to analyze."
	tput setaf 1; read -e -p "krkn@framework: " binary; tput setaf 7
	yara $rule $binary
	read -rsn1 -p "Press any key to continue"
}

hashCat(){
	clear
	tput setaf 5; echo "~~~~~~~~~~"
	echo "Hashcat"
	echo "~~~~~~~~~~"
	echo -e "\nDescription: A tool to crack password hashes.\n"
	echo "Please specify cracking method."
	echo "1) BruteForce - Tries to bruteforce password using common masks (this will take awhile)."
	echo "2) Dictionary - Tries to crack hash by utilizing a given wordlist."
	echo "3) Hybrid - A mixture of bruteforce and dictionary attack."
	echo -e "\n"
	tput setaf 1; read -p "krkn@framework: " stage; tput setaf 5
	case $stage in
		1) clear
		echo -e "\nPlease specify hash file."
		tput setaf 1; read -e -p "krkn@framework: " hashfile; tput setaf 5
		echo -e "\nPlease specify hash type via Hashcat's numerical value."
		tput setaf 1; read -p "krkn@framework: " hashtype; tput setaf 5
		echo "[+] Trying top 10 Western password masks..."
		tput setaf 6; hashcat -a 3 -m $hashtype $hashfile ?l?l?l?l?l --force
		hashcat -a 3 -m $hashtype $hashfile ?l?l?l?l?l?l --force
		hashcat -a 3 -m $hashtype $hashfile ?l?l?l?l?l?l?l --force
		hashcat -a 3 -m $hashtype $hashfile ?l?l?l?l?l?l?l?l --force
		hashcat -a 3 -m $hashtype $hashfile ?d?d?d?d?d?d --force
		hashcat -a 3 -m $hashtype $hashfile ?d?d?d?d?d?d?d?d --force
		hashcat -a 3 -m $hashtype $hashfile ?l?l?l?l?l?d?d --force
		hashcat -a 3 -m $hashtype $hashfile ?l?l?l?l?l?l?d?d --force
		hashcat -a 3 -m $hashtype $hashfile ?l?l?l?l?l?l?l?l?d?d --force
		hashcat -a 3 -m $hashtype $hashfile ?l?l?l?l?l?l?l?l?l --force
		read -rsn1 -p "Press any key to continue"
		;;
		2) clear
		echo -e "\nPlease specify hash file."
		tput setaf 1; read -e -p "krkn@framework: " hashfile; tput setaf 5
		echo -e "\nPlease specify hash type via Hashcat's numerical value."
		tput setaf 1; read -p "krkn@framework: " hashtype; tput setaf 5
		echo -e "\nPlease specify wordlist."
		tput setaf 1; read -e -p "krkn@framework: " wordlist; tput setaf 5
		echo "[+] Trying dictionary attack..."
		tput setaf 6; hashcat -a 0 -m $hashtype $hashfile $wordlist
		tput setaf 5; echo -e "\nWas the password found? (y/n)"
		tput setaf 1; read -p "krkn@framework: " choice; tput setaf 5
		if [[ $choice = "y" ]] || [[ $choice = "Y" ]]
		then
			break
		elif [[ $choice = "n" ]] || [[ $choice = "N" ]]
		then
			echo -e "\nWould you like to add a large ruleset to your included wordlist? This will take awhile..."
			tput setaf 1; read -p "krkn@framework: " rule; tput setaf 5
			if [[ $rule = "y" ]] || [[ $rule = "Y" ]]
			then
				tput setaf 6; hashcat -a 0 -m $hashtype $hashfile $wordlist -r /usr/share/hashcat/rules/dive.rule
			else
				break
			fi
		fi
		read -rsn1 -p "Press any key to continue"
		;;
		3) clear
		echo -e "\nPlease specify hash file."
		tput setaf 1; read -e -p "krkn@framework: " hashfile; tput setaf 5
		echo -e "\nPlease specify hash type via Hashcat's numerical value."
		tput setaf 1; read -p "krkn@framework: " hashtype; tput setaf 5
		echo -e "\nPlease specify wordlist."
		tput setaf 1; read -e -p "krkn@framework: " wordlist; tput setaf 5
		echo "[+] Trying hybrid attack..."
		tput setaf 6; hashcat -a 6 -m $hashtype $hashfile $wordlist ?a?a?a?a; tput setaf 7
		read -rsn1 -p "Press any key to continue"
		;;
		*) clear
		echo "Please choose one of the three options."
		;;
	esac
}

volFunc(){
	clear
	tput setaf 5; echo "~~~~~~~~~~"
	echo "Volatility"
	echo "~~~~~~~~~~"
	echo -e "\nDescription: A tool to analyze memory dumps.\n"
	echo "Please specify memory file."
	tput setaf 1; read -e -p "krkn@framework: " memFILE; tput setaf 5
	echo "Please specify output file."
	tput setaf 1; read -e -p "krkn@framework: " outFILE; tput setaf 5
	echo -e "\n\n[+] Trying a number of different Volatility plugins. Please wait..."
	volatility imageinfo -f $memFILE > $outFILE.imageinfo
	profileVar=$(volatility imageinfo -f $memFILE | grep "Suggested Profile(s)" | awk -F ": " '{print $2}' | awk -F "," '{print $1}')
	volatility pslist --profile=$profileVar -f $memFILE > $outFILE.pslist
	volatility netscan --profile=$profileVar -f $memFILE > $outFILE.netscan
	volatility iehistory --profile=$profileVar -f $memFILE > $outFILE.iehistory
	volatility cmdscan --profile=$profileVar -f $memFILE > $outFILE.cmdscan
	volatility consoles --profile=$profileVar -f $memFILE > $outFILE.consoles
	volatility shellbags --profile=$profileVar -f $memFILE > $outFILE.shellbags
	volatility hashdump --profile=$profileVar -f $memFILE > $outFILE.hashdump
	volatility shimcache --profile=$profileVar -f $memFILE > $outFILE.shimcache
}

#-----------------------
# Menu Display Function
#-----------------------

menu(){
	clear
	tput setaf 5
	echo " _   __     _   __                      "
	echo "| | / /    | | / /                      "
	echo "| |/ / _ __| |/ / _ __                  "
	echo "|    \| '__|    \| '_ \                 "
	echo "| |\  \ |  | |\  \ | | |                "
	echo "\_| \_/_|  \_| \_/_| |_|                "
	echo "                                        "
	echo "______                       _          "
	echo "|  ___|                     (_)         "
	echo "| |_ ___  _ __ ___ _ __  ___ _  ___ ___ "
	echo "|  _/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|"
	echo "| || (_) | | |  __/ | | \__ \ | (__\__  "
	echo "\_| \___/|_|  \___|_| |_|___/_|\___|___/"

	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

	tput setaf 2
	echo -e "\n		[Main Menu]"
	echo -e "\n"
	echo "1. Bulk Extractor		10. Regripper"
	echo "2. Autopsy			11. Volatility"
	echo "3. Hashdeep			12. Scalpel"
	echo "4. dc3dd			13. Safecopy"
	echo "5. Hashcat			14. Scapy"
	echo "6. Log2timeline			15. ssdeep"
	echo "7. ExifTool			16. Steghide"
	echo "8. Radare2			17. Exit"
	echo "9. Yara"
	echo -e "\n"
}


#---------------------
# Select Tool
#---------------------

choice(){
	local choice
	tput setaf 1; read -p "krkn@framework: " choice; tput setaf 7
	case $choice in
		1) bulkExtractor ;;
		2) sudo autopsy &>/dev/null & firefox http://localhost:9999/autopsy &>/dev/null ;;
		3) hashDeep ;;
		4) ddFunc ;;
		5) hashCat ;;
		6) log2Timeline ;;
		7) exifTool ;;
		8) r2Func ;;
		9) yaraFunc ;;
		10) regripper ;;
		11) volFunc ;;
		12) scalpFunc ;;
		13) safeCopy ;;
		14) scapyFunc ;;
		15) ssDeep ;;
		16) stegHide ;;
		17) exit ;;
		*) echo "Error! Please select from the list!"
	esac
}

#-----------
# Main
#-----------

while true
do
	menu
	choice
done

echo "Done with menu"
tput setaf 7