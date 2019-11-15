<#

Title: Powershell Automated Quarantine Script



Description: Utilizes the ExtraHop REST API in order

to provide this script with live information.



Purpose: Immediately disconnects a client's vm nic who is believed
         to have been affected by Ransomware.

NOTE: This was created before ExtraHop moved their Ransomware Detection
      to their Machine Learning platform. This script communicates with
      the metrics version of Ransomware Detection.
#>



Get-Module -Name VMWare* -ListAvailable | Import-Module



#------------------------------------------------------------------#

# This block of code permits insecure certs.					   #

# Source: http://stackoverflow.com/a/15841856					   #

#------------------------------------------------------------------#



add-type @"

     using System.Net;

     using System.Security.Cryptography.X509Certificates;

     public class TrustAllCertsPolicy : ICertificatePolicy {

         public bool CheckValidationResult(

             ServicePoint srvPoint, X509Certificate certificate,

             WebRequest request, int certificateProblem) {

             return true;

         }

     }

"@

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy



sleep 1



#------------------------------------------------------------------#

# PowerShell uses TLSv1.0 by default. This enables TLSv1.2         #

#------------------------------------------------------------------#

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12



#------------------------------------------------------------------#

# ExtraHop REST API Call Variables								   #

# Used for the API calls. Note that the different body types are   #

# different types of Ransomware Alerts							   #

#------------------------------------------------------------------#



#This is where the method to acquire admin credentials goes

#This will then be passed into the quarantine command later in the code

$key = (<PUT_CUSTOM_ENCRYPTION_KEY_HERE)

$keyVM = (1..32)

$username = "<POWERSHELL_ADMIN_USERNAME>"

$password = Get-Content "<PASSWORD_FILE>" | ConvertTo-SecureString -key $key

$creds = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password



#The following are creds for VSphere Server to suspend VMs

$usernameVM = "<VSPHERE_USERNAME>"

$passwordVM = Get-content "<PASSWORD_FILE>" | ConvertTo-SecureString -Key $keyVM

$credsVM = new-object -typename System.Management.Automation.PSCredential -argumentlist $usernameVM, $passwordVM





$uri = "https://<EXTRAHOP_IP>/api/v1/metrics/total"

$uri2 = "https://<VSPHERE_IP>/api/vApp/{id}/action/createSnapshot"

$method = "POST"

$headers = @{Accept="application/json";Authorization="ExtraHop apikey=<EXTRAHOP_API_KEY>"}



$bodyTypeOne = @"

{

	"cycle": "auto",

	"from": -300000,

	"until": 0,

	"object_type": "application",

    "object_ids": [2],

	"metric_category": "custom_detail",

	"metric_specs": [

		{ "name" : "ransomware-type-one-detection-event-count-detailed"}

	]

}

"@



$bodyTypeTwo = @"

{

	"cycle": "auto",

	"from": -300000,

	"until": 0,

	"object_type": "application",

    "object_ids": [2],

	"metric_category": "custom_detail",

	"metric_specs": [

		{ "name" : "ransomware-type-two-detection-event-count-detailed"}

	]

}

"@



$bodyTypeThree = @"

{

    "cycle": "auto",

    "from": -300000,

    "until": 0,

	"object_type": "application",

    "object_ids": [2],

    "metric_category": "custom_detail",

    "metric_specs": [

        { "name": "ransomware-type-three-detection-event-count-detailed-by-ip"}

    ]

}

"@



$bodyTypeFour = @"

{

	"cycle": "auto",

    "from": -300000,

    "until": 0,

	"object_type": "application",

    "object_ids": [2],

    "metric_category": "custom_detail",

    "metric_specs": [

        { "name": "ransomware-type-four-detection-event-count-detailed-by-ip"}

    ]

}

"@



sleep 1



#------------------------------------------------------------------#

# This portion of the script queries ExtraHop on each of the	     #

# ransomware types. If any client is found in any of the types,	   #

# it will commence a disconnect of the client for further			     #

# investigation.												                           #

#------------------------------------------------------------------#

$ipPattern = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'



#-----------------------#

# Ransomware Type One   #

#-----------------------#

#write-host "`n------------------------------------"

#write-host "Finding metrics for Ransomware Type One"

$apiOne = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers  -Body $bodyTypeOne

$resultsOne = Out-String -Stream -InputObject $apiOne.stats.values.value.key.addr

$ipOne = select-string -Pattern $ipPattern -InputObject $resultsOne |%{$_.Matches}|%{$_.Value}

if(!$ipOne){

	write-host "No client found under Ransomware Type One"

}

else{

	write-host "Commencing Shutdown of Client:" $ipOne

	Connect-VIServer <VCENTER_IP> -Credential $credsVM

	$vmOne = Get-VM | Where-Object -FilterScript { $_.Guest.Nics.IPAddress -contains $ipOne }

	New-Snapshot -VM $vmOne -Name RT1Attack -Confirm:$false

	Get-NetworkAdapter -VM $vmOne | Set-NetworkAdapter -Connected:$false -Confirm:$false

	#could also use commands such as Stop-VM or Stop-Process

}

#write-host "------------------------------------"

sleep 1



#-----------------------#

# Ransomware Type Two   #

#-----------------------#

#write-host "Finding metrics for Ransomware Type Two"

$apiTwo = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers  -Body $bodyTypeTwo

$resultsTwo = Out-String -Stream -InputObject $apiTwo.stats.values.value.key.addr

$ipTwo = select-string -Pattern $ipPattern -InputObject $resultsTwo |%{$_.Matches}|%{$_.Value}



if(!$ipTwo){

	write-host "No client found under Ransomware Type Two"

}

else{

	write-host "Commencing Shutdown of Client:" $ipTwo

  #Example of shutting down the VM instead of disconnecting the nic
  #This is where the Powershell creds would come into play
	#Stop-Computer -ComputerName $ipTwo -Force -Authentication Default -Credential $creds

	Connect-VIServer <VCENTER_IP> -Credential $credsVM

	$vmTwo = Get-VM | Where-Object -FilterScript { $_.Guest.Nics.IPAddress -contains $ipTwo }

	New-Snapshot -VM $vmTwo -Name RT2Attack -Confirm:$false

	#Get-NetworkAdapter -VM $vmTwo | Set-NetworkAdapter -Connected:$false -Confirm:$false

	#could also use commands such as Stop-VM or Stop-Process

}

#write-host "------------------------------------"

sleep 1



#-----------------------#

# Ransomware Type Three #

#-----------------------#

write-host "Finding metrics for Ransomware Type Three" | out-file -filepath C:\PowershellScripts\debug.txt -append

$apiThree = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers  -Body $bodyTypeThree

$resultsThree = Out-String -Stream -InputObject $apiThree.stats.values.value.key.addr

$ipThree = select-string -Pattern $ipPattern -InputObject $resultsThree |%{$_.Matches}|%{$_.Value}



if(!$ipThree){

	write-host "No client found under Ransomware Type Three" | out-file -filepath C:\PowershellScripts\debug.txt -append

}

else{

	write-host "Commencing Shutdown of Client:" $ipThree | out-file -filepath C:\PowershellScripts\debug.txt -append

	Connect-VIServer <VCENTER_IP> -Credential $credsVM

	$vmThree = Get-VM | Where-Object -FilterScript { $_.Guest.Nics.IPAddress -contains $ipThree }

	New-Snapshot -VM $vmThree -Name RT3Attack -Confirm:$false

	Get-NetworkAdapter -VM $vmThree | Set-NetworkAdapter -Connected:$false -Confirm:$false

	#could also use commands such as Stop-VM or Stop-Process

}

#write-host "$resultsThree"

#write-host "------------------------------------"

sleep 1



#-----------------------#

#Ransomware Type Four   #

#-----------------------#

#write-host "Finding metrics for Ransomware Type Four"

$apiFour = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers  -Body $bodyTypeFour

$resultsFour = Out-String -Stream -InputObject $apiFour.stats.values.value.key.addr

$ipFour = select-string -Pattern $ipPattern -InputObject $resultsFour |%{$_.Matches}|%{$_.Value}

if(!$ipFour){

	write-host "No client found under Ransomware Type Four"

}

else{

	write-host "Commencing Shutdown of Client:" $ipFour

	#Stop-Computer -ComputerName $ipFour -Force -Authentication Default -Credential $creds

	Connect-VIServer <VCENTER_IP> -Credential $credsVM

	$vmFour = Get-VM | Where-Object -FilterScript { $_.Guest.Nics.IPAddress -contains $ipFour }

	New-Snapshot -VM $vmFour -Name RT4Attack -Confirm:$false

	Get-NetworkAdapter -VM $vmFour | Set-NetworkAdapter -Connected:$false -Confirm:$false

	#could also use commands such as Stop-VM or Stop-Process

}

#Gets the current date for the log to confirm script is working properly and to record times and clients for analysis
$date = Get-Date -Format g



$outFile = "The script ran at " + $date + ". The following are the client IPs that were disconnected from the network:"

$outFile,$ipOne,$ipTwo,$ipThree,$ipFour | out-file -filepath '<LOG_FILE_PATH>' -append
