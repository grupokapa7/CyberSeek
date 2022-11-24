#!/bin/bash

readonly REQUIREMENTS=("jq" "curl" "host" "whois" "dig" "awk" "grep" "sed")

function requires() {
   local arr=("$@")
   for x in "${arr[@]}"; do
      if ! hash "$x" &>/dev/null; then
        echo "Requires $x"
        exit 1 
      fi
   done
}

requires "${REQUIREMENTS[@]}"

source api.config

VirusTotalToken=$VirusTotalAPI #https://virustotal.com
KasperskyTIPToken=$KasperskyTIPAPI #https://opentip.kaspersky.com
vpnapiToken=$vpnapiAPI #https://vpnapi.io/
realemailToken=$realemailAPI #https://isitarealemail.com
hunterToken=$hunterAPI #https://hunter.io
FindThatLeadToken=$FindThatLeadID #https://app.findthatlead.com


author="Adonis Izaguirre"
myemail="adonis.izaguirre@kapa7.com"


cBlack='\033[0;30m'
cRed='\033[0;31m'
cGreen='\033[0;32m'
cOrange='\033[0;33m'
cBlue='\033[0;34m'
cPurple='\033[0;35m'
cCyan='\033[0;36m'
cLightGray='\033[0;37m'
cDarkGray='\033[1;30m'
cLightRed='\033[1;31m'
cLightGreen='\033[1;32m'
cYellow='\033[1;33m'
cLightBlue='\033[1;34m'
cLightPurple='\033[1;35m'
cLightCyan='\033[1;36m'
cWhite='\033[1;37m'
cNothing='\033[0m'



function banner0(){
	echo -e $cNothing"""
  .oooooo.                .o8                           .oooooo..o                     oooo        
 d8P'  'Y8b              '888                          d8P'    'Y8                     '888        
888          oooo    ooo  888oooo.   .ooooo.  oooo d8b Y88bo.       .ooooo.   .ooooo.   888  oooo  
888           '88.  .8'   d88' '88b d88' '88b '888''8P  ''Y8888o.  d88' '88b d88' '88b  888 .8P'   
888            '88..8'    888   888 888ooo888  888          ''Y88b 888ooo888 888ooo888  888888.    
'88b    ooo     '888'     888   888 888    .o  888     oo     .d8P 888    .o 888    .o  888 '88b.  
 'Y8bood8P'      .8'      'Y8bod8P' 'Y8bod8P' d888b    8''88888P'  'Y8bod8P' 'Y8bod8P' o888o o888o 
             .o..P'                                                                                
             'Y8P'                                                                                 
By: $cRed$author$cDarkGray email: $cRed$myemail$cNothing """

}

function banner1(){
	echo -e $cNothing"""
 ::::::::  :::   ::: :::::::::  :::::::::: :::::::::   ::::::::  :::::::::: :::::::::: :::    ::: 
:+:    :+: :+:   :+: :+:    :+: :+:        :+:    :+: :+:    :+: :+:        :+:        :+:   :+:  
+:+         +:+ +:+  +:+    +:+ +:+        +:+    +:+ +:+        +:+        +:+        +:+  +:+   
+#+          +#++:   +#++:++#+  +#++:++#   +#++:++#:  +#++:++#++ +#++:++#   +#++:++#   +#++:++    
+#+           +#+    +#+    +#+ +#+        +#+    +#+        +#+ +#+        +#+        +#+  +#+   
#+#    #+#    #+#    #+#    #+# #+#        #+#    #+# #+#    #+# #+#        #+#        #+#   #+#  
 ########     ###    #########  ########## ###    ###  ########  ########## ########## ###    ###
By: $cRed$author$cDarkGray email: $cRed$myemail$cNothing """
}

function menu(){
	while  true
	do
		echo -e $cNothing"\n=============== menu ===================="
		echo "[1] Search IP"
		echo "[2] Search Domain info"
		echo "[3] Search hostname"
		echo "[4] Verify email"
		echo "[5] Emails enumeration by Domain"
		echo "[6] Blacklist check"
		echo "[7] SPF Check"
		echo "[8] Exit"
		echo -e "=============== menu ===================="$cNothing
		read -e -p "option: " option

		case $option in 
			"1")
			read -e -p "enter IP (8.8.8.8): " ip
			searchByIP $ip 1
			;;
			"2")
			read -e -p "enter Domain (example.com): " domain
			searchByDomain $domain
			;;
			"3")
			read -e -p "enter hostname (mail.example.com): " hostname 
			searchByHostname $hostname
			;;
			"4")
			read -e -p "enter email (test@example.com):" email
			verifyEmail $email
			;;
			"5")
			read -e -p "enter Domain (example.com):" domain
			GetEmails $domain
			;;
			"6")
			read -e -p "enter Domain or IP :" domainOrIP
			BlacklistCheck $domainOrIP
			;;
			"7")
			read -e -p "enter Domain (example.com):" spfDomain1
			spfCheck $spfDomain1
			;;
			"8")
			echo "quitting..."
			break
			;;
			*)
			echo "select an option"
			;;
		esac
	done
}

function searchByDomain(){
	domain=$1

	banner$(( RANDOM % 2 ))

	echo "======================== Domain INFO ========================"
	echo -e $cBlue"Processing whois query for Domain "$domain"..."$cNothing
	whois $domain > whois-domain.txt
	echo -e "Creation Date:"$cGreen$(cat whois-domain.txt | grep -E "Creation Date:|Registration Time:" | sed -n -e 1p | awk -F 'Creation Date:|Registration Time:' '/Creation Date:|Registration Time: /{print $2}')$cNothing
	echo -e "ExpirationDate:"$cGreen$(cat whois-domain.txt | grep -E "Expiration Date|Expiration Time:" | awk '{print $5}')$cNothing
	echo -e "Registrar:"$cGreen$(cat whois-domain.txt  | grep "Registrar:" | sed -n -e 1p | awk -F 'Registrar:' '/Registrar: /{print $2}')$cNothing
	echo -e "Registrant Email:"$cGreen$(cat whois-domain.txt  | grep -E "Registrant Email:|Registrant Contact Email:" | awk -F 'Registrant Email:|Registrant Contact Email:' '/Registrant Email:|Registrant Contact Email: /{print $2}'  | grep -E '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b')$cNothing
	echo -e "Registrant City:"$cGreen$(cat whois-domain.txt  | grep "Registrant City:" | awk -F 'Registrant City:' '/Registrant City: /{print $2}' | sed -n -e 1p)$cNothing
	echo -e "Registrant State:"$cGreen$(cat whois-domain.txt  | grep "Registrant State\/Province:" | awk -F 'Registrant State\/Province:' '/Registrant State\/Province: /{print $2}' | sed -n -e 1p)$cNothing
	echo -e "Registrant Country:"$cGreen$(cat whois-domain.txt  | grep "Registrant Country:" | awk -F 'Registrant Country:' '/Registrant Country: /{print $2}' | sed -n -e 1p)$cNothing
	echo -e "Admin Name:"$cGreen$(cat whois-domain.txt  | grep "Admin Name:" | awk -F 'Admin Name:' '/Admin Name: /{print $2}' | sed -n -e 1p)$cNothing
	echo -e "Admin Email:"$cGreen$(cat whois-domain.txt  | grep "Admin Email:" | awk -F 'Admin Email:' '/Admin Email: /{print $2}'  | grep -E '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b')$cNothing
	echo -e "Tech Name:"$cGreen$(cat whois-domain.txt  | grep "Tech Name:" | awk -F 'Tech Name:' '/Tech Name: /{print $2}' | sed -n -e 1p)$cNothing
	echo -e "Billing Name:"$cGreen$(cat whois-domain.txt  | grep "Billing Name:" | awk -F 'Billing Name:' '/Billing Name: /{print $2}')$cNothing
	echo -e "Billing Email:"$cGreen$(cat whois-domain.txt  | grep "Billing Email:" | awk -F'Billing Email:' '/Billing Email: /{print $2}' )$cNothing
	echo -e "Billing Phone:"$cGreen$(cat whois-domain.txt  | grep "Billing Phone:" | awk -F'Billing Phone:' '/Billing Phone: /{print $2}')$cNothing

	KasperskyDomainCheck $domain
	echo -e $cBlue"Checking Domain reputation in Fortinet..."$cNothing
	FortiguardQuery=$(curl -s -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0' 'https://www.fortiguard.com/webfilter?q='$domain'&version=9' | grep '<h4 class="info_title">Category:' | awk -F '<h4 class="info_title">Category:' '/<h4 class="info_title">Category: /{print $2}' | sed 's,</h4>,,g' )
	echo -e "This Domain is on category:"$cDarkGray$FortiguardQuery$cNothing" by Fortinet"

	VirusTotalDomainCheck $domain
	
	echo "\n======================== TXT Registers ========================"
	echo -e $cOrange
	host -t TXT $domain
	echo -e $cNothing
	echo "======================== MX Registers  ========================"
	host -t MX $domain | awk {'print $1 " priority: \033[32m" $6 "\033[0m = \033[31m" $7 "\033[0m"'}
	echo "======================== A Register    ========================"
	echo -e $cOrange
	host -t A $domain
	echo -e $cNothing
	echo "======================== SOA Registers ========================"
	echo -e $cOrange
	host -t SOA $domain 
	echo -e $cNothing
	echo "======================== NS Registers  ========================"
	echo -e $cOrange
	host -t NS $domain
	echo -e $cNothing
	echo "======================== SPF Check  ========================"
	echo -e $cOrange
	spfCheck $domain
	echo -e $cNothing


	echo -e $cBlue"Looking for subdomains or DNS A Registers for Domain "$domain
	curl -s -k 'https://otx.alienvault.com/api/v1/indicators/domain/'$domain'/passive_dns' | jq -r ".passive_dns[].hostname" | sort -u > domains.txt
	curl -s -k 'http://web.archive.org/cdx/search/cdx?url=*.'$domain'/*&output=text&fl=original&collapse=urlkey' | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sort -u >> domains.txt
	
   if [ "$VirusTotalToken" = "" ];then
		echo -e $cRed"Any API key found, you need to set an API key in api.config file to use this function. See https://virustotal.com"$cNothing
	else
		curl -s -k 'https://www.virustotal.com/vtapi/v2/domain/report?apikey='$VirusTotalToken'&domain='$domain | jq -r '.subdomains[]' >> domains.txt
	fi;
	
	echo -e "Done!"$cNothing
	sort domains.txt | uniq > domains.list

	echo -e "Subdomains detected: $cPurple{"
	cat domains.list | nl
	echo -e "}"$cNothing

	read -p "Do you want to show emails list for this domain? y/n: " -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]] 
	then
		GetEmails $domain
	fi;

	echo -e "\n"
	read -p "Do you want to show information about each subdomains detected? y/n: " -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]] 
	then
		while read line;
		do
			echo -e $cDarkGray"\n---------------------- Details ----------------------"$cNothing
			echo -e "Subdomain: "$cGreen$line$cNothing
			VirusTotalDomainCheck $line
			echo ""
			hostIP=$(host $line | awk '{print $4}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
			if [ -n "$hostIP" ]; then
				LoadBalancer=$(host $line | awk '{print $4}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | wc -l)
				if [[ LoadBalancer -gt 1 ]];then
					host $line | awk '{print $4}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > ip.txt
					echo -e $cPurple"Load balancer detected"$cNothing
					echo -e "Balancer IPs "$cPurple"{"$(host $line | awk '{print $4}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')"}"$cNothing
					while read balancerIP;
					do
        				echo -e "Host: "$cOrange$line" - Balancer IP: "$balancerIP$cNothing
        				searchByIP $balancerIP 0
					done < ip.txt
				else
					echo -e "IP detected: "$cGreen$hostIP$cNothing
					searchByIP $hostIP 0
				fi;
			
			else
    			echo -e $cRed"Today: Could not resolve hostname."$cNothing
			fi

		done < domains.list
	fi;
	
}

function searchByIP(){
	ip=$1
	printBanner=$2

	if [ $printBanner -eq "1" ]; then
		banner$(( RANDOM % 2 ))
	fi;

	echo -e $cBlue"Processing whois query for IP "$ip"..."$cNothing
	whois $ip > whois-ip.txt

	echo -e "AS: "$cPurple$(cat whois-ip.txt | grep "aut-num:" | awk '{print $2}')$cNothing
	echo -e "Responsible: "$cPurple$(cat whois-ip.txt | grep "responsible:" | awk -F 'responsible:' '/responsible: /{print $2}')$cNothing
	echo -e "PTR: "$cPurple$(dig -x $ip +short)$cNothing
	echo -e "Org: "$cPurple$(cat whois-ip.txt | grep -E 'Organization:|owner:|org-name:' | awk -F'owner:|Organization:|org-name:' '/owner:|Organization:|org-name: /{print $2}')$cNothing
	echo -e "Country: "$cPurple$(cat whois-ip.txt | grep -E 'Country:|country:' | sed -n -e 1p | awk '{print $2}')$cNothing
	echo -e "City: "$cPurple$(cat whois-ip.txt | grep -E 'City:|city:' | awk '{print $2}')$cNothing

	echo -e $cBlue"Looking for domains related to IP "$ip"..."
	shodanQuery=$(curl -s -X 'GET' -H 'accept: application/json' https://internetdb.shodan.io/$ip)

	if [ "$VirusTotalToken" = "" ];then
		echo -e $cRed"Any API key found, you need to set an API key in api.config file to use this function. See https://virustotal.com"$cNothing
	else
		curl -s -X GET 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey='$VirusTotalToken'&ip='$ip > virusTotal2.txt
	   cat virusTotal2.txt | jq -r '.resolutions[].hostname' > passive_dns.txt
	fi;
	
	curl -s 'https://otx.alienvault.com/api/v1/indicators/IPv4/'$ip'/passive_dns' | jq -r '.passive_dns[].hostname' >> passive_dns.txt
	echo $shodanQuery | jq -r '.hostnames[]' >> passive_dns.txt
	sort passive_dns.txt | uniq > passive_dns.list
	echo -e "Done!"$cNothing

	Domains=$(cat passive_dns.list)
	ports=$(echo $shodanQuery | jq -r '.ports')
	vulns=$(echo $shodanQuery | jq -r '.vulns')

	echo -e "Domains detected: "$cPurple"{"$Domains"}"$cNothing
	echo -e "ports detected: "$cPurple$ports$cNothing
	echo -e "vulns detected: "$cPurple$vulns$cNothing

	echo -e $cBlue"Looking for IP information related with VPN, TOR, Proxy, etc for IP "$ip

	if [ "$vpnapiToken" = "" ];then
		echo -e $cRed"Any API key found, you need to set an API key in api.config file to use this function. See #https://vpnapi.io/"$cNothing
	else
		SecInfo=$( curl -s -k 'https://vpnapi.io/api/'$ip'?key='$vpnapiToken)
		echo -e "Done!"$cNothing

		echo -e "Proxy: "$cPurple$(echo $SecInfo | jq -r '.security.proxy')$cNothing
		echo -e "VPN: "$cPurple$(echo $SecInfo | jq -r '.security.vpn')$cNothing
		echo -e "TOR: "$cPurple$(echo $SecInfo | jq -r '.security.tor')$cNothing
		echo -e "Relay: "$cPurple$(echo $SecInfo | jq -r '.security.relay')$cNothing
	fi;
	

	KasperskyIPCheck $ip
	FortiguardQuery=$(curl -s -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0' 'https://www.fortiguard.com/webfilter?q='$ip'&version=9' | grep '<h4 class="info_title">Category:' | awk -F '<h4 class="info_title">Category:' '/<h4 class="info_title">Category: /{print $2}' | sed 's,</h4>,,g' )
	echo -e "This IP is on category: "$cDarkGray$FortiguardQuery$cNothing" by Fortinet"


}

function searchByHostname(){
	hostname=$1

	KasperskyDomainCheck $hostname
	FortiguardQuery=$(curl -s -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0' 'https://www.fortiguard.com/webfilter?q='$hostname'&version=9' | grep '<h4 class="info_title">Category:' | awk -F '<h4 class="info_title">Category:' '/<h4 class="info_title">Category: /{print $2}' | sed 's,</h4>,,g' )
	echo -e "This hostname is on category: "$cDarkGray$FortiguardQuery$cNothing" by Fortinet"

	VirusTotalDomainCheck $hostname

	echo -e $cDarkGray"---------------------- Details ----------------------"$cNothing
	echo -e "hostname: "$cGreen$hostname$cNothing
	hostIP=$(host $hostname | awk '{print $4}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
	if [ -n "$hostIP" ]; then
		LoadBalancer=$(host $hostname | awk '{print $4}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | wc -l)
		if [[ LoadBalancer -gt 1 ]];then
			host $hostname | awk '{print $4}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > ip.txt
			echo -e $cPurple"Load balancer detected"$cNothing
			echo -e "Balancer IPs "$cPurple"{"$(host $hostname | awk '{print $4}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')"}"$cNothing
			while read balancerIP;
			do
       			echo -e 'Host: '$cOrange$hostname' - Balancer IP: '$balancerIP$cNothing
       			searchByIP $balancerIP 0
			done < ip.txt
		else
			echo -e "IP detected: "$cGreen$hostIP$cNothing
			searchByIP $hostIP 0
		fi;
		
	else
    	echo -e $cRed"Could not resolve hostname."$cNothing
	fi

}

function VirusTotalDomainCheck(){
	echo -e $cBlue"\nChecking Domain information in VirusTotal..."$cNothing
	vDomain=$1
	if [ "$VirusTotalToken" = "" ];then
		echo -e $cRed"Any API key found, you need to set an API key in api.config file to use this function. See https://virustotal.com"$cNothing
	else
		curl -s -X GET 'https://www.virustotal.com/vtapi/v2/domain/report?apikey='$VirusTotalToken'&domain='$vDomain > virusTotal.txt
		detected_urlsRow=$(cat virusTotal.txt | jq -r '.detected_urls' | jq length)
		vtcount=0
		((detected_urlsRow--))
		echo -e $cBlue"\nMalicious activity report"$cNothing
		while [ $vtcount -le $detected_urlsRow ]
		do
			url=$(cat virusTotal.txt | jq -r '.detected_urls['$vtcount'].url')
			positives=$(cat virusTotal.txt | jq -r '.detected_urls['$vtcount'].positives')
			total=$(cat virusTotal.txt | jq -r '.detected_urls['$vtcount'].total')
			scan_date=$(cat virusTotal.txt | jq -r '.detected_urls['$vtcount'].scan_date')
			echo -e "At "$cDarkGray$scan_date$cNothing" this domain was detected for "$cDarkGray$positives"/"$total$cNothing" AV engines with url: {"$url"}"
			((vtcount++))
		done

		echo -e $cBlue"\nResolution IPs history..."$cNothing
		resolutionsRows=$(cat virusTotal.txt | jq -r ".resolutions" | jq length)
		vtcount=0
		((resolutionsRows--))
		while [ $vtcount -le $resolutionsRows ]
		do
			last_resolved=$(cat virusTotal.txt | jq -r '.resolutions['$vtcount'].last_resolved')
			ip_address=$(cat virusTotal.txt | jq -r '.resolutions['$vtcount'].ip_address')
			echo -e "At "$cDarkGray$last_resolved$cNothing" this domain was detected with IP: "$cDarkGray$ip_address$cNothing
			((vtcount++))
		done
	fi;
}


function KasperskyDomainCheck(){
	echo -e $cBlue"\nChecking Domain reputation in Kaspersky..."$cNothing
	if [ "$KasperskyTIPToken" = "" ];then
		echo -e $cRed"Any API key found, you need to set an API key in api.config file to use this function. See https://opentip.kaspersky.com"$cNothing
	else
		kDomain=$1
		Domainzone=$(curl -s -X GET 'https://opentip.kaspersky.com/api/v1/search/domain?request='$kDomain -H 'x-api-key:'$KasperskyTIPToken | jq -r '.Zone')
		KasperskyTIPMessage=""
		Color="\033[30m"
		case $Domainzone in 
				"Red")
				KasperskyTIPMessage="classified as Malware."
				Color=$cRed			
				;;
				"Yellow")
				KasperskyTIPMessage="classified as Adware and other (Adware, Pornware, and other programs)."
				Color=$cYellow	
				;;
				"Green")
				KasperskyTIPMessage="No threats detected."
				Color=$cGreen	
				;;
				"Grey")
				KasperskyTIPMessage="No data or not enough information is available."
				Color=$cLightGray	
				;;
				"Orange")
				KasperskyTIPMessage="classified as Malware."
				Color=$cOrange	
				;;
		esac 
		echo -e $cDarkGray"This Domain is on "$Color$Domainzone$cDarkGray" zone by Kaspersky, "$KasperskyTIPMessage$cNothing
	fi;
}

function KasperskyIPCheck(){
	echo -e $cBlue"\nChecking IP reputation in Kaspersky..."$cNothing
	if [ "$KasperskyTIPToken" = "" ];then
		echo -e $cRed"Any API key found, you need to set an API key in api.config file to use this function. See https://opentip.kaspersky.com"$cNothing
	else
		kIP=$1
		KasperskyTIPQuery=$(curl -s -X GET 'https://opentip.kaspersky.com/api/v1/search/ip?request='$kIP -H 'x-api-key:'$KasperskyTIPToken)
		IPzone=$(echo $KasperskyTIPQuery | jq -r '.Zone')
		KasperskyTIPMessage=""
		Color=$cNothing
		case $IPzone in 
				"Red")
				KasperskyTIPMessage="classified as Malware."
				Color=$cRed			
				;;
				"Yellow")
				KasperskyTIPMessage="classified as Adware and other (Adware, Pornware, and other programs)."
				Color=$cYellow
				;;
				"Green")
				KasperskyTIPMessage="No threats detected."
				Color=$cGreen	
				;;
				"Grey")
				KasperskyTIPMessage="No data or not enough information is available."
				Color=$cLightGray	
				;;
				"Orange")
				KasperskyTIPMessage="classified as Malware."
				Color=$cOrange	
				;;
		esac 
		echo -e $cDarkGray"This IP is on "$Color$IPzone$cDarkGray" zone by Kaspersky, "$KasperskyTIPMessage$cNothing
	fi;
}

function GetEmails(){
   HDomain=$1
	echo -e $cBlue"\nHunter.io: Looking for emails for "$HDomain$cNothing
	if [ "$hunterToken" = "" ];then
		echo -e $cRed"Any API key found, you need to set an API key in api.config file to use this function. See https://hunter.io"$cNothing
	else
		curl -s -k "https://api.hunter.io/v2/domain-search?domain="$HDomain"&api_key="$hunterToken | jq -r '.data.emails[].value' > emails.txt
		echo -e $cBlue"Done!"$cNothing
	fi;

	echo -e $cBlue"Findthatlead.com: Looking for emails for "$HDomain$cNothing
	if [ "$FindThatLeadToken" = "" ];then
		echo -e $cRed"Any API key found, you need to set an API key in api.config file to use this function. See https://app.findthatlead.com"$cNothing
	else
		curl -s -k -X POST "https://app.findthatlead.com/api/searchTool" -H 'Authorization: Bearer '$FindThatLeadToken -H 'Content-Type: application/x-www-form-urlencoded' -d "domComp=$HDomain&token=$FindThatLeadToken&type=all" | jq -r ".response[].emails[].email" >> emails.txt
		echo -e $cBlue"Done!"$cNothing
	fi; 

	sort emails.txt | uniq > emails.list
	echo -e "Emails founds:"$cPurple"{"
	cat emails.list | nl
	echo -e "}"$cNothing


}

function BlacklistCheck(){
	bDomainOrIP=$1
	curl -s -k -X GET 'https://mxtoolbox.com/api/v1/Lookup?command=blacklist&argument='$bDomainOrIP'&resultindext=1&disableRhsbl=true&format=1' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0' -H 'TempAuthorization: 27eea1cd-e644-4b7b-bebe-38010f55dab3' > blacklist.txt
	echo -e $cBlue"\nChecking if this Domain or IP has been used for spam activity..."$cNothing

	blacklistRows=$(cat blacklist.txt | jq -r ".ResultDS.SubActions" | jq length)
	blcount=0
	((blacklistRows--))
	while [ $blcount -le $blacklistRows ]
	do
		blStatus=$(cat blacklist.txt | jq -r '.ResultDS.SubActions['$blcount'].Status')
		blName=$(cat blacklist.txt | jq -r '.ResultDS.SubActions['$blcount'].Name')

		case $blStatus in 
				"0")
				echo -e "Checking on "$cBlue$blName$cNothing" - "$cGreen"Clean"$cNothing
				;;
				"1")
				echo -e "Checking on "$cBlue$blName$cNothing" - "$cYellow"TimeOut"$cNothing
				;;
				"2")
				echo -e "Checking on "$cBlue$blName$cNothing" - "$cRed"Listed!"$cNothing
				;;
		esac 
		((blcount++))
	done
}

function spfCheck(){
	spfDomain=$1
	curl -s -k -X GET 'https://mxtoolbox.com/api/v1/Lookup?command=spf&argument='$spfDomain'&resultindext=2&disableRhsbl=true&format=1' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0' -H 'TempAuthorization: 27eea1cd-e644-4b7b-bebe-38010f55dab3' > spf.txt
	echo -e $cBlue"\nChecking SPF for domain "$spfDomain$cNothing

	echo -e "SPF detected: "$cOrange$(dig txt $spfDomain +short | grep 'spf')$cNothing

	spfRows=$(cat spf.txt | jq -r ".ResultDS.SubActions" | jq length)
	spfCount=0
	((spfRows--))
	while [ $spfCount -le $spfRows ]
	do
		spfStatus=$(cat spf.txt | jq -r '.ResultDS.SubActions['$spfCount'].Status')
		spfName=$(cat spf.txt | jq -r '.ResultDS.SubActions['$spfCount'].Name')
		spfResponse=$(cat spf.txt | jq -r '.ResultDS.SubActions['$spfCount'].Response')

		case $spfStatus in 
				"0")
				echo -e "Checking module "$cBlue$spfName$cNothing" - "$cGreen$spfResponse$cNothing
				;;
				"1")
				echo -e "Checking module "$cBlue$spfName$cNothing" - "$cYellow"TimeOut"$cNothing
				;;
				"2")
				echo -e "Checking module "$cBlue$spfName$cNothing" - "$cRed$spfResponse$cNothing
				;;
		esac 
		((spfCount++))
	done
}

function verifyEmail(){
	email=$1

	echo -e $cBlue"Checking if email exist..."
	if [ "$realemailToken" = "" ];then
		echo -e $cRed"Any API key found, you need to set an API key in api.config file to use this function. See https://isitarealemail.com"$cNothing
	else
		status=$(curl -s -H 'Authorization:'$realemailToken "https://isitarealemail.com/api/email/validate?email="$email | jq '.status' | sed 's,",,g')
		echo -e "Done!"$cNothing

		case $status in 
			"valid")
			echo -e "Status: "$cGreen" the email address is valid."$cNothing
			;;
			"invalid")
			echo -e "Status: "$cOrange" the email address is invalid. It is either malformed, there is no mail server at the domain or the address does not exist on the server."$cNothing
			;;
			"unknown")
			echo -e "Status: "$cRed" it cannot be determined if the email address exists in the mail server. This may happen if there is a mail server which is unresponsive. These validations are not charged. Depending on your use case you may want to block or allow unknown's"$cNothing
			;;
		esac
	fi;
	
}

banner$(( RANDOM % 2 ))
menu







