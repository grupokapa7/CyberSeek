# CyberSeek
this is an OSINT tool that helps you with the following activities:

-Search information about an IP (reputacion with Kaspersky and Fortinet, malware activity, domains related with these IP, open ports, vulns)
-Search information about domain (reputacion with Kaspersky and Fortinet, malware activity, subdomains and A DNS registers list, some emails enumeration, 
                                  resolution IPs history, DNS registers like MX,A,TXT,NS and SOA )
-Search information about hostname (reputacion with Kaspersky and Fortinet, malware activity, resolution IP history, load balancer detection)
-email validation (check if an email exist)


some APIs are required for modules (Kaspersky, malware activity, email enumeration, subdomain enumeration)
the api.config file stores your tokens for each account, you can get your tokens from the following site:
    Kaspersky site https://opentip.kaspersky.com
    VirusTotal site https://virustotal.com
    VPNApi site https://vpnapi.io/
    RealEmail https://isitarealemail.com
    Hunter https://hunter.io
    FindThatLead https://app.findthatlead.com
