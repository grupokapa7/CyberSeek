import requests
from fake_useragent import UserAgent
from requests import Session
import urllib.parse

class VirusTotal:
    def __init__(self):
        self.base_url = "https://www.virustotal.com"
        self.session: Session = requests.session()
        #this is the temp VT token when you visit Virus Total, is not your lucky day bro :(
        self.token = "MTI1MDc2MDQwMjAtWkc5dWRDQmlaU0JsZG1scy0xNzAzNDAwMDI4LjU3Nw=="
        self.agent = UserAgent().random

    def virustotal_lookup(self,query,isIP=False,isHost=False,isHash=False,isUrl=False,getResolutions=False,getCommunicatingFiles=False,
                          getSubdomains=False,getContactedUrls=False,getContactedDomains=False,getReferrerFiles=False,
                          getContactedIps=False,getDroppedFiles=False,getSiblings=False):
        try:
            if len(query) >= 300:
                return {"success": False, "result": "Invalid input"}
            
            url=""
            if isIP:
                url = self.base_url + f"/ui/ip_addresses/{query}"
            elif isHost:
                url = self.base_url + f"/ui/domains/{query}"
            elif isHash:
                url = self.base_url + f"/ui/files/{query}"
            elif isUrl:
                url_encode= urllib.parse.quote(query,safe='')
                url = self.base_url + f"/ui/search?limit=20&relationships%5Bcomment%5D=author%2Citem&query={url_encode}"
            else:
                data ={"success":"False","result":f"Error trying to detect valid format for {query}"}
                return data

            if getResolutions:
                url = url + "/resolutions"
            elif getCommunicatingFiles:
                url = url + "/communicating_files"
            elif getSubdomains:
                url = url + "/subdomains"
            elif getReferrerFiles:
                url = url + "/referrer_files"
            elif getSiblings:
                url = url + "/siblings"
            elif getContactedUrls:
                url = url + "/contacted_urls"
            elif getContactedDomains:
                url = url + "/contacted_domains"
            elif getContactedIps:
                url = url + "/contacted_ips"
            elif getDroppedFiles:
                url = url + "/dropped_files"
            
            headers = { 
                'User-Agent': self.agent, 
                'X-VT-Anti-Abuse-Header': self.token,
                'X-Tool': 'vt-ui-main',
                'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8'
                }
            res = requests.get(url,headers=headers,timeout=10)
            
            if res.status_code==200:
                data = res.json()
                data["success"]="True"
                return data
            else:
                data ={"success":"False","result":f"Error trying to check {query} on Virus Total"}
                return data
        except:
            data ={ "success":"False", "result":"Internal error" }
            return data
        