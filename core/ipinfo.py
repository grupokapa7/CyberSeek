import requests
from core.reccon import *
from core.utilities import *
from urllib.parse import urlparse

class ipinfo:
    def suggestion(query):
        try:
            if utilities.valid_ip(query):
                output = ipinfo.getIpLocation(query)
                return output
            elif utilities.valid_domain(query):
                ip = Reconnaissance.dns_lookup(query,'A',True)
                output = ipinfo.getIpLocation(ip['result'].split('\n')[0])
                return output
            elif utilities.valid_url(query):
                parsed = urlparse(query)
                host = parsed.hostname
                ip = Reconnaissance.dns_lookup(host,'A',True)
                output = ipinfo.getIpLocation(ip['result'].split('\n')[0])
                return output
            else:
                data ={ "success":"False", "result":"Error trying to recover IP info" }
                return data
        except:
            data ={ "success":"False", "result":"Error trying to recover IP info" }
            return data
    

    def getIpLocation(query):
        try:
            url = f"https://ipinfo.io/{query}/json"
            res = requests.get(url)
            if res.status_code==200:
                data = res.json()
                data["success"]="True"
                return data
            data ={ "success":"False", "result":f"Remote server response with {res.status_code}" }
            return data
        except:
            data ={ "success":"False", "result":"Error trying to recover IP info" }
            return data