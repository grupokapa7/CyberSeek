import requests
from core.utilities import *

class MXToolBox:
    def __init__(self):
        #this is the temp token when you visit MXToolBox, is not your lucky day bro :(
        self.token = "27eea1cd-e644-4b7b-bebe-38010f55dab3"
        self.agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0'
        self.base_url = "https://mxtoolbox.com"
    
    def blacklist_check(self,query):
        try:
            if len(query) > 253:
                return {"success": "False", "result": "Input too long."}
            
            if not utilities.valid_domain(query) and not utilities.valid_ip(query):
                return {"success": "False", "result": "Invalid domain or IP."}
            
            url = f"{self.base_url}/api/v1/Lookup"
            params = {
                "command": "blacklist",
                "argument": query,
                "resultindext": 1,
                "disableRhsbl": "true",
                "format": 1
            }
            headers = {
                "User-Agent": self.agent,
                "TempAuthorization": self.token
            }
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                data["success"] = "True"
                return data
            else:
                data ={"success":"False","result":f"Error trying to check {query} on MX ToolBox"}
                return data
        except:
            data ={ "success":"False", "result":"Internal error" }
            return data

    def spf_check(self,query):
        try:
            if len(query) > 253:
                return {"success": "False", "result": "Input too long."}
            
            if not utilities.valid_domain(query):
                return {"success": "False", "result": "Invalid domain."}
            
            url = f"{self.base_url}/api/v1/Lookup"
            params = {
                "command": "spf",
                "argument": query,
                "resultindext": 2,
                "disableRhsbl": "true",
                "format": 1
            }
            headers = {
                "User-Agent": self.agent,
                "TempAuthorization": self.token
            }
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                data["success"] = "True"
                return data
            else:
                data ={"success":"False","result":f"Error trying to check {query} on MX ToolBox"}
                return data
        except:
            data ={ "success":"False", "result":"Internal error" }
            return data