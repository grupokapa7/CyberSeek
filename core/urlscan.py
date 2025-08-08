import configparser
import requests
from requests import Session
from fake_useragent import UserAgent

class UrlScanIO:
    def __init__(self):
        self.base_url = "https://urlscan.io/api/v1"
        self.session: Session = requests.session()
        self.agent = UserAgent().random

    def get_quote(self,):
        headers={
            'User-Agent':self.agent
        }

        url = self.base_url + '/quotas'

        res = self.session.get(url,headers=headers)
        print("output",res.text)

    def get_token(self):
        config = configparser.ConfigParser(interpolation=None)
        config.read("tokens.ini")

        token = ""
        if config.has_section("Scanurl") and "token_scanurl" in config["Scanurl"]:
            token = config["Scanurl"]["token_scanurl"]
            return token
        return token
    
    def get_result(self,uuid):
        token = self.get_token()
        if not token:
            data ={"success":"False","result":f"please set a token for UrlScan.io"}
            return data
        
        url = self.base_url + "/result/" + uuid + "/"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": token
        }
        res = requests.get(url, headers=headers)
        print(res.status_code,res.text)
        return res.json()
                    
    def scan_url(self,query):
        token = self.get_token()
        if not token:
            data ={"success":"False","result":f"please set a token for UrlScan.io"}
            return data
        
        url = self.base_url + "/scan"

        payload = {
            "url": query,
        }
        headers = {
            "Content-Type": "application/json",
            "x-api-key": token
        }

        res = requests.post(url, json=payload, headers=headers)

        if res.status_code == 200:
            output = res.json()
            output["success"]="True"
            return output
        else:
            data ={"success":"False","result":f"Error trying to check {query} on urlscan.io"}
            return data