import requests
from requests import Session
from fake_useragent import UserAgent

class CiscoTalos:
    def __init__(self):
        self.base_url = "https://talosintelligence.com/cloud_intel"
        self.session: Session = requests.session()
        self.agent = UserAgent().random

    def getSuggestion(self,query):
        try:
            headers={
                'User-Agent':self.agent
            }
            url = f'https://talosintelligence.com/cloud_intel/query_suggestion?query={query}'
            res = self.session.get(url,headers=headers)
            if res.status_code == 200:
                data=res.json()
                data["success"]="True"
                return data
            else:
                data ={"success":"False","result":f"Error trying to check {query} on Cisco Talos Intelligence"}
                return data
        except:
            data ={ "success":"False", "result":"Internal error" }
            return data

    def reputation_lookup(self,query,isUrl=False,isIP=False,isHost=False):
        try:
            headers={
                'User-Agent':self.agent
            }
            url=""

            if isHost or isUrl:
                url = self.base_url + f'/url_reputation?url={query}'

            elif isIP:
                url = self.base_url + f'/ip_reputation?ip={query}'

            elif url =="":
                output = {"success":"False","result":f"Error trying to check {query} on Cisco Talos Intelligence, no action selected"}
                return output
            
            res = self.session.get(url,headers=headers)
            if res.status_code >= 200 and res.status_code < 300:
                data=res.json()
                data["success"]="True"
                return data
            else:
                data ={"success":"False","result":f"Error trying to check {query} on Cisco Talos Intelligence"}
                return data
        except:
            data ={ "success":"False", "result":"Internal error" }
            return data
