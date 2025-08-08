import requests, re
from fake_useragent import UserAgent
from requests import Session

class KasperskyOpenTIP:
    def __init__(self):
        self.session: Session = requests.session()
        self.agent = UserAgent().random
        self.Cym9cgwjk = ""


    def get_valid_cookie(self):
        url_session = "https://opentip.kaspersky.com/ui/checksession"
        headers = { 'User-Agent': self.agent }
        res = requests.get(url_session,headers=headers,timeout=10)
        self.Cym9cgwjk=res.headers["Cym9cgwjk"]

    def kaspersky_lookup(self,query,isUrl=False):
        try:
            self.get_valid_cookie()
            url = 'https://opentip.kaspersky.com/ui/lookup'
            headers = {'User-Agent': self.agent,'cym9cgwjk': self.Cym9cgwjk}
            data = {'query': query,'silent': False,}
        
            res = self.session.post(url, headers=headers, json=data,timeout=10)
            if res.status_code==200:
                data=res.json()
                data["success"]="True"
                return data
            else:
                data ={"success":"False","result":f"Error trying to check {query} on Kaspersky Open TIP"}
                return data
        except:
            data ={ "success":"False", "result":"Internal error" }
            return data

