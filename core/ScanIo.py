import requests
from requests import Session
from fake_useragent import UserAgent
from core.utilities import *

class scanio_sandbox:
    def __init__(self):
        self.base_url = "https://www.filescan.io"
        self.session: Session = requests.session()
        self.agent = UserAgent().random

    def send_url(self,target=""):
        try:
            target_url = utilities.valid_url(target)
            url = self.base_url + '/api/scan/url'
            data = {'url': target_url}
            res = requests.post(url, data=data)
            data=res.json()
            data["success"]="True"
            return data
        except:
            data ={"success":"False","result":f"Error trying to check {target} on Scanio sandbox."}
            return data
        
    def send_file(self,target_file=None,password=None):
        try:
            url = self.base_url + '/api/scan/file'
            files = {
                'file': (
                    target_file.filename,
                    target_file.stream,
                    target_file.content_type or 'application/octet-stream'
                )
            }
            data = {
                'is_private': 'false',
                'description': f"Scan of {target_file.filename}",
            }
            if password:
                data['password']=password
                
            res = requests.post(url, files=files, data=data)
            data=res.json()
            data["success"]="True"
            return data
        except:
            data ={"success":"False","result":f"Error trying to analyze file on Scanio sandbox."}
            return data
        
    def recover_status(self,flow_id=""):
        try:
            url=f"https://www.filescan.io/api/scan/{flow_id}/report?filter=general"
            res = requests.get(url)
            data=res.json()
            data["success"]="True"
            return data
        except:
            data ={"success":"False","result":f"Error trying to check {flow_id} on Scanio sandbox."}
            return data
        
    def get_url_report(self,flow_id=""):
        try:
            url=f"https://www.filescan.io/api/scan/{flow_id}/report?filter=f:renderResults"
            res = requests.get(url)
            data=res.json()
            data["success"]="True"
            return data
        except:
            data ={"success":"False","result":f"Error trying to check {flow_id} on filescanIO sandbox."}
            return data
        
    def get_file_report(self,flow_id=""):
        try:
            url = f"https://www.filescan.io/api/scan/{flow_id}/report?filter=dr:domainResolveResults&filter=f:extractedUrls&filter=f:emulationData&filter=f:strings"
            res = requests.get(url)
            data=res.json()
            data["success"]="True"
            return data
        except:
            data ={"success":"False","result":f"Error trying to check {flow_id} on filescanIO sandbox."}
            return data
        
    def get_mitre_report(self,flow_id=""):
        try:
            url=f"https://www.filescan.io/api/scan/{flow_id}/report?sorting=allSignalGroups(description%3Aasc%2CallMitreTechniques%3Adesc%2CaverageSignalStrength%3Adesc)s"
            res = requests.get(url)
            data=res.json()
            data["success"]="True"
            return data
        except:
            data ={"success":"False","result":f"Error trying to check {flow_id} on Scanio sandbox."}
            return data