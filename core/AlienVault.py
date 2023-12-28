
import requests
from core.core import *
from fake_useragent import UserAgent

class AlienVault:
    def check_resolution_ip(ip):
        try:
            print(f"\nChecking ip resolution data on AlienVault for {c.Orange}{ip}{c.Reset}")
            url_session = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
            agent=UserAgent().random
            headers = { 'User-Agent': agent }
            response = requests.get(url_session,headers=headers)
            
            if response.status_code==200:
                data=response.json()
                analysis=data['passive_dns']
                result=[]

                for x in analysis:
                    host_name=x["hostname"]
                    row=["AlienVault",host_name]
                    result.append(row)

                return result

        except:
            print(f"{c.Red}Error on ip resolution process for AlienVault!{c.Reset}")
            pass

    def subdomains_enumeration(domain):
        try:
            print(f"\nChecking subdomain enumeration on AlienVault for {c.Orange}{domain}{c.Reset}")
            url_session = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            agent=UserAgent().random
            headers = { 'User-Agent': agent }
            response = requests.get(url_session,headers=headers)
            
            if response.status_code==200:
                data=response.json()
                analysis=data['passive_dns']
                result=[]

                list1=[]

                for x in analysis:
                    list1.append(x["hostname"])

                list2=list(dict.fromkeys(list1))

                for x in list2:
                    row=["AlienVault",x]
                    result.append(row)

                return result

        except:
            print(f"{c.Red}Error on subdomain enumeration process for AlienVault!{c.Reset}")
            pass