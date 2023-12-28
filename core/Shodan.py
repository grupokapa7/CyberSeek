
import socket
import requests
from core.core import *
from fake_useragent import UserAgent
import dns.resolver
from tabulate import tabulate

class Shodan:
    def check_resolution_ip(ip):
        try:
            print(f"\nChecking ip resolution data on Shodan for {c.Orange}{ip}{c.Reset}")
            url_session = f"https://internetdb.shodan.io/{ip}"
            agent=UserAgent().random
            headers = { 'User-Agent': agent }
            response = requests.get(url_session,headers=headers)
            
            if response.status_code==200:
                data=response.json()
                analysis=data['hostnames']
                result=[]

                for x in analysis:
                    row=["Shodan",x]
                    result.append(row)

                return result

        except:
            print(f"{c.Red}Error on ip resolution process for Shodan!{c.Reset}")
            pass

    def check_ports_vuls(value):
        try:
            print(f"\nChecking open ports and vulns data on Shodan for {c.Orange}{value}{c.Reset}")

            try:
                result = dns.resolver.resolve(value, 'A')
                for x in result:
                    print(f"IP detected for {c.Orange}{value}{c.Reset} is {c.Orange}{x}{c.Reset}")
                    url_session = f"https://internetdb.shodan.io/{x}"
                    agent=UserAgent().random
                    headers = { 'User-Agent': agent }
                    response = requests.get(url_session,headers=headers)
            
                    if response.status_code==200:
                        data=response.json()
                        try:
                            ports=[]
                            for port in data['ports']:
                                try:  
                                    print(f"Checking connection to port {c.Orange}{port}{c.Reset}")
                                    conn=socket.socket()  
                                    conn.settimeout(3)
                                    conn.connect((value,port))  
                                    banner = conn.recv(1024) 
                                    row=[port,banner.decode('utf-8')]
                                    ports.append(row)
                                except socket.timeout:
                                    print(f"Connection timeout for port {c.Orange}{port}{c.Reset}")
                                except:
                                    pass
                                
                            
                            header=["Port","Banner"]
                            print(tabulate(ports, header,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))

                        except:
                            pass

                        try:
                            vuls=[]
                            for vul in data['vulns']:
                                row=[vul]
                                vuls.append(row)

                            header=["Vulnerabilities"]
                            print(tabulate(vuls, header,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
                            
                        except:
                            pass
                        

            except:
                print(f"{c.Red}Error no ip detected!{c.Reset}")
                pass

        except:
            print(f"{c.Red}Error on open ports detection process for Shodan!{c.Reset}")
            pass