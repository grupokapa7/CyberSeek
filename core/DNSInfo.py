import dns.resolver
from tabulate import tabulate
from core.core import *
from core.VirusTotal import *
from core.AlienVault import *

class DNSInformation:

    def main(hostname):
        records_type_a= DNSInformation.dns_record_type_a(hostname)
        records_type_mx=DNSInformation.dns_record_type_mx(hostname)
        records_type_txt=DNSInformation.dns_record_type_txt(hostname)
        records_type_ns=DNSInformation.dns_record_type_ns(hostname)
        records_type_soa=DNSInformation.dns_record_type_soa(hostname)

        records=[]
        try:
            for x in records_type_a:
                records.append(x)
        except:
            pass

        try:
            for x in records_type_mx:
                records.append(x)
        except:
            pass
        
        try:
            for x in records_type_txt:
                records.append(x)
        except:
            pass
        
        try:
            for x in records_type_ns:
                records.append(x)
        except:
            pass

        try:
            for x in records_type_soa:
                records.append(x)
        except:
            pass
       
        
        
        

        headers=["Registers","Value"]
        print(tabulate(records, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))

        virustotal_results=VirusTotal.subdomains_enumeration(hostname)
        alienvault_results=AlienVault.subdomains_enumeration(hostname)
        results=[]
        try:
            for x in virustotal_results:
                results.append(x)
            for x in alienvault_results:
                results.append(x)
        except:
            pass

        headers=["Engine","Hostname"]
        print(tabulate(results, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))

    def dns_record_type_a(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'A')
            records=[]
            for x in result:
                row=["A",x]
                records.append(row)
            
            return records

        except:
            pass

    def dns_record_type_mx(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'MX')
            records=[]
            for x in result:
                row=["MX",x]
                records.append(row)
            return records

        except:
            pass

    def dns_record_type_txt(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'TXT')
            records=[]
            for x in result:
                row=["TXT",x]
                records.append(row)
            return records

        except:
            pass

    def dns_record_type_ns(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'NS')
            records=[]
            for x in result:
                row=["NS",x]
                records.append(row)
            return records

        except:
            pass

    def dns_record_type_soa(hostname):
        try:
            result = dns.resolver.resolve(hostname, 'SOA')
            records=[]
            for x in result:
                row=["SOA",x]
                records.append(row)
            return records

        except:
            pass
