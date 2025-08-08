import subprocess, re
from core.utilities import *

class Reconnaissance:

    @staticmethod
    def whois_lookup(query):
        try:
            if not query or len(query) > 253:
                return {"success": "False", "result": "Invalid input"}

            if utilities.is_private_ip(query):
                return {"success": "False", "result": "Internal network not allowed."}

            if not utilities.valid_domain(query) and not utilities.valid_ip(query):
                return {"success": "False", "result": "Invalid domain or IP"}

            cmd = ['whois', query]
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=5)

            if "Invalid query" in result:
                return {"success": "False", "result": "Invalid WHOIS query"}

            return {"success": "True", "result": result.strip()}
        
        except subprocess.CalledProcessError:
            return {"success": "False", "result": "WHOIS lookup failed."}
        except Exception:
            return {"success": "False", "result": "Server error"}


    @staticmethod
    def dns_lookup_all(query):
        if len(query) > 253:
            return {"success": "False", "result": "Input too long."}
        
        if not utilities.valid_domain(query) and not utilities.valid_ip(query):
            return {"success": "False", "result": "Invalid domain or IP."}
        
        if utilities.is_private_ip(query):
            return {"success": "False", "result": "Internal network not allowed."}

        result = []
        for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'DS', 'PTR']:
            result.append(Reconnaissance.dns_lookup(query, record_type,True))
        return result

        
    @staticmethod
    def dns_lookup(query, type,internal=False):
        try:
            if len(query) > 253 or len(type) > 10:
                return {"success": "False", "type": type, "result": "Input too long."}
            
            if not utilities.valid_domain(query) and not utilities.valid_ip(query):
                return {"success": "False", "type": type, "result": "Invalid domain or IP."}

            VALID_TYPES = {'A','AAAA','MX','TXT','NS','CNAME','SOA','DS','PTR'}
            if type not in VALID_TYPES:
                return {"success": "False", "type": type, "result": "Unsupported DNS record type."}

            if utilities.is_private_ip(query):
                return {"success": "False", "type": type, "result": "Internal network not allowed."}

            cmd = ['dig', '+short', '-x', query] if type == 'PTR' else ['dig', '+short', query, type]
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=5)
            if internal:
                return {'success': 'True', 'type': type, 'result': result.strip()}
            return [{'success': 'True', 'type': type, 'result': result.strip()}]
            
        except subprocess.CalledProcessError as e:
            return {"success": "False", "type": type, "result": "Lookup failed."}
        except Exception:
            return {"success": "False", "type": type, "result": "Server error."}
