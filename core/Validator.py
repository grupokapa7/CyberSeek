import re
import ipaddress
    
class validator:
    
    def domain(value):
        try:
            ipaddress.ip_address(value)
            return False
        except ValueError:
            domain_pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")
            return bool(domain_pattern.match(value))

    def ip_address(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def url(value):
        try:
            url_pattern = re.compile(
                r'^(https?|ftp):\/\/'  # Scheme (http, https, or ftp)
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # Domain
                r'localhost|'  # localhost
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IP address
                r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6 address
                r'(?::\d+)?'  # Port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE
            )

            return bool(url_pattern.match(value))
        except:
            return False

    def hostname(value):
        try:
            ipaddress.ip_address(value)
            return False
        except:
            hostname_pattern = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
            return bool(hostname_pattern.match(value))

    def hash(value):
        try:
            md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
            sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')
            sha512_pattern = re.compile(r'^[a-fA-F0-9]{128}$')
                
            #if bool(md5_pattern.match(value)):
            #    return True
            if bool(sha256_pattern.match(value)):
                return True
            elif bool(sha512_pattern.match(value)):
                return True
            else:
                return False   
        except:
            return False