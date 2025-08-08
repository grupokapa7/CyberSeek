import re, configparser, ipaddress
from urllib.parse import urlparse

class utilities:
	
    def save_tokens(data):
        if not isinstance(data, dict) or not data:
            return {"success": "False", "result": "Invalid JSON structure"}

        config = configparser.ConfigParser(interpolation=None)
        config["Scanurl"] = {} 
        for key, value in data.items():
            config["Scanurl"][str(key)] = str(value)

        try:
            with open('tokens.ini', 'w') as configfile:
                config.write(configfile)
            return {"success": "True", "result": "Success"}
        except Exception as e:
            return {"success": "False", "result": f"Failed to save tokens"}
        
    def get_tokens():
        try:
            config = configparser.ConfigParser(interpolation=None)
            config.read("tokens.ini")

            data = {}
            for section in config.sections():
                data[section] = dict(config[section])
            return data
        except:
            return None
        
    def valid_ip(ip):
        try:
            return all(0 <= int(part) <= 255 for part in ip.split('.')) and ip.count('.') == 3
        except ValueError:
            return False

    def valid_domain(domain):
        return bool(re.fullmatch(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$', domain))

    def detect_hash_type(h):
        if re.fullmatch(r'[a-fA-F0-9]{32}', h):
            return "MD5"
        if re.fullmatch(r'[a-fA-F0-9]{64}', h):
            return "SHA256"
        if re.fullmatch(r'[a-fA-F0-9]{128}', h):
            return "SHA512"
        return None

    def valid_url(url):
        parsed = urlparse(url if urlparse(url).scheme else 'http://' + url)
        return parsed.geturl()
    
    def is_private_ip(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
