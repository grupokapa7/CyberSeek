
# CyberSeek v3.0
CyberSeek is an open source project that empowers users with a broad range of cybersecurity analysis tools, combining the power of various threat intelligence sources into one unified platform.

### Installation
```bash
git clone https://github.com/sp34rh34d/CyberSeek.git
cd CyberSeek
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
cd CyberSeek && chmod +x app.py
```
### One line instalation
```bash
git clone https://github.com/sp34rh34d/CyberSeek.git && cd CyberSeek && python3 -m venv env && source env/bin/activate && pip3 install -r requirements.txt && chmod +x app.py
```
Default username/password `admin:arasaka`

### Key Features
* IP Reputation Lookup (VirusTotal, Kaspersky, Cisto Talos)
* Domain Reputation Lookup (VirusTotal, Kaspersky, Cisto Talos)
* Hostname Reputation Lookup (VirusTotal, Kaspersky, Cisto Talos)
* URL Analysis (VirusTotal, Kaspersky, Cisto Talos)
* File Analysis using MD5/SHA256/SHA512 hashes (VirusTotal, Kaspersky, MalwareBazaar)
* Blacklist Check (MXToolBox)
* Whois Lookup
* SPF Check (MXToolBox)
* DNS Information
* Sandbox Analysis (Filescan.io)

### Future Features
* EML Analysis - [Smasher project](https://github.com/sp34rh34d/Smasher) will be part of CyberSeek as EML Analysis feature, the main repo will be delete.

CLI version still available for Bash Lovers :)

### SSL Context
by default CyberSeek listen on `http://127.0.0.1:8080`, if you want to enable ssl protocol you can do the following. 
Modify the `config.ini` file with.
```
[cyberseek]
PERMANENT_SESSION_LIFETIME = 10
INTERFACE = 127.0.0.1
PORT = 8080
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = Lax
WTF_CSRF_SSL_STRICT = True
```
Using nginx for this example you can add the following configuration into `/etc/nginx/sites-enabled/default`
```
server {
    listen 80;
    server_name cyberseek.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cyberseek.example.com;

    ssl_certificate /etc/ssl/certs/cert.crt;
    ssl_certificate_key /etc/ssl/private/private.key;

    # Strong security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Flask app reverse proxy
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

### Dynamic Analysis (files)
CyberSeek now supports dynamic sandbox analysis for URLs and files on various platforms including Windows, Linux, and Android using its integrated filescan sandbox.
<img width="1664" height="958" alt="Screenshot 2025-08-08 at 12 13 10 AM" src="https://github.com/user-attachments/assets/3b65011e-d012-443d-8d92-9983e20e427f" />

### Dynamic Analysis (url)
<img width="1898" height="982" alt="Screenshot 2025-08-14 at 9 00 40 AM" src="https://github.com/user-attachments/assets/b865e443-3083-49c9-90b4-fdfabd0ca3ac" />

### Reputation Lookup (domain/hostname/IP/hash)
<img width="1665" height="953" alt="Screenshot 2025-08-07 at 11 58 04 PM" src="https://github.com/user-attachments/assets/7598f315-a48d-44d8-9ae3-538ad5a5efd6" />

### DNS Information
<img width="1658" height="488" alt="Screenshot 2025-08-07 at 11 47 17 PM" src="https://github.com/user-attachments/assets/4cfd36db-55ac-444c-bc00-9cfe4ced7830" />

### Blacklist check
<img width="1646" height="817" alt="Screenshot 2025-08-07 at 11 56 02 PM" src="https://github.com/user-attachments/assets/ff1d0b48-733b-49f9-8b9f-d2ff65825d4f" />

### SPF Configuration check
<img width="1652" height="767" alt="Screenshot 2025-08-07 at 11 56 59 PM" src="https://github.com/user-attachments/assets/ecb34d06-1718-4fc2-8318-1f2b3a94eee4" />

### Whois Information
<img width="1670" height="966" alt="Screenshot 2025-08-07 at 11 46 59 PM" src="https://github.com/user-attachments/assets/6330d088-79be-4dcb-84e5-1f2b99d24df2" />





