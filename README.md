
Herramienta de OSINT que ayuda con las siguientes actividades:

1.- Búsqueda de IP
        Reputación de IP (Kaspersky / Fortinet)
        Actividad de malware
        Dominios relacionados con dicha IP
        Puertos abiertos (pasivo)
        Vulnerabilidades (pasivo)
        
2.- Búsqueda de dominio
        Reputación del Dominio (Kaspersky / Fortinet)
        Actividad de malware
        Enumeración de registros A y subdominios
        Enumeración de correos electrónicos
        Detección de balanceador de carga
        Registros MX, TXT, NS, SOA, A

3.- otros
        Validación de correos electrónicos (si existe o no)
        Revisión de SPF
        Revisión de IP o Dominio en Blacklist (actividad de spam)

Algunas APIs son necesarias para el funcionamiento de algunos módulos, puede obtenerlo en los siguientes sitios:
Kaspersky= https://opentip.kaspersky.com 
Virus Total= https://virustotal.com 
VPN API=  https://vpnapi.io/
Real Email= https://isitarealemail.com 
Hunter io= https://hunter.io
FindThatLead= https://app.findthatlead.com

Al crear el token en dichos sitios, puede agregarlos en el archivo api.config ejemplo(VirusTotalAPI="<TOKEN>")
