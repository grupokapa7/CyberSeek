
Herramienta de OSINT que ayuda con las siguientes actividades:

1.- Búsqueda de IP 
        <li>Reputación de IP (Kaspersky / Fortinet)</li>
        <li>Actividad de malware</li>
        <li>Dominios relacionados con dicha IP</li>
        <li>Puertos abiertos (pasivo)</li>
        <li>Vulnerabilidades (pasivo)</li>
        
2.- Búsqueda de dominio 
        <li>Reputación del Dominio (Kaspersky / Fortinet)</li>
        <li>Actividad de malware</li>
        <li>Enumeración de registros A y subdominios</li>
        <li>Enumeración de correos electrónicos</li>
        <li>Detección de balanceador de carga</li>
        <li>Registros MX, TXT, NS, SOA, A</li>

3.- otros 
        <li>Validación de correos electrónicos (si existe o no)</li>
        <li>Revisión de SPF</li>
        <li>Revisión de IP o Dominio en Blacklist (actividad de spam)</li>

Algunas APIs son necesarias para el funcionamiento de algunos módulos, puede obtenerlo en los siguientes sitios:
<li>Kaspersky= https://opentip.kaspersky.com </li>
<li>Virus Total= https://virustotal.com </li>
<li>VPN API=  https://vpnapi.io/</li>
<li>Real Email= https://isitarealemail.com </li>
<li>Hunter io= https://hunter.io</li>
<li>FindThatLead= https://app.findthatlead.com</li>

Al crear el token en dichos sitios, puede agregarlos en el archivo api.config ejemplo(VirusTotalAPI="<TOKEN>")
