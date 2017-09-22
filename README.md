mkrecon is a bash shell script that launches several tools to pentest a single host.

Tools used are ike-scan joomscan sqlmap whatweb wpscan nikto fimap dirb ldapsearch redis-cli rpcclient smbclient dnsrecon dnsenum netkit-rsh showmount

Packages you will need to install (in Kali): openvas-cli xmlstarlet ncrack exploitdb wfuzz curl ike-scan wget snmpcheck rsh-client bind9-host dnsrecon dnsenum hydra screen eyewitness nmap wpscan whatweb dirb ldap-utils skipfish blindelephant joomscan seclists libwww-mechanize-perl nikto

If you want to use openvas, change the password variable in the openvasScan function.


