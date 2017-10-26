mkrecon is a bash shell script that launches several tools to pentest a single host.

Tools used are nmap openvas ike-scan joomscan sqlmap whatweb wpscan nikto fimap dirb ldapsearch redis-cli rpcclient smbclient dnsrecon dnsenum netkit-rsh showmount ncrack searchsploit mech-dump wfuzz snmp-check skipfish joomscan hydra eyewitness


Packages you will need to install (in Kali): openvas-cli xmlstarlet ncrack exploitdb wfuzz curl ike-scan wget snmpcheck rsh-client bind9-host dnsrecon dnsenum hydra screen eyewitness nmap wpscan whatweb dirb ldap-utils skipfish blindelephant joomscan seclists libwww-mechanize-perl nikto

If you want to use openvas, change the password variable in the openvasScan function.

Usage: ~/mkrecon.sh "IP or host"
Output files are placed in /root/mkrecon/"IP or host"


The mkbash file contains my customized bash environment plus a couple functions:
mkprobe() - Probe the local system for weak configs, passwords, etc.
dumpPackages() - Dump a package list from rpm/dpkg.  Copy back to attack host and run localsearchsploit, which uses searchsploit to find possible vulnerabilities

