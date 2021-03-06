mkrecon is a bash shell script that launches several tools to pentest a single host.

The latest, and freshly patched, version of Kali is required.

Packages you will need to install (in Kali): alien arachni bind9-host blindelephant brutespray cewl curl dirb dnsenum dnsrecon dos2unix exif exploitdb eyewitness git hsqldb-utils hydra ike-scan iproute2 john joomscan jq kafkacat ldap-utils libgmp-dev libnet-whois-ip-perl libxml2-utils libwww-mechanize-perl libpostgresql-jdbc-java libmysql-java libjt400-java libjtds-java libderby-java libghc-hdbc-dev libhsqldb-java mariadb-common metasploit-framework ncat ncrack nikto nmap nmap-common nsis open-iscsi openvas-cli postgresql-client-common python-pip routersploit rpcbind rpm rsh-client ruby screen seclists skipfish sqlline snmpcheck time tnscmd10g unzip wapiti wfuzz wget whatweb wig wordlists wpscan xmlstarlet zaproxy

If you want to use OpenVAS, change the password variable in the openvasScan function.

If you want to attack Oracle databases, you will need to install the Oracle InstantClient libraries.
- Goto http://www.oracle.com/technetwork/database/database-technologies/instant-client/downloads/index.html
- Select  Instant Client for Linux
- Get the latest instantclient-basic&jdbc&sqlplus&sdk-linux.*.zips
- Put all zip files in /tmp
- mkrecon.sh will auto-install/setup the app when it sees it in /tmp

Usage: ~/mkrecon.sh "IP or hostname"

Output files are placed in /root/mkrecon/"IP|hostname"

################################################################################

WHAT MKRECON DOES
- starts with an nmap scan(with version-detection scripts)
- runs nmap discovery, safe, exploit, vuln, and auth nse scripts
- tries a dictionary attack against snmp
- OpenVAS scan (if you have it configured)
- ncrack and brutespray on auth services found during nmap scan
- hydra on ftp, telnet, ssh, mssql, mysql, smb, postgres, vnc on whatever port(s) they are on
- try leaked ssh private keys on all ports running ssh
- dirb with multiple dictionaries on all web service ports
- spider the discovered dirb urls
- hydra on discovered web directories that require auth (code 401)
- For any webservice discovered on any port: arachni, whatweb, Joomscan, WPScan, clusterd, droopescan, fimap, WAScan, nikto, wafw00f, wapiti, wig, ZAP, sqlmap, skipfish, cewl, davtest, cadaver, exif, and metasploit http modules
- eyewitness (screenshots) of the discovered web pages
- routersploit on discovered telnet, ssh, ftp, web services
- mech-dump of pages with parameters
- wfuzz on parameters discovered by mech-dump using multiple dictionaries including login pages
- wfuzz script will remove most common detected number of lines/chars so that only anomalous data is shown
- discover kafka and pull records
- discover redis and pull records
- discover zookeeper and pull records
- discover mesos and pull records
- discover mongodb and pull records.  Crack password hashes with rockyou dictionary.
- show nfs shares and content
- show rsync shares and content
- show smb shares and content
- show elasticsearch indexes and content
- show docker info
- try simple postgres auth and pull users/password hashes
- try simple mysql auth and pull users/password hashes
- show iscsi info
- retrieve ike keys and try to crack them with rockyou dictionary.
- retrieve ipmi password hashes and try to crack them with rockyou dictionary.
- show LDAP info
- show Memcached info
- show RabbitMQ info
- show Cassandra info
- show Java JMX info
- discover IP cameras
- try to retrieve Java RMI data
- run HP metasploit modules if HP discovered
- run SAP metasploit modules if SAP discovered
- run Juniper metasploit modules if Juniper discovered
- run Cisco metasploit modules if Cisco discovered
- dictionary attack Oracle DB sids
- pull all RFC1918 PTR records if target is running DNS.  Checks for zone records first for speed.
- pull dns srv, mx, txt, etc records for domain


################################################################################

The mkbash file contains my customized bash environment plus a couple functions:

mkprobe() - Probe the local system for weak configs, passwords, etc.

dumpPackages() - Dump a package list from rpm/dpkg.  Copy back to attack host and run localsearchsploit, which uses searchsploit to find possible vulnerabilities
