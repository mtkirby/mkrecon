#!/bin/bash
# 20171003 Kirby


umask 077

################################################################################
function MAIN()
{ 
    #set -x
    
    export TARGET=$1 
    export RECONDIR="${HOME}/mkrecon/${TARGET}"
    mkdir -p ${HOME}/mkrecon >/dev/null 2>&1
    cd ${HOME}/mkrecon || exit 1
    if [[ -d "$TARGET" ]]
    then
        # remove old files
        rm -rf "$TARGET" >/dev/null 2>&1
    fi
    
    buildEnv || exit 1
    cd "$RECONDIR" || exit 1
    
    echo "starting openvasScan"
	openvasScan &

    echo "starting snmpScan"
    snmpScan
    
    echo "starting nmapScan"
    nmapScan
    if ! grep -q 'Ports: ' "$RECONDIR"/${TARGET}.ngrep 2>/dev/null
    then
    	echo "FAILED: no ports found"
    	exit 1
    fi
    echo "starting ncrackScan"
    ncrackScan
    
    searchsploit --colour --nmap "$RECONDIR"/${TARGET}.xml >> "$RECONDIR"/${TARGET}.searchsploit 2>&1 &
    
    echo "starting nmapEyeWitness"
    nmapEyeWitness
    
    echo "starting otherNmaps"
    otherNmaps
    
    for rawport in $(egrep 'Ports: ' "$RECONDIR"/${TARGET}.ngrep)
    do  
    	port=${rawport%%/*}
    
    	# web
    	if echo $rawport |grep -v Splunkd |egrep -q '[[:digit:]]+/open/tcp//http'
    	then
    		echo "http://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
    	fi
    	if echo $rawport |grep -v Splunkd |egrep -q '[[:digit:]]+/open/tcp//ssl.http'
        then
    		echo "https://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
    	fi
    
    	# rsh
    	if echo $rawport |egrep -q '^514/open'
    	then
            echo "starting rshBrute"
    		rshBrute &
    	fi
    
        # nfs
        if echo $rawport |egrep -q '/open/tcp//mountd' \
        || echo $rawport |egrep -q '/open/tcp//nfs'
        then
            echo "starting nfsScan"
    		nfsScan &
    	fi
    
    	# dns
        if echo $rawport |egrep -q '53/open/.*//domain'
        then
            echo "starting dnsScan"
    		dnsScan &
    	fi
    
        # ike
        if echo $rawport |egrep -q '[[:digit:]]+/open/udp//isakmp'
        then
            echo "starting ikeScan"
            ikeScan $port 
        fi
    
        # rsync
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//rsync'
        then
            echo "starting rsyncScan"
    		rsyncScan $port 
    	fi
    
        # cifs/smb
        if echo $rawport |egrep -q '445/open/tcp//microsoft-ds' \
        || echo $rawport |egrep -q '445/open/tcp//netbios-ssn'
        then
            echo "starting smbScan"
    		smbScan &
    	fi
    
        # redis
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//redis/'
        then
            echo "starting redisScan"
    		redisScan $port 
    	fi
    
        # ldap
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//ldap/'
        then
            echo "starting ldapScan"
            ldapScan $port
    	fi

        # elasticsearch
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//http//Elasticsearch'
        then
            echo "starting elasticsearchScan"
            elasticsearchScan $port
        fi
    
        # iscsi
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//iscsi'
        then
            echo "starting iscsiScan"
            iscsiScan $port
        fi
    
    done
    
    if [[ -f "$RECONDIR"/${TARGET}.baseurls ]]
    then
        echo "starting skipfishScan"
    	skipfishScan
        echo "starting webDiscover"
    	webDiscover
    fi
    
    if [[ -f "$RECONDIR"/${TARGET}.spider ]]
    then
        echo "starting fuzzURLs"
    	fuzzURLs &
        echo "starting sqlmapScan"
        sqlmapScan &
    fi
    
    if [[ -d "$RECONDIR"/tmp/${TARGET}.dirb ]]
    then
        echo "starting hydraScanURLs"
        hydraScanURLs &
    fi
    
    if [[ -f "$RECONDIR"/${TARGET}.urls ]]
    then
        echo "starting mechDumpURLs"
        mechDumpURLs &
        echo "starting scanURLs"
        scanURLs &
        echo "starting davScanURLs"
        davScanURLs &
        echo "starting exifScanURLs"
        exifScanURLs &
    fi
    
    jobscount=0
    while jobs |grep -q Running
    do
        echo "Jobs are still running.  Waiting $jobscount out of 180"
        jobs -l
        (( jobscount++ ))
        if [[ "$jobscount" -ge 180 ]]
        then
            echo "killing jobs"
            killHangs
            for i in $(jobs -l |awk '{print $2}')
            do
                kill $i
            done
        else
            sleep 60
        fi
    done
    
    if screen -ls |grep -q ".${TARGET}."
    then
        echo "List of detached screens:"
        screen -ls |grep ".${TARGET}."
    fi
    
    
    set +x
}
################################################################################

################################################################################
function joinBy()
{ 
    local IFS="$1"
    shift
    echo "$*"
}
################################################################################

################################################################################
function killHangs()
{
    # sometimes scans will fork and hang
    local scan
    for scan in ike-scan joomscan sqlmap whatweb wpscan nikto fimap dirb ldapsearch redis-cli rpcclient smbclient dnsrecon dnsenum netkit-rsh showmount wget cewl
    do
        pkill -t $TTY -f $scan
    done

    return 0
}
################################################################################

################################################################################
function buildEnv()
{
    local file
    local pkgs="openvas-cli xmlstarlet ncrack exploitdb wfuzz curl ike-scan wget snmpcheck rsh-client bind9-host dnsrecon dnsenum hydra screen eyewitness nmap wpscan whatweb dirb ldap-utils skipfish blindelephant joomscan seclists libwww-mechanize-perl nikto open-iscsi cewl"

    TIMEOUT='timeout --kill-after=10 --foreground'
    local rawtty=$(tty)
    TTY=${rawtty#*/*/}

    DATE=$(date +"%Y%m%d%H%M")

    if [[ "$LOGNAME" != "root" ]]
    then
        echo "FAILED: you must run as root"
        return 1
    fi

    if [[ "$RECONDIR" =~ ^$ ]]
    then
        echo "FAILED: you must define RECONDIR"
        return 1
    fi

    if [[ "$TARGET" =~ ^$ ]]
    then
        echo "FAILED: you must define TARGET"
        return 1
    fi

    if [[ ! -d "$RECONDIR" ]]
    then
        if ! mkdir -p $RECONDIR
        then
            echo "FAILED: unable to create dir $RECONDIR"
            return 1
        fi
    fi

    if ! which omp xmlstarlet ncrack searchsploit mech-dump wfuzz curl ike-scan wget timeout snmp-check netkit-rsh host dnsrecon dnsenum hydra screen eyewitness nmap wpscan whatweb dirb ldapsearch skipfish joomscan iscsiadm cewl >/dev/null 2>&1
    then
        echo "FAILED: missing apps.  Read the script."
        echo "run: apt-get install -y $pkgs"
        return 1
    fi
    
    if ! grep -q kali /etc/os-release
    then
        echo "FAILURE: you should be running this script on kali"
        return 1
    fi

    # make sure we have dictionary files
    for file in /usr/share/seclists/Miscellaneous/wordlist-common-snmp-community-strings.txt \
    /usr/share/nmap/nselib/data/snmpcommunities.lst \
    /usr/share/seclists/Miscellaneous/snmp.txt \
    /usr/share/wordlists/metasploit/sap_default.txt \
    /usr/share/wordlists/metasploit/idrac_default_pass.txt \
    /usr/share/wordlists/metasploit/http_default_pass.txt \
    /usr/share/wordlists/metasploit/http_default_users.txt \
    /usr/share/wordlists/metasploit/tomcat_mgr_default_pass.txt \
    /usr/share/wordlists/metasploit/tomcat_mgr_default_users.txt \
    /usr/share/nmap/nselib/data/vhosts-full.lst \
    /usr/share/dirb/wordlists/common.txt \
    /usr/share/wordlists/metasploit/sap_icm_paths.txt \
    /usr/share/wordlists/metasploit/joomla.txt \
    /usr/share/wordlists/metasploit/http_owa_common.txt \
    /usr/share/wfuzz/wordlist/general/admin-panels.txt
    do
        if [[ ! -f "$file" ]]
        then
            echo "FAILURE: missing file $file"
            echo "run: apt-get install -y pkgs"
            return 1
        fi
    done

    # prep default usernames/passwords
    mkdir -p "$RECONDIR"/tmp >/dev/null 2>&1
    if [[ ! -f "$RECONDIR"/tmp/users.lst ]] \
    || [[ ! -f "$RECONDIR"/tmp/passwds.lst ]]
    then
        rm -f "$RECONDIR"/tmp/users.tmp "$RECONDIR"/tmp/passwds.tmp >/dev/null 2>&1
        #awk '{print $1}' /usr/share/wordlists/metasploit/sap_default.txt >> "$RECONDIR"/tmp/users.tmp 2>/dev/null
        #awk '{print $2}' /usr/share/wordlists/metasploit/sap_default.txt >> "$RECONDIR"/tmp/passwds.tmp 2>/dev/null
        cat /usr/share/wordlists/metasploit/idrac_default_pass.txt >> "$RECONDIR"/tmp/users.tmp 2>/dev/null
        cat /usr/share/wordlists/metasploit/http_default_pass.txt >> "$RECONDIR"/tmp/passwds.tmp 2>/dev/null
        cat /usr/share/wordlists/metasploit/http_default_users.txt >> "$RECONDIR"/tmp/users.tmp 2>/dev/null
        cat /usr/share/wordlists/metasploit/tomcat_mgr_default_pass.txt >> "$RECONDIR"/tmp/passwds.tmp 2>/dev/null
        cat /usr/share/wordlists/metasploit/tomcat_mgr_default_users.txt >> "$RECONDIR"/tmp/users.tmp 2>/dev/null
        cat "$RECONDIR"/tmp/users.tmp |sort -u > "$RECONDIR"/tmp/users.lst
        cat "$RECONDIR"/tmp/users.tmp "$RECONDIR"/tmp/passwds.tmp |sort -u > "$RECONDIR"/tmp/passwds.lst
    fi

    rm -f "$RECONDIR"/tmp/mkrecon.txt >/dev/null 2>&1
    echo '.cvspass' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.Xauthority' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.vnc/passwd' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.lesshst' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.viminfo' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.netrc' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.ssh/id_rsa' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.ssh/id_dsa' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.ssh/id_ecdsa' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.git' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.gitconfig' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.wget-hsts' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.smb/smb.conf' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.dropbox' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.rsyncpw' >> "$RECONDIR"/tmp/mkrecon.txt
    echo '.k5login' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'security.txt' >> "$RECONDIR"/tmp/mkrecon.txt

    if [[ ! -f "$RECONDIR"/tmp/dns.lst ]]
    then
        cat /usr/share/dnsrecon/namelist.txt /usr/share/dnsenum/dns.txt /usr/share/nmap/nselib/data/vhosts-full.lst |sort -u >"$RECONDIR"/tmp/dns.lst 2>/dev/null
    fi

    if echo $TARGET |egrep -q '[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+'
    then
        IP=$TARGET
    else
        IP=$(getent hosts $TARGET|awk '{print $1}' |head -1)
    fi

    if ! echo $IP |egrep -q '[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+'
    then
        echo "FAILED: unable to resolve host $TARGET"
        exit 1
    fi

    return 0
}
################################################################################

################################################################################
function openvasScan()
{
    local password='notMyPassword'
    local targetUuid
    local configUuid
    local taskUuid
    local scanUuid
    local reportCSV
    local reportTXT
    local reportHTML
    local pkg

    if ! omp -u admin -w $password -g >/dev/null 2>&1
    then
        echo "FAILED: UNABLE TO CONNECT TO OPENVAS"
        echo "If you want to use OpenVas, change the password in the openvasScan function"
        return 1
    fi  

    for pkg in nsis rpm alien
    do
        if ! dpkg -s $pkg >/dev/null 2>&1
        then
            echo "installing $pkg for openvas"
            apt-get install -y $pkg >/dev/null 2>&1
        fi
    done


    if ! grep -q max_checks /etc/openvas/openvassd.conf
    then
        echo "max_checks=2" >>/etc/openvas/openvassd.conf
    fi  

    reportCSV=$(omp -u admin -w $password -F |awk '/  CSV Results$/ {print $1}' |head -1)
    reportTXT=$(omp -u admin -w $password -F |awk '/  TXT$/ {print $1}' |head -1)
    reportHTML=$(omp -u admin -w $password -F |awk '/  HTML$/ {print $1}' |head -1)

    configUuid=$(omp -u admin -w $password -g|egrep ' Full and fast$'|awk '{print $1}')

    targetUuid=$(omp -u admin -w $password --pretty-print --xml "<create_target>
          <name>${TARGET}-$RANDOM</name>
          <hosts>${TARGET}</hosts>
          </create_target>" |xmlstarlet sel -t -v /create_target_response/@id)

    if ! taskUuid=$(omp -u admin -w $password -C --config=$configUuid --target=$targetUuid -n ${TARGET}-${DATE})
    then
        echo "FAILED: UNABLE TO CREATE OPENVAS TASK"
        return 1
    fi      

    if ! scanUuid=$(omp -u admin -w $password -S $taskUuid)
    then
        echo "FAILED: UNABLE TO START OPENVAS TASK"
        return 1
    fi      

    while ! omp -u admin -w $password -G $taskUuid 2>/dev/null|grep $taskUuid|grep -q Done
    do  
        sleep 20
    done    

    omp -u admin -w $password --get-report $scanUuid --format $reportCSV >"$RECONDIR"/${TARGET}.openvas.csv 2>&1
    omp -u admin -w $password --get-report $scanUuid --format $reportTXT >"$RECONDIR"/${TARGET}.openvas.txt 2>&1
    omp -u admin -w $password --get-report $scanUuid --format $reportHTML >"$RECONDIR"/${TARGET}.openvas.html 2>&1

    return 0
}
################################################################################

################################################################################
function snmpScan()
{
    # snmp
    # nmap has false negatives on snmp detection.  We'll try communities with snmp-check.
    local community

    for community in $(cat /usr/share/seclists/Miscellaneous/wordlist-common-snmp-community-strings.txt /usr/share/nmap/nselib/data/snmpcommunities.lst /usr/share/seclists/Miscellaneous/snmp.txt |egrep -v '^#'|sort -u 2>/dev/null)
    do
        echo "snmp-check -c $community $IP 2>&1 |egrep -v '^snmp-check |^Copyright |SNMP request timeout' >>\"$RECONDIR\"/tmp/${TARGET}.snmp-check 2>&1" >> "$RECONDIR"/tmp/${TARGET}.snmp-check.sh
    done
    echo "grep -q 'System information' \"$RECONDIR\"/tmp/${TARGET}.snmp-check && mv -f \"$RECONDIR\"/tmp/${TARGET}.snmp-check \"$RECONDIR\"/${TARGET}.snmp-check" >>"$RECONDIR"/tmp/${TARGET}.snmp-check.sh
    chmod 700 "$RECONDIR"/tmp/${TARGET}.snmp-check.sh
    screen -dmS ${TARGET}.snmp-check.$RANDOM $TIMEOUT 3600 "$RECONDIR"/tmp/${TARGET}.snmp-check.sh

    return 0
}
################################################################################


################################################################################
function nmapScan()
{
    # other udp ports: U:111,123,12444,1258,13,13200,1604,161,17185,17555,177,1900,20110,20510,2126,2302,23196,26000,27138,27244,27777,27950,28138,30710,3123,31337,3478,3671,37,3702,3784,389,44818,4569,47808,49160,49161,49162,500,5060,53,5351,5353,5683,623,636,64738,6481,67,69,8611,8612,8767,88,9100,9600 
    nmap --open -T4 -sT -sU -p T:1-65535,U:111,123,161,500,53,67 --script=version -sV --version-all -O -oN "$RECONDIR"/${TARGET}.nmap -oG "$RECONDIR"/${TARGET}.ngrep -oX "$RECONDIR"/${TARGET}.xml $TARGET >/dev/null 2>&1

    return 0
}
################################################################################

################################################################################
function nmapEyeWitness()
{
    if [[ ! -f "$RECONDIR"/${TARGET}.xml ]]
    then
        echo "FAILED: no nmap xml file"
        return 1
    fi
    screen -dmS ${TARGET}.ew.$RANDOM $TIMEOUT 3600 eyewitness -d "$RECONDIR"/${TARGET}.nmapEyeWitness --no-dns --no-prompt --all-protocols -x "$RECONDIR"/${TARGET}.xml

    return 0
}
################################################################################

################################################################################
function otherNmaps()
{
    local a_tcpports=()
    local a_udpports=()
    local a_urls=()
    local port
    local tcppports
    local udpports
    local scanports

    if [[ ! -f "$RECONDIR"/${TARGET}.ngrep ]]
    then
        echo "FAILED TO FIND NGREP FILE"
        return 1
    fi
    for port in $(egrep 'Ports: ' "$RECONDIR"/${TARGET}.ngrep)
    do
        if echo $port |egrep -q '[[:digit:]]+/open/tcp/'
        then
            a_tcpports[${#a_tcpports[@]}]=${port%%/*}
            tcpports="T:$(joinBy , "${a_tcpports[@]}")"
        fi
        if echo $port |egrep -q '[[:digit:]]+/open/udp/'
        then
            a_udpports[${#a_udpports[@]}]=${port%%/*}
            udpports="U:$(joinBy , "${a_udpports[@]}")"
        fi
        scanports=$(joinBy , $tcpports $udpports)
    done

    # run nmap scripts in pairs that have category overlaps
    #screen -dmS ${TARGET}.nmap-authbrute.$RANDOM $TIMEOUT 14400 nmap -T4 -p $scanports --script=auth,brute -oN "$RECONDIR"/${TARGET}.nmap-authbrute $TARGET
    screen -dmS ${TARGET}.nmap-auth.$RANDOM $TIMEOUT 14400 nmap -T4 -p $scanports --script=auth -oN "$RECONDIR"/${TARGET}.nmap-auth $TARGET
    screen -dmS ${TARGET}.nmap-exploitvuln.$RANDOM $TIMEOUT 14400 nmap -T4 -p $scanports --script=exploit,vuln -oN "$RECONDIR"/${TARGET}.nmap-exploitvuln $TARGET
    screen -dmS ${TARGET}.nmap-discoverysafe.$RANDOM $TIMEOUT 14400 nmap -T4 -p $scanports --script=discovery,safe -oN "$RECONDIR"/${TARGET}.nmap-discoverysafe $TARGET

    return 0
}    
################################################################################

################################################################################
function rshBrute()
{
    local login

    for login in adm admin ansible apache apache2 asterisk backup cacti cassandra centos cisco control data database demo ftp guest hadoop jboss jenkins jira kafka linux manager master memcached mysql nagios named nobody operator oracle pi postgres project rabbitmq redhat redis redmine root sales sapadm server share spark squid student superman support sysadm sysadmin sysop teamspeak teamspeak3 tech test tomcat toor ubuntu unbound user user1 vagrant vmware vnc web webadmin webapp weblogic www www-data zabbix
    do
        $TIMEOUT 900 netkit-rsh -l $login $TARGET id -a 2>&1 |grep -v 'Permission denied' >>"$RECONDIR"/${TARGET}.rsh 
    done

    return 0
}
################################################################################

################################################################################
function nfsScan()
{
    local output
    local i

    ( $TIMEOUT 90 showmount -e ${TARGET} >"$RECONDIR"/${TARGET}.showmount-e 2>&1 || rm -f "$RECONDIR"/${TARGET}.showmount-e >/dev/null 2>&1 ) &
    ( $TIMEOUT 90 showmount -a ${TARGET} >"$RECONDIR"/${TARGET}.showmount-a 2>&1 || rm -f "$RECONDIR"/${TARGET}.showmount-a >/dev/null 2>&1 ) &


    # the nfs-ls nse script only works half the time
    for i in {1..10}
    do
        output=$($TIMEOUT 60 nmap -p 111 --script=nfs-ls $TARGET 2>&1)
        if echo $output|grep -q nfs-ls:
        then
            echo "$output" > "$RECONDIR"/${TARGET}.nmap-nfsls
            break
        fi
    done

    return 0
}
################################################################################

################################################################################
function dnsScan()
{
    local domain

    domain=$(host $IP $IP |grep 'domain name pointer' |tail -1 |sed -e 's/.*domain name pointer \(.*\)./\1/'  |sed -e 's/\.$//')
    if [[ "$(echo $domain |grep -o '.' |grep -c '\.')" -ge 3 ]]
    then
        domain=$(host $IP $IP |grep 'domain name pointer' |tail -1 |sed -e 's/.*domain name pointer \(.*\)./\1/'  |sed -e 's/\.$//' |cut -d'.' -f2-)
    fi
    $TIMEOUT 900 dnsrecon -n $TARGET -r ${IP%.*}.0-${IP%.*}.255  >>"$RECONDIR"/${TARGET}.dnsreconptr 2>&1 &
    $TIMEOUT 10800 dnsrecon -n $TARGET -r 192.168.0.0-192.168.255.255  >>"$RECONDIR"/${TARGET}.dnsreconptr.192.168 2>&1 &
    $TIMEOUT 10800 dnsrecon -n $TARGET -r 172.16.0.0-172.31.255.255  >>"$RECONDIR"/${TARGET}.dnsreconptr.172.16 2>&1 &
    $TIMEOUT 10800 dnsrecon -n $TARGET -r 10.0.0.0-10.63.255.255  >>"$RECONDIR"/${TARGET}.dnsreconptr.10.0 2>&1 &
    $TIMEOUT 10800 dnsrecon -n $TARGET -r 10.64.0.0-10.127.255.255  >>"$RECONDIR"/${TARGET}.dnsreconptr.10.64 2>&1 &
    $TIMEOUT 10800 dnsrecon -n $TARGET -r 10.128.0.0-10.191.255.255  >>"$RECONDIR"/${TARGET}.dnsreconptr.10.128 2>&1 &
    $TIMEOUT 10800 dnsrecon -n $TARGET -r 10.192.0.0-10.255.255.255  >>"$RECONDIR"/${TARGET}.dnsreconptr.10.192 2>&1 &
    if [[ $domain =~ ^..* ]]
    then
        $TIMEOUT 90 dnsenum --dnsserver $TARGET -f "$RECONDIR"/tmp/dns.lst --nocolor --enum -p0 $domain >>"$RECONDIR"/${TARGET}.dnsenum 2>&1 &
        $TIMEOUT 90 dnsrecon -d $domain -n $TARGET >>"$RECONDIR"/${TARGET}.dnsrecon 2>&1 &
        $TIMEOUT 90 host -a $domain. $TARGET >>"$RECONDIR"/${TARGET}.host-a 2>&1 &
        $TIMEOUT 90 host -l $domain. $TARGET >>"$RECONDIR"/${TARGET}.host-l 2>&1 &
    fi

    return 0
}
################################################################################

################################################################################
function ikeScan()
{
    local port=$1
    $TIMEOUT 90 ike-scan -d $port $TARGET >>"$RECONDIR"/${TARGET}.ike-scan 2>&1 

    return 0
}
################################################################################

################################################################################
function rsyncScan()
{
    local port=$1
    local share

    $TIMEOUT 90 rsync --list-only --port=$port rsync://$TARGET >>"$RECONDIR"/${TARGET}.rsync 2>&1 || rm -f "$RECONDIR"/${TARGET}.rsync >/dev/null 2>&1
    if [[ -f  "$RECONDIR"/${TARGET}.rsync ]]
    then
        for share in $(cat "$RECONDIR"/${TARGET}.rsync)
        do
            $TIMEOUT 600 rsync --list-only --port=${port%%/*} rsync://$TARGET/$share >>"$RECONDIR"/${TARGET}.rsync-$share 2>&1 
        done
    fi

    return 0
}
################################################################################

################################################################################
function smbScan()
{
    local share
    local cmd

    smbclient -g -N -L $TARGET >"$RECONDIR"/${TARGET}.smbshares 2>&1
    for share in $(egrep '^Disk' "$RECONDIR"/${TARGET}.smbshares |cut -d'|' -f2)
    do
        echo "####################" >>"$RECONDIR"/${TARGET}.smbdirs
        echo "//$TARGET/$share" >>"$RECONDIR"/${TARGET}.smbdirs
        $TIMEOUT 90 smbclient -N -c dir //$TARGET/"$share" >>"$RECONDIR"/${TARGET}.smbdirs 2>&1
        echo "" >>"$RECONDIR"/${TARGET}.smbdirs
        echo "" >>"$RECONDIR"/${TARGET}.smbdirs
    done
    for cmd in srvinfo dsgetdcinfo ntsvcs_getversion wkssvc_wkstagetinfo wkssvc_getjoininformation wkssvc_enumeratecomputernames dfsenum netshareenumall enumdomusers enumdomgroups
    do
        echo "####################" >>"$RECONDIR"/${TARGET}.rpcclient
        echo "cmd: $cmd" >>"$RECONDIR"/${TARGET}.rpcclient
        $TIMEOUT 90 rpcclient -U "" $TARGET -N -c $cmd >>"$RECONDIR"/${TARGET}.rpcclient 2>&1
        echo "" >>"$RECONDIR"/${TARGET}.rpcclient
        echo "" >>"$RECONDIR"/${TARGET}.rpcclient
    done

    return 0
}
################################################################################

################################################################################
function iscsiScan()
{
    local port=$1

    $TIMEOUT 90 iscsiadm -m discovery -t st -p ${TARGET}:${port} >> "$RECONDIR"/${TARGET}.iscsiadm 2>&1

    return 0
}
################################################################################

################################################################################
function elasticsearchScan()
{
    local port=$1

    $TIMEOUT 90 curl -s "http://${TARGET}:${port}/_cat/indices?v" >> "$RECONDIR"/${TARGET}.elasticsearch 2>&1

    return 0
}
################################################################################


################################################################################
function redisScan()
{
    local port=$1
    local i

    for i in {0..16}
    do
        $TIMEOUT 90 redis-cli -h $TARGET -p $port -n $i --scan >> "$RECONDIR"/${TARGET}.redis 2>&1
    done

    return 0
}
################################################################################

################################################################################
function ldapScan()
{
    local port=$1

    $TIMEOUT 90 ldapsearch -h $TARGET -p $port -x -s base >> "$RECONDIR"/${TARGET}.ldap 2>&1

    return 0
}
################################################################################

################################################################################
function webDiscover()
{
    local a_dirbfiles=()
    local a_robots=()
    local a_urls=()
    local dirbfile
    local newurl
    local port
    local robotdir
    local shortfile
    local sslflag
    local url
    local wordlist
    local urlfile


    # Build dirb dictionary array
    #for wordlist in /usr/share/dirb/wordlists/vulns/apache.txt \
    #/usr/share/dirb/wordlists/vulns/sap.txt \
    #/usr/share/dirb/wordlists/vulns/tomcat.txt \
    #/usr/share/wfuzz/wordlist/general/admin-panels.txt \
    #"$RECONDIR"/tmp/mkrecon.txt
    #do
    for wordlist in /usr/share/dirb/wordlists/common.txt \
    /usr/share/dirb/wordlists/vulns/*txt \
    /usr/share/wordlists/metasploit/sap_icm_paths.txt \
    /usr/share/wordlists/metasploit/joomla.txt \
    /usr/share/wordlists/metasploit/http_owa_common.txt \
    /usr/share/wfuzz/wordlist/general/admin-panels.txt \
    "$RECONDIR"/tmp/mkrecon.txt
    do
        if [[ -f "$wordlist" ]]
        then
            a_dirbfiles[${#a_dirbfiles[@]}]=$wordlist
        fi
    done

    # first run through baseurls
    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        # Run nikto in the background
        urlfile=${url//\//,}
        screen -dmS ${TARGET}.nikto.$RANDOM -L -Logfile "$RECONDIR"/${TARGET}.${urlfile}.nikto $TIMEOUT 900 nikto -no404 -host "$url"

        # collect words from websites
        $TIMEOUT 300 wget -rq -O "$RECONDIR"/tmp/wget.dump "$url" >/dev/null 2>&1
        if [[ -f "$RECONDIR"/tmp/wget.dump ]]
        then
            html2dic "$RECONDIR"/tmp/wget.dump 2>/dev/null |sort -u >> "$RECONDIR"/${TARGET}.webwords 
        fi


        echo "##################################################" >>"$RECONDIR"/${TARGET}.robots.txt
        echo "${url}/robots.txt" >>"$RECONDIR"/${TARGET}.robots.txt
        curl -s ${url}/robots.txt >>"$RECONDIR"/${TARGET}.robots.txt 2>&1
        echo "" >>"$RECONDIR"/${TARGET}.robots.txt
        echo "##################################################" >>"$RECONDIR"/${TARGET}.robots.txt

        for robotdir in $(curl -s ${url}/robots.txt 2>&1 |egrep '^Disallow: ' |awk '{print $2}' |sed -e 's/\*//g' |tr -d '\r')
        do
            if [[ ! $robotdir =~ ^/$ ]] \
            && [[ ! $robotdir =~ \? ]] \
            && [[ $robotdir =~ /$ ]] 
            then
                a_robots[${#a_robots[@]}]="${url}${robotdir}"
            fi
            $TIMEOUT 60 wget --no-check-certificate -r -l3 --spider ${url}${robotdir} 2>&1 | grep '^--' |grep -v '(try:' | awk '{ print $3 }' >> "$RECONDIR"/tmp/${TARGET}.robotspider.raw 2>/dev/null
        done

        $TIMEOUT 60 wget --no-check-certificate -r -l3 --spider --force-html -D $TARGET "$url" 2>&1 | grep '^--' |grep -v '(try:' | awk '{ print $3 }' |grep $TARGET  >> "$RECONDIR"/tmp/${TARGET}.spider.raw 2>/dev/null

        cat "$RECONDIR"/tmp/${TARGET}.spider.raw "$RECONDIR"/tmp/${TARGET}.robotspider.raw 2>/dev/null |egrep -vi '\.(css|js|png|gif|jpg|gz|ico)$' |sort -u > "$RECONDIR"/${TARGET}.spider
    done

    # combine all the words from the wget spider
    if [[ -f "$RECONDIR"/tmp/${TARGET}.webwords ]]
    then
        sort -u "$RECONDIR"/tmp/${TARGET}.webwords > "$RECONDIR"/${TARGET}.webwords 2>/dev/null
    fi

    # second run through baseurls.  dirb may take hours
    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        # do not put all txt files on dirb cmdline cuz it truncates it's args
        # instead iterate over an array
        mkdir -p "$RECONDIR"/tmp/${TARGET}.dirb >/dev/null 2>&1
        for dirbfile in ${a_dirbfiles[@]}
        do
            shortfile=${dirbfile##*/}
            $TIMEOUT 1800 dirb "$url" "$dirbfile" -r -f -S >> "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-${shortfile}.dirb 2>&1
        done
    done

    # run dirb on everything robots.txt tells us to ignore
    for url in ${a_robots[@]}
    do
        for dirbfile in ${a_dirbfiles[@]}
        do
            shortfile=${dirbfile##*/}
            # check if dirb was already run on this url
            if ! grep -q "$url" "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-${shortfile}.dirb 2>/dev/null
            then
                $TIMEOUT 1800 dirb "$url" "$dirbfile" -r -f -S >> "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-robots-${shortfile}.dirb 2>&1
            fi
        done
    done

    for url in $(cat "$RECONDIR"/tmp/${TARGET}.robotspider.raw 2>/dev/null|sort -u)
    do
        echo "<a href=\"$url\">$url</a><br>" >> "$RECONDIR"/${TARGET}.robotspider.html
    done

    for url in $(grep CODE:200 "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-*.dirb |grep -v SIZE:0 |awk '{print $2}' |sort -u)
    do
        echo "${url%\?*}" >> "$RECONDIR"/tmp/${TARGET}.dirburls.raw
    done

    for url in $(grep '==> DIRECTORY: ' "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-*.dirb |awk '{print $3}' |sort -u)
    do
        echo "${url%\?*}" >> "$RECONDIR"/tmp/${TARGET}.dirburls.raw
    done

    cat "$RECONDIR"/tmp/${TARGET}.dirburls.raw |sed -e 's/\/\/*$/\//g'|sed -e 's/\/\.\/*$/\//g' |sed -e 's/\/\%2e\/*$/\//g' |sort -u > "$RECONDIR"/${TARGET}.dirburls

    for url in $(cat "$RECONDIR"/${TARGET}.dirburls)
    do
        $TIMEOUT 120 wget --no-check-certificate -r -l2 --spider --force-html -D $TARGET "$url" 2>&1 | grep '^--' |grep -v '(try:' |egrep "$IP|$TARGET" | awk '{ print $3 }' >> "$RECONDIR"/tmp/${TARGET}.spider.raw 2>/dev/null
        # sometimes timeout command forks badly on exit
        pkill -t $TTY -f wget
    done

    mkdir -p "$RECONDIR"/tmp/cewl >/dev/null 2>&1
    egrep -vi '\.(css|js|png|gif|jpg|gz|ico)$' "$RECONDIR"/tmp/${TARGET}.spider.raw |sort -u > "$RECONDIR"/${TARGET}.spider
    for url in $(cat "$RECONDIR"/${TARGET}.spider|sort -u)
    do
        urlfile=${url//\//,}
		$TIMEOUT 10 cewl -d 1 -a --meta_file "$RECONDIR"/tmp/cewl/${TARGET}.${urlfile}.cewlmeta -e --email_file "$RECONDIR"/tmp/cewl/${TARGET}.${urlfile}.cewlemail -w "$RECONDIR"/tmp/cewl/${TARGET}.${urlfile}.cewl "$url" >/dev/null 2>&1 
        echo "<a href=\"$url\">$url</a><br>" >> "$RECONDIR"/${TARGET}.spider.html
    done
    cat "$RECONDIR"/tmp/cewl/${TARGET}.*.cewl |sort -u > "$RECONDIR"/${TARGET}.cewl
    cat "$RECONDIR"/tmp/cewl/${TARGET}.*.cewlemail |sort -u > "$RECONDIR"/${TARGET}.cewlemail
    cat "$RECONDIR"/tmp/cewl/${TARGET}.*.cewlmeta |sort -u > "$RECONDIR"/${TARGET}.cewlmeta

    cat "$RECONDIR"/${TARGET}.dirburls "$RECONDIR"/${TARGET}.spider 2>/dev/null |egrep -vi '\.(css|js|png|gif|jpg|gz|ico)$' |cut -d'?' -f1|cut -d'%' -f1|cut -d'"' -f1 |sort -u > /tmp/${TARGET}.urls.raw

    # remove duplicates that have standard ports.  e.g. http://target:80/dir -> http://target/dir
    for url in $(cat /tmp/${TARGET}.urls.raw)
    do
        if echo $url|grep ':80/' |egrep -q '^http://'
        then 
            newurl=$(echo $url|sed -e 's/:80//')
        elif echo $url|grep ':443/' |egrep -q '^https://'
        then
            newurl=$(echo $url|sed -e 's/:443//')
        else 
            newurl=$url
        fi
        echo $newurl >> /tmp/${TARGET}.urls.stripped
    done
    cat /tmp/${TARGET}.urls.stripped|sort -u > "$RECONDIR"/${TARGET}.urls 
    rm -f /tmp/${TARGET}.urls.stripped >/dev/null 2>&1
    rm -f /tmp/${TARGET}.urls.raw >/dev/null 2>&1

    for url in $(cat "$RECONDIR"/${TARGET}.urls)
    do 
        echo "<a href=\"$url\">$url</a><br>" >> "$RECONDIR"/${TARGET}.urls.html
    done

    for url in $(cat "$RECONDIR"/${TARGET}.urls)
    do 
        echo "##################################################" >> "$RECONDIR"/${TARGET}.headers 2>&1
        echo "$url" >> "$RECONDIR"/${TARGET}.headers
        $TIMEOUT 20 wget -O /dev/null --no-check-certificate -S --method=OPTIONS "$url" >> "$RECONDIR"/${TARGET}.headers 2>&1
    done


    return 0
}
################################################################################

################################################################################
function skipfishScan()
{
    local a_urls=()

    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        a_urls[${#a_urls[@]}]="$url"
    done
    screen -dmS ${TARGET}.skipfish.$RANDOM skipfish -k 0:30:00 -g2 -f20 -o "$RECONDIR"/${TARGET}.skipfish ${a_urls[*]}
    return 0
}
################################################################################

################################################################################
function hydraScanURLs()
{
    local path
    local hydrafile
    local sslflag
    local url
    local port

    for url in $(grep CODE:401 "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-*.dirb |awk '{print $2}'|sed -e 's/\/*$/\//g'|sort -u)
    do
        echo "${url%\?*}" >> "$RECONDIR"/${TARGET}.dirburls.401
    done

    if [[ ! -f "$RECONDIR"/${TARGET}.dirburls.401 ]]
    then
        return 0
    fi

    # hydra
    for url in $(cat "$RECONDIR"/${TARGET}.dirburls.401)
    do
        if [[ "$url" =~ ^https ]]
        then
            sslflag="-S"
        else
            sslflag=""
        fi
        port=$(getPortFromUrl "$url")
        path=/${url#*//*/}
        hydrafile=${url//\//,}.hydra
        mkdir -p "$RECONDIR"/${TARGET}.hydra >/dev/null 2>&1
        $TIMEOUT 600 hydra -I -L "$RECONDIR"/tmp/users.lst -P "$RECONDIR"/tmp/passwds.lst -e nsr -u -f -t 5 $sslflag -s $port $TARGET http-get "$path" >> "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>&1
        grep -q 'valid pair found' "$RECONDIR"/${TARGET}.hydra/${hydrafile} || rm -f "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>/dev/null
    done
    rmdir "$RECONDIR"/${TARGET}.hydra >/dev/null 2>&1

    return 0
}
################################################################################


################################################################################
function sqlmapScan()
{
    local url

    for url in $(grep '?' "$RECONDIR"/${TARGET}.spider |egrep -v '/\?' |cut -d'?' -f1 |sort -u 2>/dev/null)
    do
        $TIMEOUT 300 sqlmap --random-agent --batch --flush-session -a -u "$url" 2>&1 |egrep -v '\[INFO\] (testing|checking|target|flushing|heuristics|confirming|searching|dynamic|URI parameter)|\[WARNING\]|\[CRITICAL\]|shutting down|starting at|do you want to try|legal disclaimer:|404 \(Not Found\)|how do you want to proceed|it is not recommended|do you want sqlmap to try|^\|_|^ ___|^      \||^       __H|^        ___|fetched random HTTP User-Agent|there was an error checking|Do you want to follow|Do you want to try|Method Not Allowed'|uniq >> "$RECONDIR"/${TARGET}.sqlmap 2>&1
    done

    return 0
}

################################################################################
function fuzzURLs()
{
    local wfuzzfile
    local url
    local file
    local ignore
    local filename

    mkdir -p "$RECONDIR"/${TARGET}.wfuzz/raws >/dev/null 2>&1
    grep '?' "$RECONDIR"/${TARGET}.spider |egrep -v '/\?' |sed -e 's/\(\?[^=]*\)=[^&]*/\1=FUZZ/g' |sed -e 's/\(\&[^=]*\)=[^&]*/\1=FUZZ/g' |sed -e 's/\?$/\?FUZZ/'|sort -u 2>/dev/null > "$RECONDIR"/tmp/${TARGET}.spider.FUZZ
    for url in $(cat "$RECONDIR"/tmp/${TARGET}.spider.FUZZ)
    do
        wfuzzfile=${url//\//,}
        $TIMEOUT 60 wfuzz --hc 404 -w /usr/share/wfuzz/wordlist/vulns/sql_inj.txt "$url" >> "$RECONDIR"/${TARGET}.wfuzz/raws/${wfuzzfile}.sql.wfuzz.raw 2>&1
        $TIMEOUT 60 wfuzz --hc 404 -w /usr/share/wfuzz/wordlist/vulns/dirTraversal-nix.txt "$url" >> "$RECONDIR"/${TARGET}.wfuzz/raws/${wfuzzfile}.dtnix.wfuzz.raw 2>&1
        $TIMEOUT 60 wfuzz --hc 404 -w /usr/share/wfuzz/wordlist/vulns/dirTraversal-win.txt "$url" >> "$RECONDIR"/${TARGET}.wfuzz/raws/${wfuzzfile}.dtwin.wfuzz.raw 2>&1
        # sometimes timeout command forks badly on exit
        pkill -t $TTY -f wfuzz

        for file in "$RECONDIR"/${TARGET}.wfuzz/raws/${wfuzzfile}.*.wfuzz.raw
        do
            ignore=$(cat "$file" |grep 'C=' |awk '{print $3" "$4}'|sort -u -c |sort -k1 -n|tail -1|awk '{print $2" "$3}')
            filename=${file##*/}
            cat $file |egrep -v "$ignore|^\.\.\.\"" >> "$RECONDIR"/${TARGET}.wfuzz/${filename%%.raw} 2>&1
            egrep -q "^ID" "$RECONDIR"/${TARGET}.wfuzz/${filename%%.raw} || rm -f "$RECONDIR"/${TARGET}.wfuzz/${filename%%.raw} 
        done
    done

    return 0
}
################################################################################

################################################################################
function mechDumpURLs()
{
    local url
    local output

    for url in $(cat "$RECONDIR"/${TARGET}.urls |egrep -v '/./$|/../$' |egrep -v '/\?')
    do
        #mech-dump --all --text "$url" >> "$RECONDIR"/${TARGET}.mech-dump 2>/dev/null
        output=$($TIMEOUT 60 mech-dump --absolute --forms "$url" 2>/dev/null)
        if [[ ${#output} -gt 0 ]]
        then
            echo "################################################################################" >> "$RECONDIR"/${TARGET}.mech-dump
            echo "URL: $url" >> "$RECONDIR"/${TARGET}.mech-dump
            echo "$output" >> "$RECONDIR"/${TARGET}.mech-dump
        fi
        # sometimes timeout command forks badly on exit
        pkill -t $TTY -f mech-dump
    done

    return 0
}

################################################################################

################################################################################
function davScanURLs()
{
    local url
    local port
    local output

    for url in $(cat "$RECONDIR"/${TARGET}.urls |sed -e 's|\(^.*://.*/\).*|\1|'|egrep -v '/.*/./$|/.*/../$'|sort-u )
    do
        # try multiple DAV scans.  None of these are 100% reliable, so try several.
        $TIMEOUT 90 davtest -cleanup -url "$url" 2>&1|grep SUCCEED >> "$RECONDIR"/${TARGET}.davtest

        echo ls | $TIMEOUT 10 cadaver "$url" 2>&1 |egrep -v 'command can only be used when connected to the server.|^Try running|^Could not access|^405 Method|^Connection to' >> "$RECONDIR"/${TARGET}.cadaver

        port=$(getPortFromUrl "$url")
        output=$($TIMEOUT 90 nmap -p $port -Pn --script http-webdav-scan --script-args "http-webdav-scan.path=/${url#*/*/*/}" ${TARGET} 2>&1 )
        if echo $output |grep -q http-webdav-scan:
        then
            echo "$output" >>"$RECONDIR"/${TARGET}.nmap-webdav
        fi
    done
    grep -q SUCCEED "$RECONDIR"/${TARGET}.davtest 2>/dev/null || rm -f "$RECONDIR"/${TARGET}.davtest >/dev/null 2>&1
    grep -q succeeded "$RECONDIR"/${TARGET}.cadaver 2>/dev/null || rm -f "$RECONDIR"/${TARGET}.cadaver >/dev/null 2>&1

    return 0
}
################################################################################

################################################################################
function exifScanURLs()
{
    local url
    local port
    local output

    for url in $(cat "$RECONDIR"/${TARGET}.urls |egrep -v '/./$|/../$' |sed -e 's|\(^.*://.*/\).*|\1|'|sort -u)
    do
        port=$(getPortFromUrl "$url")
        output=$($TIMEOUT 60 nmap -T4 -p $port --script=http-exif-spider --script-args "http-exif-spider.url=/${url#*/*/*/}" $TARGET 2>&1)
        if echo $output |grep -q http-exif-spider:
        then
            echo "$output" >> ${TARGET}.nmap-http-exif-spider
        fi
    done

    return 0
}
################################################################################

################################################################################
function getPortFromUrl()
{
    local url=$1
    local port

    port=$(echo $url|sed -e 's/.*:\([[:digit:]]*\)\/.*/\1/')
    if ! echo $port |egrep -q "^[[:digit:]]+$"
    then
        if echo $url |grep -q "^https"
        then
            port=443
        else
            port=80
        fi
    fi

    echo $port
}
################################################################################
function scanURLs()
{
    local url

    screen -dmS ${TARGET}.urlsew.$RANDOM $TIMEOUT 7200 eyewitness -d "$RECONDIR"/${TARGET}.urlsEyeWitness --no-dns --no-prompt --all-protocols -f "$RECONDIR"/${TARGET}.urls

    # run whatweb on top dirs
    for url in $(egrep '/$' "$RECONDIR"/${TARGET}.urls |egrep -v '/./$|/../$')
    do
        if [[ "$(echo $url |grep -o '.' |grep -c '/')" -le 4 ]]
        then
            egrep -q "^$url" "$RECONDIR"/${TARGET}.whatweb 2>/dev/null || $TIMEOUT 300 whatweb -a3 --color=never "$url" >> "$RECONDIR"/${TARGET}.whatweb 2>/dev/null
        fi
    done

    # run wpscan on first found wordpress
    for url in $(grep -i wordpress "$RECONDIR"/${TARGET}.whatweb 2>/dev/null |head -1 |awk '{print $1}')
    do
        $TIMEOUT 900 wpscan -t 10 --follow-redirection --disable-tls-checks -e --no-banner --no-color --batch --url "$url" > "$RECONDIR"/${TARGET}.wpscan 2>&1 &
    done

    # run joomscan on first found joomla
    for url in $(grep -i joomla "$RECONDIR"/${TARGET}.whatweb 2>/dev/null |head -1 |awk '{print $1}')
    do
        $TIMEOUT 900 joomscan -pe -u "$url" > "$RECONDIR"/${TARGET}.joomscan 2>&1 &
    done

    # run fimap on anything with php
    for url in $(egrep -i '\.php$' "$RECONDIR"/${TARGET}.urls |awk '{print $1}')
    do
        $TIMEOUT 300 fimap --force-run -4 -u "$url" 2>&1 |egrep -v '^fimap |^Another fimap|^:: |^Starting harvester|^No links found|^AutoAwesome is done' >> "$RECONDIR"/${TARGET}.fimap
    done

    return 0
}
################################################################################

################################################################################
function ncrackScan()
{
    screen -dmS ${TARGET}.ncrack.$RANDOM -L -Logfile "$RECONDIR"/${TARGET}.ncrack $TIMEOUT 7200 ncrack -iX "$RECONDIR"/${TARGET}.xml -U "$RECONDIR"/tmp/users.lst -P "$RECONDIR"/tmp/passwds.lst -v -g CL=3,cr=3,to=2h

    return 0
}
################################################################################

MAIN $*
stty sane >/dev/null 2>&1

