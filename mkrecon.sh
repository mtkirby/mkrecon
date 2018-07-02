#!/bin/bash
# https://github.com/mtkirby/mkrecon
# version 20180702

umask 077

################################################################################
function MAIN()
{ 
    #set -x

    local ciscoflag=0
    local d
    local fields
    local FTPPORTS=()
    local hpflag=0
    local job
    local jobscount
    local juniperflag=0
    local line
    local HTTPPORTS=()
    local HTTPSPORTS=()
    local NONSSLPORTS=()
    local owner
    local port
    local portinfo=()
    local proto
    local protocol
    local rawport
    local rmiflag=0
    local RMIPORTS=()
    local rpc_info
    local sapflag=0
    local service
    local sshflag=0
    local ssl
    local SSHPORTS=()
    local SSLPORTS=()
    local sstitle
    local state
    local TCPPORTS=()
    local TELNETPORTS=()
    local UDPPORTS=()
    local version
    
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
    echo "... outputs $RECONDIR/${TARGET}.nmap.snmp-brute"
    echo "... outputs $RECONDIR/${TARGET}.snmp-check if anything found"
    snmpScan &
    
    echo "starting domainNameScan"
    echo "... outputs $RECONDIR/${TARGET}.dnsinfo"
    domainNameScan &

    echo "starting nmapScan"
    echo "... outputs $RECONDIR/${TARGET}.nmap"
    echo "... outputs $RECONDIR/${TARGET}.ngrep"
    echo "... outputs $RECONDIR/${TARGET}.xml"
    nmapScan
    if ! egrep -q 'Ports: .*/open/' "$RECONDIR"/${TARGET}.ngrep 2>/dev/null
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
    searchsploit --colour --nmap "$RECONDIR"/${TARGET}.xml >> "$RECONDIR"/${TARGET}.searchsploit 2>&1 
    
    echo "starting basicEyeWitness"
    echo "... outputs $RECONDIR/${TARGET}.basicEyeWitness"
    basicEyeWitness &
    
    echo "examining open ports"
    echo "... outputs $RECONDIR/${TARGET}.baseurls"
    echo "... outputs $RECONDIR/${TARGET}.port.certificate"
    IFS=$'\n'
    for line in $(egrep '\sPorts:\s' "$RECONDIR"/${TARGET}.ngrep |sed -e 's/.*Ports: //')
    do
        IFS=','
        for fields in $line
        do
            portinfo=()
            IFS='/'
            for d in $fields
            do
                portinfo[${#portinfo[@]}]="$d"
            done
            IFS=$'\n'
            port="${portinfo[0]// /}"
            state=${portinfo[1]}
            protocol=${portinfo[2]}
            owner=${portinfo[3]}
            service=${portinfo[4]}
            rpc_info=${portinfo[5]}
            version=${portinfo[6]}

            if [[ $state =~ filtered ]]
            then
                continue
            fi

            if [[ $version =~ ^[A-Za-z]... ]] \
            && ! grep -q "SEARCHING FOR $version" "$RECONDIR"/${TARGET}.searchsploit
            then
                sstitle=${version%% *}
                sstitle=${sstitle%%/*}
                echo "$BORDER" >> "$RECONDIR"/${TARGET}.searchsploit 
                echo "SEARCHING FOR $version" >> "$RECONDIR"/${TARGET}.searchsploit
                searchsploit --colour -t "$sstitle" >> "$RECONDIR"/${TARGET}.searchsploit 2>&1 
                echo "$BORDER" >> "$RECONDIR"/${TARGET}.searchsploit 
            fi

            if [[ $version =~ Splunkd ]]
            then
                continue
            fi

            if [[ $protocol == 'tcp' ]] 
            then
                TCPPORTS[${#TCPPORTS[@]}]=$port
            fi

            if [[ $protocol == 'tcp' ]] \
            && [[ $service =~ ssl ]]
            then
                SSLPORTS[${#SSLPORTS[@]}]=$port
            else
                NONSSLPORTS[${#NONSSLPORTS[@]}]=$port
            fi

            if [[ $protocol == 'udp' ]] 
            then
                UDPPORTS[${#UDPPORTS[@]}]=$port
            fi

            echo "examining port $port"

            if [[ $service =~ cisco ]] \
            || [[ $version =~ cisco ]] 
            then
                ciscoflag=1
            fi
        
            if [[ $service =~ juniper ]] \
            || [[ $version =~ juniper ]] 
            then
                juniperflag=1
            fi
        
            if [[ $version =~ HP.System ]]
            then
                hpflag=1
            fi
        
            # web
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'http' ]]
            then
                echo "http://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
                if portcheck $port ${HTTPPORTS[@]}
                then
                    HTTPPORTS[${#HTTPPORTS[@]}]=$port
                fi
            fi
            if [[ $protocol == 'tcp' ]] \
            && [[ $service =~ ssl.http ]]
            then
                echo "https://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
                if portcheck $port ${HTTPSPORTS[@]}
                then
                    HTTPSPORTS[${#HTTPSPORTS[@]}]=$port
                fi
            fi
    
            # sometimes nmap can't identify a web service, so just try anyways
            if [[ $protocol == 'tcp' ]] \
            && echo "... testing $port for http with wget" \
            && timeout --kill-after=10 --foreground 90 \
                wget -U "$USERAGENT" --tries=3 --retry-connrefused -O /dev/null --no-check-certificate \
                    -S -D $TARGET --method=HEAD http://${TARGET}:${port} 2>&1 \
                    |egrep -qi 'HTTP/|X-|Content|Date' \
            && ! grep -q "http://${TARGET}:${port}" "$RECONDIR"/${TARGET}.baseurls >/dev/null 2>&1
            then
                echo "http://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
                if portcheck $port ${HTTPPORTS[@]}
                then
                    HTTPPORTS[${#HTTPPORTS[@]}]=$port
                fi
            fi
            if [[ $protocol == 'tcp' ]] \
            && echo "... testing $port for https with wget" \
            && timeout --kill-after=10 --foreground 90 \
                wget -U "$USERAGENT" --tries=3 --retry-connrefused -O /dev/null --no-check-certificate \
                    -S  -D $TARGET  --method=HEAD https://${TARGET}:${port} 2>&1 \
                    |egrep -qi 'HTTP/|X-|Content|Date' \
            && ! grep -q "https://${TARGET}:${port}" "$RECONDIR"/${TARGET}.baseurls >/dev/null 2>&1
            then
                echo "https://${TARGET}:${port}" >> "$RECONDIR"/${TARGET}.baseurls
                if portcheck $port ${HTTPSPORTS[@]}
                then
                    HTTPSPORTS[${#HTTPSPORTS[@]}]=$port
                fi
            fi
    
            # check for SSL/TLS
            if [[ $protocol == 'tcp' ]] \
            && echo "... testing $port for ssl/tls with openssl" \
            && echo quit|timeout --kill-after=10 --foreground 30 \
                openssl s_client -showcerts -connect ${TARGET}:${port} 2>/dev/null \
                |grep -q CERTIFICATE 
            then
                echo quit|timeout --kill-after=10 --foreground 30 \
                    openssl s_client -showcerts -connect ${TARGET}:${port} \
                    > "$RECONDIR"/${TARGET}.${port}.certificate 2>&1
                ssl=1
                proto="https"
            else
                ssl=0
                proto="http"
            fi
    
            # ftp
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'ftp' ]]
            then
                FTPPORTS[${#FTPPORTS[@]}]=$port
                echo "starting doHydra $port ftp"
                echo "... outputs $RECONDIR/${TARGET}.ftp.$port.hydra"
                doHydra $port ftp &
            fi
        
            # telnet
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'telnet' ]]
            then
                TELNETPORTS[${#TELNETPORTS[@]}]=$port
                echo "starting doHydra $port telnet"
                echo "... outputs $RECONDIR/${TARGET}.telnet.$port.hydra"
                doHydra $port telnet &
            fi
        
            # ssh
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'ssh' ]]
            then
                SSHPORTS[${#SSHPORTS[@]}]=$port
                echo "starting doHydra $port ssh"
                echo "... outputs $RECONDIR/${TARGET}.ssh.$port.hydra"
                doHydra $port ssh &
                sshflag=1
            fi
        
            # mssql
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'ms-sql' ]]
            then
                echo "starting doHydra $port mssql"
                echo "... outputs $RECONDIR/${TARGET}.mssql.$port.hydra"
                doHydra $port mssql &
            fi
        
            # mysql
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'mysql' ]]
            then
                echo "starting doHydra $port mysql"
                echo "... outputs $RECONDIR/${TARGET}.mysql.$port.hydra"
                doHydra $port mysql &

                echo "starting mysqlScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.mysql.$port"
                mysqlScan $port &
            fi
        
            # oracle
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'oracle-tns' ]]
            then
                echo "starting tnscmd10g on oracle $port"
                echo "... outputs $RECONDIR/${TARGET}.oracle.tnscmd10g.\$port"
                tnscmd10gScan $port &

                echo "starting oracleScan $port"
                echo "... outputs $RECONDIR/${TARGET}.oracle.$port.hydra"
                #echo "... outputs $RECONDIR/${TARGET}.nmap-oracle-brute.\$sid"
                oracleScan $port &
            fi
    
            # vnc
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'vnc' ]]
            then
                echo "starting passHydra $port vnc"
                echo "... outputs $RECONDIR/${TARGET}.vnc.$port.hydra"
                passHydra $port vnc /usr/share/seclists/Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt &
            fi
    
            # rsh
            if [[ $port == '514' ]] \
            && [[ $protocol == 'tcp' ]] 
            then
                echo "starting rshBrute"
                echo "... outputs $RECONDIR/${TARGET}.rsh"
                rshBrute &
            fi
        
            # kafka
            if [[ $protocol == 'tcp' ]]
            then
                # nmap cannot yet identify the kafka service, so test anything tcp
                echo "... testing $port for kafka"

                if kafkacat -b $TARGET:$port -L >/dev/null 2>&1
                then
                    echo "starting kafkaScan for port $port"
                    echo "... outputs $RECONDIR/${TARGET}.${port}.kafkacat"
                    echo "... outputs $RECONDIR/${TARGET}.${port}.\$topic.kafkacat"
                    kafkaScan $port &
                fi
            fi

    
            # nfs
            if [[ $protocol == 'tcp' ]] \
            && [[ $service =~ mountd || $service =~ nfs ]] 
            then
                echo "starting nfsScan"
                echo "... outputs $RECONDIR/${TARGET}.showmount-e if anything found"
                echo "... outputs $RECONDIR/${TARGET}.showmount-a if anything found"
                echo "... outputs $RECONDIR/${TARGET}.nfsls if anything found"
                nfsScan &
            fi
    
            # ipmi
            if [[ $port == '623' ]] \
            && [[ $protocol == 'tcp' ]] 
            then
                echo "starting ipmiScan"
                echo "... outputs $RECONDIR/${TARGET}.ipmi.hashcat"
                echo "... outputs $RECONDIR/${TARGET}.ipmi.john"
                echo "... outputs $RECONDIR/${TARGET}.ipmi.john.cracked"
                ipmiScan &
            fi
        
            # memcache
            if [[ $protocol == 'tcp' ]] \
            && [[ $service =~ memcached ]] 
            then
                echo "starting memcacheScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.msf.memcached.${port}.out"
                memcacheScan $port &
            fi
        
            # zookeeper
            if [[ $protocol == 'tcp' ]] \
            && [[ $service =~ zookeeper ]] 
            then
                echo "starting zookeeperScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.${port}.zookeeper.envi"
                echo "... outputs $RECONDIR/${TARGET}.${port}.zookeeper.stat"
                echo "... outputs $RECONDIR/${TARGET}.${port}.zookeeper.req"
                echo "... outputs $RECONDIR/${TARGET}.${port}.zookeeper.dump"
                zookeeperScan $port &
            fi

            # mesos
            # nmap sometimes shows mesos as "unknown", so probe for a page
            if [[ $protocol == 'tcp' ]] \
            && [[ $version =~ Mesos ]] \
            || curl -A "$USERAGENT" --retry 20 --retry-connrefused -k \
                -s http://${TARGET}:${port}/showme404 2>&1 \
                |grep -q timestamp
            then
                echo "starting mesosScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.version"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.env"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.trace"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.health"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.status"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.info"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.flags"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.features"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.dump"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.system-stats"
                echo "... outputs $RECONDIR/${TARGET}.${port}.mesos.metrics-snapshot"
                mesosScan $port &
            fi
        
            # dns
            if [[ $port == '53' ]] \
            && [[ $protocol == 'udp' ]] \
            && [[ $service == 'domain' ]] 
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
            if [[ $protocol == 'udp' ]] \
            && [[ $service == 'isakmp' ]] 
            then
                echo "starting ikeScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.${port}.ike-scan"
                echo "... outputs $RECONDIR/${TARGET}.${port}.ike-scan.key"
                echo "... outputs $RECONDIR/${TARGET}.${port}.ike-scan.key.crack"
                echo "... outputs $RECONDIR/${TARGET}.${port}.ike-scan.key.out"
                ikeScan $port &
            fi
        
            # rsync
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'rsync' ]] 
            then
                echo "starting rsyncScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.${port}.rsync"
                echo "... outputs $RECONDIR/${TARGET}.${port}.rsync-\$share"
                rsyncScan $port &
            fi
        
            # cifs/smb
            if [[ $protocol == 'tcp' ]] \
            && [[ $port == '445' ]] \
            && [[ $service == 'microsoft-ds' || $service == 'netbios-ssn' ]] 
            then
                echo "starting smbScan"
                echo "... outputs $RECONDIR/${TARGET}.smbshares"
                echo "... outputs $RECONDIR/${TARGET}.smbdirs"
                echo "... outputs $RECONDIR/${TARGET}.rpcclient"
                smbScan &

                echo "starting doHydra $port smb"
                echo "... outputs $RECONDIR/${TARGET}.smb.$port.hydra"
                doHydra $port smb &
            fi
        
            # redis
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'redis' ]] 
            then
                echo "starting redisScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.redis.${port}"
                redisScan $port &
            fi
        
            # ldap
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'ldap' ]] 
            then
                echo "starting ldapScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.ldap.${port}"
                echo "... outputs $RECONDIR/${TARGET}.ldap.${port}.\$context"
                ldapScan $port &
            fi
    
            # elasticsearch
            if [[ $protocol == 'tcp' ]] \
            && [[ $version == 'Elasticsearch' ]] 
            then
                echo "starting elasticsearchScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.elasticsearch.indexes.${port}"
                echo "... outputs $RECONDIR/${TARGET}.elasticsearch.indexes.${port}.\$index"
                elasticsearchScan $port $proto &
            fi
        
            # iscsi
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'iscsi' ]] 
            then
                echo "starting iscsiScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.iscsiadm.${port}"
                iscsiScan $port &
            fi

            if [[ $protocol == 'tcp' ]] \
            && [[ $version =~ SAP ]] 
            then
                sapflag=1
            fi
        
            if [[ $version =~ Java.RMI ]] \
            || [[ $service =~ java-rmi ]] \
            || [[ $service =~ rmiregistry ]] 
            then
                rmiflag=1
                RMIPORTS[${#RMIPORTS[@]}]=$port
            fi
        
            # docker
            if [[ $protocol == 'tcp' ]] \
            && [[ $version =~ Docker ]]
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
            if [[ $protocol == 'tcp' ]] \
            && [[ $service =~ postgresql ]]
            then
                echo "starting postgresqlScan for port $port"
                echo "... outputs $RECONDIR/${TARGET}.postgresql.$port"
                postgresqlScan $port &
    
                echo "starting postgresqlHydra for port $port"
                echo "... outputs $RECONDIR/${TARGET}.postgresql.$port.hydra"
                doHydra $port postgres &
            fi
    
        done
    done

    echo "starting otherNmaps"
    echo "... outputs $RECONDIR/${TARGET}.nmap-auth"
    echo "... outputs $RECONDIR/${TARGET}.nmap-exploitvuln"
    echo "... outputs $RECONDIR/${TARGET}.nmap-discoverysafe"
    echo "... outputs $RECONDIR/${TARGET}.nmap-ajp-brute"
    echo "... outputs $RECONDIR/${TARGET}.nmap-xmpp-brute"
    echo "... outputs $RECONDIR/${TARGET}.nmap-oracle-sid-brute"
    echo "... outputs $RECONDIR/${TARGET}.nmap-ipmi-brute"
    otherNmaps &

    if [[ $sshflag == 1 ]]
    then
        echo "starting ssh badKeyScan"
        echo "... outputs $RECONDIR/${TARGET}.ssh.badKeys"
        badKeyScan &
    fi

    if [[ $hpflag == 1 ]]
    then
        # separate HP scan from other http scans because of time
        echo "starting msfHPScan"
        echo "... outputs $RECONDIR/${TARGET}.hp.msf"
        msfHPScan &
    fi

    if [[ $sapflag == 1 ]]
    then
        # separate SAP scan from other http scans because of time
        echo "starting msfSapScan"
        echo "... outputs $RECONDIR/${TARGET}.sap.msf"
        msfSapScan &
    fi

    if [[ $rmiflag == 1 ]]
    then
        echo "starting msfRMIScan"
        echo "... outputs $RECONDIR/${TARGET}.rmi.msf"
        msfRMIScan &
    fi

    if [[ $ciscoflag == 1 ]]
    then
        echo "starting msfCiscoScan"
        echo "... outputs $RECONDIR/${TARGET}.cisco.msf"
        msfCiscoScan &
    fi

    if [[ $juniperflag == 1 ]]
    then
        echo "starting msfJuniperScan"
        echo "... outputs $RECONDIR/${TARGET}.juniper.msf"
        msfJuniperScan &
    fi

    if [[ -f "$RECONDIR"/${TARGET}.baseurls ]]
    then
        echo "starting webDiscover"
        echo "... outputs $RECONDIR/${TARGET}.robots.txt"
        echo "... outputs $RECONDIR/${TARGET}.robotspider.html"
        echo "... outputs $RECONDIR/${TARGET}.dirburls"
        echo "... outputs $RECONDIR/${TARGET}.urls.401"
        echo "... outputs $RECONDIR/${TARGET}.spider"
        echo "... outputs $RECONDIR/${TARGET}.spider.html"
        echo "... outputs $RECONDIR/${TARGET}.urls"
        echo "... outputs $RECONDIR/${TARGET}.urls.html"
        # do not background.  There are dependencies below.
        webDiscover 

        echo "starting WAScan"
        echo "... outputs $RECONDIR/${TARGET}.\$port.WAScan"
        WAScan &

        echo "starting msfHttpScan"
        echo "... outputs $RECONDIR/${TARGET}.http.msf"
        msfHttpScan &
    
        echo "starting routersploitScan"
        echo "... outputs $RECONDIR/${TARGET}.routersploit"
        routersploitScan &
    
        echo "starting skipfishScan"
        echo "... outputs $RECONDIR/${TARGET}.skipfish/"
        skipfishScan &

        echo "starting wigScan"
        echo "... outputs $RECONDIR/${TARGET}.wig"
        # do not background.  Limit number of simultaneous scans
        wigScan 

        echo "starting wapitiScan"
        echo "... outputs $RECONDIR/${TARGET}.\$port.wapiti"
        # do not background.  Limit number of simultaneous scans
        wapitiScan 

        echo "starting wafw00fScan"
        echo "... outputs $RECONDIR/${TARGET}.wafw00f"
        # do not background.  Limit number of simultaneous scans
        wafw00fScan 

        echo "starting niktoScan"
        echo "... outputs $RECONDIR/${TARGET}.nikto"
        # do not background.  Limit number of simultaneous scans
        niktoScan 

        echo "starting arachniScan"
        echo "... outputs $RECONDIR/${TARGET}/arachni.d"
        # do not background.  Limit number of simultaneous scans
        arachniScan 

        # Enable when trying harder...
        #echo "starting webWords"
        #echo "... outputs $RECONDIR/${TARGET}.webwords"
        #webWords 
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
    
    if [[ -f "$RECONDIR"/${TARGET}.urls.401 ]]
    then
        echo "starting hydraScanURLs"
        echo "... outputs $RECONDIR/${TARGET}.hydra/ if anything found"
        hydraScanURLs &
    fi
    
    if [[ -f "$RECONDIR"/${TARGET}.urls ]]
    then
        echo "starting getHeaders"
        echo "... outputs $RECONDIR/${TARGET}.headers"
        getHeaders &

        echo "starting davScanURLs"
        echo "... outputs $RECONDIR/${TARGET}.davtest if anything found"
        echo "... outputs $RECONDIR/${TARGET}.cadaver if anything found"
        echo "... outputs $RECONDIR/${TARGET}.nmap-webdav if anything found"
        davScanURLs &

        echo "starting scanURLs"
        echo "... outputs $RECONDIR/${TARGET}.whatweb"
        echo "... outputs $RECONDIR/${TARGET}.wpscan if anything found"
        echo "... outputs $RECONDIR/${TARGET}.joomscan if anything found"
        # do not background.  Limit number of simultaneous scans
        scanURLs 

        echo "starting fimapScan"
        echo "... outputs $RECONDIR/${TARGET}.fimap if anything found"
        fimapScan &

        echo "starting mechDumpURLs"
        echo "... outputs $RECONDIR/${TARGET}.mech-dump"
        # do not background mech-dump.  There are dependencies in wfuzzURLs.
        mechDumpURLs 

        echo "starting zapScan"
        echo "... outputs $RECONDIR/${TARGET}.zap.html"
        # do not background.  Limit number of simultaneous scans
        zapScan 

        echo "starting wfuzzURLs"
        echo "... outputs $RECONDIR/${TARGET}.wfuzz/"
        wfuzzURLs &
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
        echo "Jobs are still running.  Waiting... $jobscount out of 2880 minutes"
        jobs -l
        (( jobscount++ ))
        if [[ "$jobscount" -gt 2880 ]]
        then
            echo "killing jobs"
            #killHangs
            #sleep 60
            IFS=$'\n'
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
    # sometimes timeout will fork and hang
    local scan
    for scan in ike-scan joomscan sqlmap whatweb wpscan nikto fimap dirb ldapsearch redis-cli rpcclient smbclient dnsrecon dnsenum netkit-rsh showmount wget cewl mech-dump
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
    local icdir
    local testdir
    local pkgs="alien arachni bind9-host blindelephant brutespray cewl curl dirb dnsenum dnsrecon dos2unix exif exploitdb eyewitness git hsqldb-utils hydra ike-scan iproute2 john joomscan jq kafkacat ldap-utils libgmp-dev libnet-whois-ip-perl libxml2-utils libwww-mechanize-perl libpostgresql-jdbc-java libmysql-java libjt400-java libjtds-java libderby-java libghc-hdbc-dev libhsqldb-java mariadb-common metasploit-framework ncat ncrack nikto nmap nmap-common nsis open-iscsi openvas-cli postgresql-client-common python-pip routersploit rpcbind rpm rsh-client ruby screen seclists skipfish sqlline snmpcheck time tnscmd10g unzip wafw00f wapiti wfuzz wget whatweb wig wordlists wpscan xmlstarlet zaproxy"

    for pkg in $pkgs
    do
        if ! dpkg -s $pkg >/dev/null 2>&1
        then
            echo "FAILED: missing apps."
            echo "run: apt-get update; apt-get upgrade -y; apt-get install -y $pkgs"
            return 1
        fi
    done

    local rawtty=$(tty)
    TTY=${rawtty#*/*/}
    BORDER='################################################################################' 
    DATE=$(date +"%Y%m%d%H%M")
    USERAGENT='Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/5.0)'

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

    mkdir -p "$RECONDIR"/tmp >/dev/null 2>&1

    # prep default usernames/passwords
    cat /usr/share/wordlists/metasploit/http_default_users.txt \
        /usr/share/wordlists/metasploit/tomcat_mgr_default_users.txt \
        /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
        /usr/share/wordlists/metasploit/idrac_default_user.txt \
        /usr/share/wordlists/metasploit/http_default_users.txt \
        |dos2unix -f \
        |sort -u \
        >> "$RECONDIR"/tmp/users.tmp 

    cat /usr/share/seclists/Passwords/Common-Credentials/best110.txt \
        /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
        /usr/share/seclists/Passwords/Common-Credentials/top-shortlist.txt \
        /usr/share/wordlists/metasploit/idrac_default_pass.txt \
        /usr/share/wordlists/metasploit/adobe_top100_pass.txt \
        /usr/share/wordlists/metasploit/db2_default_pass.txt \
        /usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt \
        /usr/share/wordlists/metasploit/http_default_pass.txt \
        /usr/share/wordlists/metasploit/mirai_pass.txt \
        /usr/share/wordlists/metasploit/multi_vendor_cctv_dvr_pass.txt \
        /usr/share/wordlists/metasploit/postgres_default_pass.txt \
        /usr/share/wordlists/metasploit/tomcat_mgr_default_pass.txt \
        |dos2unix -f \
        |sort -u \
        >> "$RECONDIR"/tmp/passwds.tmp

    # add extra passwords
    echo "adminadmin" >> "$RECONDIR"/tmp/passwds.tmp
    echo "changethis" >> "$RECONDIR"/tmp/passwds.tmp
    echo "changeme" >> "$RECONDIR"/tmp/passwds.tmp
    echo "j5Brn9" >> "$RECONDIR"/tmp/passwds.tmp
    echo "UNKNOWN" >> "$RECONDIR"/tmp/passwds.tmp
    echo "Password" >> "$RECONDIR"/tmp/passwds.tmp
    echo "nimda" >> "$RECONDIR"/tmp/passwds.tmp
    echo "admin1" >> "$RECONDIR"/tmp/passwds.tmp
    echo "Password@123" >> "$RECONDIR"/tmp/passwds.tmp

    cat /usr/share/wordlists/metasploit/*userpass*txt \
        |sed -e 's/ /:/g' \
        |sort -u \
        >> "$RECONDIR"/tmp/userpass.tmp

    cat /usr/share/seclists/Passwords/Default-Credentials/db2-betterdefaultpasslist.txt \
        /usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt \
        /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt \
        /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt \
        /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt \
        /usr/share/seclists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt \
        /usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt \
        /usr/share/seclists/Passwords/Default-Credentials/windows-betterdefaultpasslist.txt \
        /usr/lib/python3/dist-packages/routersploit/resources/wordlists/defaults.txt \
        |dos2unix -f \
        |sort -u \
        >> "$RECONDIR"/tmp/userpass.tmp

    grep OptWordlist /usr/lib/python3/dist-packages/routersploit/*/*/*/*/*.py 2>/dev/null \
        |cut -d'"' -f2 \
        |sed -e 's|,|\n|g' \
        |egrep -v '^:|:$|^ ' \
        |sort -u \
        >> "$RECONDIR"/tmp/userpass.tmp

    echo "toor:toor" >> "$RECONDIR"/tmp/userpass.tmp

    cat "$RECONDIR"/tmp/users.tmp \
        |dos2unix -f \
        |sed -e 's| ||g' \
        |sort -u \
        > "$RECONDIR"/tmp/users.lst

    cat "$RECONDIR"/tmp/users.tmp "$RECONDIR"/tmp/passwds.tmp \
        |dos2unix -f \
        |sed -e 's| ||g' \
        |sort -u \
        > "$RECONDIR"/tmp/passwds.lst

    cat "$RECONDIR"/tmp/userpass.tmp \
        |dos2unix -f \
        |grep ':' \
        |sed -e 's| ||g' \
        |sort -u \
        |egrep -v ':$|^:' \
        > "$RECONDIR"/tmp/userpass.lst

    cat /usr/share/seclists/Passwords/Default-Credentials/oracle-betterdefaultpasslist.txt \
        /usr/share/nmap/nselib/data/oracle-default-accounts.lst \
        |dos2unix -f \
        |sed -e 's|:|/|g' \
        |sort -u \
        > "$RECONDIR"/tmp/defaultoracleuserpass.nmap

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


    if [[ ! -f /usr/share/wordlists/rockyou.txt ]]
    then
        gzip -k -d /usr/share/wordlists/rockyou.txt.gz >/dev/null 2>&1
    fi

    cat \
        /usr/share/dnsrecon/namelist.txt \
        /usr/share/dnsenum/dns.txt \
        /usr/share/nmap/nselib/data/vhosts-full.lst \
        |sort -u >"$RECONDIR"/tmp/dns.lst

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


    # Check for Oracle InstantClient libraries.
    # Issue warning if not found and provide instructions.
    # If instantclient zip files are in /tmp, then install them

    for testdir in /opt/oracle/instantclient*
    do 
        icdir=$testdir
    done

    if [[ ! -d "$icdir" ]] \
    && ls /tmp/instantclient-*-linux.*.zip >/dev/null 2>&1
    then
        echo "$BORDER"
        echo "# Found instantclient files and now installing"
        echo "$BORDER"
        mkdir -p /opt/oracle >/dev/null 2>&1
        for file in /tmp/instantclient-*.zip
        do
            unzip -o -d /opt/oracle $file >/dev/null 2>&1
        done
    fi

    if [[ ! -d "$icdir" ]] \
    && ! ls /tmp/instantclient-*-linux.*.zip >/dev/null 2>&1
    then
        echo "$BORDER"
        echo "# WARNING: You do not have the Oracle libraries installed"
        echo "# Some Metasploit and Nmap modules may not work if pentesting against Oracle DB"
        echo "# If you want to install the Oracle libraries:"
        echo "# Goto http://www.oracle.com/technetwork/database/database-technologies/instant-client/downloads/index.html"
        echo "# Login to Oracle"
        echo "# Select  Instant Client for Linux"
        echo "# Select the Accept license radio button"
        echo "# Get the latest instantclient-basic-linux.*.zip"
        echo "# Get the latest instantclient-jdbc-linux.*.zip"
        echo "# Get the latest instantclient-sqlplus-linux.*.zip"
        echo "# Get the latest instantclient-sdk-linux.*.zip"
        echo "# Put all zip files in /tmp"
        echo "# Rerun mkrecon.sh and it will auto-install/setup"
        echo "$BORDER"
        echo "Continuing without Oracle libraries..."
    fi

    for testdir in /opt/oracle/instantclient*
    do 
        icdir=$testdir
    done
    if [[ -d "$icdir" ]]
    then
        echo "Found Oracle libraries in $icdir and will setup env"
        export PATH=$PATH:$icdir
        export SQLPATH=$icdir
        export TNS_ADMIN=$icdir
        export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$icdir
        export ORACLE_HOME=$icdir

        if ! grep -q $icdir /etc/profile.d/oracle.sh >/dev/null 2>&1
        then
            echo "export PATH=\$PATH:$icdir"                        >/etc/profile.d/oracle.sh
            echo "export SQLPATH=$icdir"                           >>/etc/profile.d/oracle.sh
            echo "export TNS_ADMIN=$icdir"                         >>/etc/profile.d/oracle.sh
            echo "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:$icdir" >>/etc/profile.d/oracle.sh
            echo "export ORACLE_HOME=$icdir"                       >>/etc/profile.d/oracle.sh
            chmod 644 /etc/profile.d/oracle.sh
        fi

        if ! grep -q $icdir /etc/ld.so.conf.d/oracle.conf >/dev/null 2>&1
        then
            echo "$icdir" > /etc/ld.so.conf.d/oracle.conf
            chmod 644 /etc/ld.so.conf.d/oracle.conf
        fi

        if [[ ! -e $icdir/libclntsh.so ]]
        then
            rm -f $icdir/libclntsh.so >/dev/null 2>&1
            ln -s $icdir/libclntsh.so.* $icdir/libclntsh.so
        fi
        for file in ojdbc8.jar libheteroxa12.so orai18n.jar orai18.jar \
            orai18n-mapping.jar orai18n-mapping.jar
        do
            if [[ ! -e /usr/share/java/$file ]]
            then
                rm -f /usr/share/java/$file >/dev/null 2>&1
                ln -s $icdir/$file /usr/share/java/$file
            fi
        done
    
        if [[ -f /etc/init.d/metasploit ]] \
        && ! grep -q oracle.sh /etc/init.d/metasploit
        then
            echo '#!/bin/sh                                          '  >/etc/init.d/metasploit
            echo '                                                   ' >>/etc/init.d/metasploit
            echo '# chkconfig: 2345 80 30                            ' >>/etc/init.d/metasploit
            echo '# description: Metasploit RPC and web daemons      ' >>/etc/init.d/metasploit
            echo '                                                   ' >>/etc/init.d/metasploit
            echo '### BEGIN INIT INFO                                ' >>/etc/init.d/metasploit
            echo '# Provides:          metasploit                    ' >>/etc/init.d/metasploit
            echo '# Required-Start:    $remote_fs $network $named    ' >>/etc/init.d/metasploit
            echo '# Required-Stop:     $remote_fs $network $named    ' >>/etc/init.d/metasploit
            echo '# Default-Start:     2 3 4 5                       ' >>/etc/init.d/metasploit
            echo '# Default-Stop:      0 1 6                         ' >>/etc/init.d/metasploit
            echo '# Short-Description: Metasploit RPC and web daemons' >>/etc/init.d/metasploit
            echo '### END INIT INFO                                  ' >>/etc/init.d/metasploit
            echo '                                                   ' >>/etc/init.d/metasploit
            echo '. /etc/profile.d/oracle.sh                         ' >>/etc/init.d/metasploit
            echo '                                                   ' >>/etc/init.d/metasploit
            echo 'exec /opt/metasploit/ctlscript.sh "$@"             ' >>/etc/init.d/metasploit
            chmod 755 /etc/init.d/metasploit
        fi

        if ! gem list --local 2>/dev/null|grep -q ruby-oci8
        then
            gem install ruby-oci8 >/dev/null 2>&1
        fi
    fi

    return 0
}
################################################################################

################################################################################
function otherNmaps()
{
    local tcpports
    local udpports
    local scanports
    local sid

    tcpports="T:$(joinBy , "${TCPPORTS[@]}")"
    udpports="U:$(joinBy , "${UDPPORTS[@]}")"
    scanports=$(joinBy , $tcpports $udpports)

    ( timeout --kill-after=10 --foreground 172800 \
        nmap -T2 -Pn -p $scanports --script=ajp-brute -oN "$RECONDIR"/${TARGET}.nmap-ajp-brute $TARGET 2>&1 \
        |grep -q '|' \
        || rm -f "$RECONDIR"/${TARGET}.nmap-ajp-brute ) &

    ( timeout --kill-after=10 --foreground 172800 \
        nmap -T2 -Pn -p $scanports --script=xmpp-brute -oN "$RECONDIR"/${TARGET}.nmap-xmpp-brute $TARGET 2>&1 \
        |grep -q '|' \
        || rm -f "$RECONDIR"/${TARGET}.nmap-xmpp-brute ) &

    ( timeout --kill-after=10 --foreground 172800 \
        nmap -T2 -Pn -p $scanports --script=oracle-sid-brute -oN "$RECONDIR"/${TARGET}.nmap-oracle-sid-brute $TARGET >/dev/null 2>&1 
        if grep -q '|' "$RECONDIR"/${TARGET}.nmap-oracle-sid-brute
        then
            for sid in $(awk '/^\|/ {print $2}' "$RECONDIR"/${TARGET}.nmap-oracle-sid-brute |grep -v oracle-sid-brute)
            do
                timeout --kill-after=10 --foreground 172800 nmap -T2 -Pn -p $scanports --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=$sid -oN "$RECONDIR"/${TARGET}.nmap-oracle-brute-stealth.${sid} $TARGET >/dev/null 2>&1 &
                timeout --kill-after=10 --foreground 172800 nmap -T2 -Pn -p $scanports --script oracle-enum-users --script-args oracle-enum-users.sid=$sid,userdb=$RECONDIR/tmp/users.lst -oN "$RECONDIR"/${TARGET}.nmap-oracle-enum-users.${sid} $TARGET >/dev/null 2>&1 &
            done
        else
            rm -f "$RECONDIR"/${TARGET}.nmap-oracle-sid-brute 
        fi
    ) &

    ( timeout --kill-after=10 --foreground 172800 nmap -T3 -Pn -sU -p 623 --script ipmi-brute -oN "$RECONDIR"/${TARGET}.nmap-ipmi-brute $TARGET |grep -q '|' \
        || rm -f "$RECONDIR"/${TARGET}.nmap-ipmi-brute \
        ; grep -q 'open|filtered' "$RECONDIR"/${TARGET}.nmap-ipmi-brute 2>/dev/null \
        && rm -f "$RECONDIR"/${TARGET}.nmap-ipmi-brute ) &

    screen -dmS ${TARGET}.nmap-auth.$RANDOM timeout --kill-after=10 --foreground 172800 \
        nmap -T2 -Pn -p $scanports --script=auth --script-args http.useragent="$USERAGENT" -oN "$RECONDIR"/${TARGET}.nmap-auth $TARGET

    screen -dmS ${TARGET}.nmap-exploitvuln.$RANDOM timeout --kill-after=10 --foreground 172800 \
        nmap -T2 -Pn -p $scanports --script=exploit,vuln --script-args http.useragent="$USERAGENT" -oN "$RECONDIR"/${TARGET}.nmap-exploitvuln $TARGET

    screen -dmS ${TARGET}.nmap-discoverysafe.$RANDOM timeout --kill-after=10 --foreground 172800 \
        nmap -T2 -Pn -p $scanports --script=discovery,safe --script-args http.useragent="$USERAGENT" -oN "$RECONDIR"/${TARGET}.nmap-discoverysafe $TARGET
    
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
        echo "# WARNING: UNABLE TO CONNECT TO OPENVAS"
        echo "# If you need to install OpenVas, run apt-get install -y greenbone-security-assistant greenbone-security-assistant-common openvas openvas-cli openvas-manager openvas-manager-common openvas-scanner"
        echo "# Then run openvas-check-setup and follow the instructions until it says everything is working."
        echo "# Also change the username/password in the openvasScan function of this script."
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

    cat /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
        /usr/share/nmap/nselib/data/snmpcommunities.lst \
        /usr/share/seclists/Discovery/SNMP/snmp.txt \
        /usr/lib/python3/dist-packages/routersploit/resources/wordlists/snmp.txt \
        /usr/share/wordlists/metasploit/snmp_default_pass.txt \
        |dos2unix -f \
        |egrep -v '^#' \
        |sort -u \
        >"$RECONDIR"/tmp/snmp.txt

    nmap -Pn -T1 -p 161 -sU --script snmp-brute $TARGET --script-args snmp-brute.communitiesdb="$RECONDIR"/tmp/snmp.txt -oN "$RECONDIR"/${TARGET}.nmap.snmp-brute >/dev/null 2>&1
    
    if grep -q 'Valid credentials' "$RECONDIR"/${TARGET}.nmap.snmp-brute 2>/dev/null
    then
        for community in $(awk '/Valid credentials/ {print $2}' "$RECONDIR"/${TARGET}.nmap.snmp-brute |sort -u)
        do
            echo "$BORDER" >>"$RECONDIR"/${TARGET}.snmp-check
            echo "COMMUNITY: $community" >>"$RECONDIR"/${TARGET}.snmp-check
            snmp-check -c "$community" $IP 2>&1 \
                |egrep -v '^snmp-check |^Copyright ' \
                >>"$RECONDIR"/${TARGET}.snmp-check 2>&1
        done
    fi

    return 0
}
################################################################################


################################################################################
function nmapScan()
{
    # other udp ports: U:111,123,12444,1258,13,13200,1604,161,17185,17555,177,1900,20110,20510,2126,2302,23196,26000,27138,27244,27777,27950,28138,30710,3123,31337,3478,3671,37,3702,3784,389,44818,4569,47808,49160,49161,49162,500,5060,53,5351,5353,5683,623,636,64738,6481,67,69,8611,8612,8767,88,9100,9600 
    nmap -Pn --open -T3 -sT -sU -p T:1-65535,U:67,68,69,111,123,161,500,53,623,5353,1813,4500,177,5060,5269 \
        --script=version -sV --version-all -O \
        --script-args http.useragent="$USERAGENT" \
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
    screen -dmS ${TARGET}.ew.$RANDOM timeout --kill-after=10 --foreground 172800 \
        eyewitness --threads 2 -d "$RECONDIR"/${TARGET}.basicEyeWitness \
        --user-agent "$USERAGENT" --max-retries 10 --timeout 20 \
        --no-dns --no-prompt --all-protocols -x "$RECONDIR"/${TARGET}.xml
    return 0
}
################################################################################

################################################################################
function routersploitScan()
{
    local port
    local module
    local ssl
    local url
    local cmdfile
    local service

    for port in ${FTPPORTS[@]}
    do
        cmdfile="$RECONDIR"/tmp/routersploitscript.ftp
        mkdir -p "$RECONDIR"/tmp/routersploitscript.ftp.d >/dev/null 2>&1
        echo "exec echo \"$BORDER$BORDER\"" >>$cmdfile
        echo "exec echo \"TESTING $IP:$port WITH $module\"" >>$cmdfile
        echo "use creds/generic/ftp_default" >>$cmdfile
        echo "set target $IP" >>$cmdfile
        echo "set port $port" >>$cmdfile
        echo "set threads 1" >>$cmdfile
        echo "set verbosity false" >>$cmdfile
        echo "set stop_on_success false" >>$cmdfile
        echo "run" >>$cmdfile
    done
    for port in ${TELNETPORTS[@]}
    do
        cmdfile="$RECONDIR"/tmp/routersploitscript.telnet
        mkdir -p "$RECONDIR"/tmp/routersploitscript.telnet.d >/dev/null 2>&1
        echo "exec echo \"$BORDER$BORDER\"" >>$cmdfile
        echo "exec echo \"TESTING $IP:$port WITH $module\"" >>$cmdfile
        echo "use creds/generic/telnet_default" >>$cmdfile
        echo "set target $IP" >>$cmdfile
        echo "set port $port" >>$cmdfile
        echo "set threads 1" >>$cmdfile
        echo "set verbosity false" >>$cmdfile
        echo "set stop_on_success false" >>$cmdfile
        echo "run" >>$cmdfile
    done
    for port in ${SSHPORTS[@]}
    do
        cmdfile="$RECONDIR"/tmp/routersploitscript.ssh
        mkdir -p "$RECONDIR"/tmp/routersploitscript.ssh.d >/dev/null 2>&1
        echo "exec echo \"$BORDER$BORDER\"" >>$cmdfile
        echo "exec echo \"TESTING $IP:$port WITH $module\"" >>$cmdfile
        echo "use creds/generic/ssh_default" >>$cmdfile
        echo "set target $IP" >>$cmdfile
        echo "set port $port" >>$cmdfile
        echo "set threads 1" >>$cmdfile
        echo "set verbosity false" >>$cmdfile
        echo "set stop_on_success false" >>$cmdfile
        echo "run" >>$cmdfile
    done

    for port in ${HTTPPORTS[@]}
    do
        cmdfile="$RECONDIR"/tmp/routersploitscript.http
        mkdir -p "$RECONDIR"/tmp/routersploitscript.http.d >/dev/null 2>&1
        for module in \
            creds/generic/http_basic_digest_default \
            creds/generic/http_basic_digest_bruteforce 
        do
            echo "exec echo \"$BORDER$BORDER\"" >>$cmdfile
            echo "exec echo \"TESTING $IP:$port WITH $module\"" >>$cmdfile
            echo "use $module" >>$cmdfile
            echo "set target $IP" >>$cmdfile
            echo "set port $port" >>$cmdfile
            echo "set ssl false" >>$cmdfile
            echo "set threads 1" >>$cmdfile
            echo "set verbosity false" >>$cmdfile
            echo "set stop_on_success false" >>$cmdfile
            echo "run" >>$cmdfile
        done
        for module in $(echo "show all" |routersploit 2>/dev/null|grep webinterface_http)
        do
            echo "exec echo \"$BORDER$BORDER\"" >>$cmdfile
            echo "exec echo \"TESTING $IP:$port WITH $module\"" >>$cmdfile
            echo "use $module" >>$cmdfile
            echo "set target $IP" >>$cmdfile
            echo "set port $port" >>$cmdfile
            echo "set ssl false" >>$cmdfile
            echo "set threads 1" >>$cmdfile
            echo "set verbosity false" >>$cmdfile
            echo "set stop_on_success false" >>$cmdfile
            echo "run" >>$cmdfile
        done
    done

    for port in ${HTTPSPORTS[@]}
    do
        cmdfile="$RECONDIR"/tmp/routersploitscript.https
        mkdir -p "$RECONDIR"/tmp/routersploitscript.https.d >/dev/null 2>&1
        for module in \
            creds/generic/http_basic_digest_default \
            creds/generic/http_basic_digest_bruteforce 
        do
            echo "exec echo \"$BORDER$BORDER\"" >>$cmdfile
            echo "exec echo \"TESTING $IP:$port WITH $module\"" >>$cmdfile
            echo "use $module" >>$cmdfile
            echo "set target $IP" >>$cmdfile
            echo "set port $port" >>$cmdfile
            echo "set ssl true" >>$cmdfile
            echo "set threads 1" >>$cmdfile
            echo "set verbosity false" >>$cmdfile
            echo "set stop_on_success false" >>$cmdfile
            echo "run" >>$cmdfile
        done
        for module in $(echo "show all" |routersploit 2>/dev/null|grep webinterface_http)
        do
            echo "exec echo \"$BORDER$BORDER\"" >>$cmdfile
            echo "exec echo \"TESTING $IP:$port WITH $module\"" >>$cmdfile
            echo "use $module" >>$cmdfile
            echo "set target $IP" >>$cmdfile
            echo "set port $port" >>$cmdfile
            echo "set ssl true" >>$cmdfile
            echo "set threads 1" >>$cmdfile
            echo "set verbosity false" >>$cmdfile
            echo "set stop_on_success false" >>$cmdfile
            echo "run" >>$cmdfile
        done
    done

    # Launch a routersploit for each service.
    # Move into a service-dedicated directory because routersploit creates a logfile.
    for service in ssh telnet ftp http https
    do
        if [[ -f "$RECONDIR"/tmp/routersploitscript.$service ]]
        then
            (
            cd "$RECONDIR"/tmp/routersploitscript.$service.d
            cat "$RECONDIR"/tmp/routersploitscript.$service \
                |timeout --kill-after 10 --foreground 172800 \
                routersploit 2>&1 \
                |sed -r "s/\x1B\[(([0-9]{1,2})?(;)?([0-9]{1,2})?)?[m,K,H,f,J]//g" \
                |strings -a \
                > "$RECONDIR"/${TARGET}.routersploit.$service 2>&1
            ) &
        fi
    done

    while jobs 2>&1|grep -q 'routersploit'
    do
        wait -n $(jobs 2>&1|grep routersploit |cut -d'[' -f2|cut -d']' -f1|head -1)
    done

    return 0
}
################################################################################

################################################################################
function rshBrute()
{
    local login

    for login in $(cat "$RECONDIR"/tmp/users.lst)
    do
        timeout --kill-after=10 --foreground 300 netkit-rsh -l $login $TARGET id -a 2>&1 |grep -v 'Permission denied' \
            >>"$RECONDIR"/${TARGET}.rsh 
    done

    return 0
}
################################################################################

################################################################################
function kafkaScan()
{
    local port=$1
    local topic

    timeout --kill-after=10 --foreground 300 \
        kafkacat -b $TARGET:$port -L \
        >> "$RECONDIR"/${TARGET}.${port}.kafkacat 2>&1

    for topic in $(kafkacat -b $TARGET:$port -L \
        |awk '/topic / {print $2}' |cut -d'"' -f2 |sort -u)
    do
        if [[ $(timeout --kill-after=10 --foreground 900 kafkacat -C -b $TARGET:$port -t $topic -o beginning -c 1 -e 2>/dev/null |wc -l) -gt 0 ]]
        then
            timeout --kill-after=10 --foreground 900 \
                kafkacat -C -b $TARGET:$port -t $topic -o beginning -c 100 -e 2>/dev/null \
                |strings -a \
                |jq -M . \
                >> "$RECONDIR"/${TARGET}.${port}.${topic}.kafkacat 2>&1
        fi
    done

    return 0
}
################################################################################

################################################################################
function nfsScan()
{
    local output
    local i

    ( timeout --kill-after=10 --foreground 300 \
        showmount -e ${TARGET} >"$RECONDIR"/${TARGET}.showmount-e 2>&1 \
        || rm -f "$RECONDIR"/${TARGET}.showmount-e >/dev/null 2>&1 ) &
    ( timeout --kill-after=10 --foreground 300 \
        showmount -a ${TARGET} >"$RECONDIR"/${TARGET}.showmount-a 2>&1 \
        || rm -f "$RECONDIR"/${TARGET}.showmount-a >/dev/null 2>&1 ) &


    # the nfs-ls nse script only works half the time
    for i in {1..10}
    do
        output=$(timeout --kill-after=10 --foreground 300 nmap -T2 -Pn -p 111 --script=nfs-ls $TARGET 2>&1)
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
    local file
    local tmp={}

    domain=$(host $IP $IP |grep 'domain name pointer' \
        |tail -1 |sed -e 's/.*domain name pointer \(.*\)./\1/'  |sed -e 's/\.$//')
    if [[ "$(echo $domain |grep -o '.' |grep -c '\.')" -ge 3 ]]
    then
        domain=$(host $IP $IP |grep 'domain name pointer' |tail -1 \
            |sed -e 's/.*domain name pointer \(.*\)./\1/'  |sed -e 's/\.$//' |cut -d'.' -f2-)
    fi

    if [[ $domain =~ ^..* ]]
    then
        timeout --kill-after=10 --foreground 900 dnsenum --dnsserver $TARGET -f "$RECONDIR"/tmp/dns.lst --nocolor --enum -p0 $domain \
            >>"$RECONDIR"/${TARGET}.dnsenum 2>&1 &
        timeout --kill-after=10 --foreground 900 dnsrecon -d $domain -n $TARGET >>"$RECONDIR"/${TARGET}.dnsrecon 2>&1 
        host -a $domain. $TARGET >>"$RECONDIR"/${TARGET}.host-a 2>&1 &
        host -l $domain. $TARGET >>"$RECONDIR"/${TARGET}.host-l 2>&1 &
    fi

    timeout --kill-after=10 --foreground 900 dnsrecon -n $TARGET -r ${IP%.*}.0-${IP%.*}.255  \
        >>"$RECONDIR"/${TARGET}.dnsreconptr.local 2>&1 

    mkdir -p "$RECONDIR"/${TARGET}.arpas >/dev/null 2>&1
    for a in {0..255}
    do  
        for b in {0..255}
        do  
            (   
            tmp[10$a$b]=$(host -a $b.$a.10.in-addr.arpa. ${TARGET} 2>&1)
            if echo "${tmp[10$a$b]}" | grep -q "no servers could be reached"
            then
                # try again for slow dns
                sleep 3
                tmp[10$a$b]=$(host -a $b.$a.10.in-addr.arpa. ${TARGET} 2>&1)
            fi  
            if ! echo "${tmp[10$a$b]}" | grep -q " not found:"
            then
                echo "${tmp[10$a$b]}" > "$RECONDIR"/${TARGET}.arpas/$b.$a.10.in-addr.arpa. 
            fi  
            unset tmp[10$a$b]
            ) & 
            sleep .05 
        done
        sleep 5
    done
    for a in {16..31}
    do  
        for b in {0..255}
        do  
            (   
            tmp[172$a$b]=$(host -a $b.$a.172.in-addr.arpa. ${TARGET} 2>&1)
            if echo "${tmp[172$a$b]}" | grep -q "no servers could be reached"
            then
                # try again for slow dns
                sleep 3
                tmp[172$a$b]=$(host -a $b.$a.172.in-addr.arpa. ${TARGET} 2>&1)
            fi  
            if ! echo "${tmp[172$a$b]}" | grep -q " not found:"
            then
                echo "${tmp[172$a$b]}" > "$RECONDIR"/${TARGET}.arpas/$b.$a.172.in-addr.arpa. 
            fi  
            unset tmp[172$a$b]
            ) & 
            sleep .05 
        done
        sleep 5
    done
    for a in {0..255}
    do  
        (   
        tmp[192168$a$b]=$(host -a $a.168.192.in-addr.arpa. ${TARGET} 2>&1)
        if echo "${tmp[192168$a$b]}" | grep -q "no servers could be reached"
        then
            # try again for slow dns
            sleep 3
            tmp[192168$a$b]=$(host -a $a.168.192.in-addr.arpa. ${TARGET} 2>&1)
        fi  
        if ! echo "${tmp[192168$a$b]}" | grep -q " not found:"
        then
            echo "${tmp[192168$a$b]}" > "$RECONDIR"/${TARGET}.arpas/$a.168.192.in-addr.arpa. 
        fi  
        unset tmp[192168$a$b]
        ) & 
        sleep .05 
    done

    # sleep for background lookup jobs
    sleep 20

    # retry if failed the first time
    echo "CHECKING $RECONDIR/${TARGET}.arpas/*.in-addr.arpa."
    for file in "$RECONDIR"/${TARGET}.arpas/*.in-addr.arpa.
    do
        [[ ! -f "$file" ]] && break

        arpa=${file##*/}
        if ! grep -q SOA "$file"
        then
            host -a $arpa ${TARGET} > "$file" 2>&1
            grep -q "Host $arpa not found:" "$file" \
                && rm -f "$file" >/dev/null 2>&1
        fi
    done

    # pull discovered domains from arpa files
    egrep "IN\s+NS\s" "$RECONDIR"/${TARGET}.arpas/*.arpa. \
		|awk '{print $5}'|cut -d'.' -f2-  |sort -u \
        > "$RECONDIR"/${TARGET}.domains 2>&1
    for domain in $(cat "$RECONDIR"/${TARGET}.domains)
    do
        host -a $domain $TARGET >>"$RECONDIR"/${TARGET}.host-a.$domain 2>&1
        host -l $domain $TARGET >>"$RECONDIR"/${TARGET}.host-l.$domain 2>&1
    done
            

    for arpa in $(cat "$RECONDIR"/${TARGET}.arpas/*.in-addr.arpa. 2>/dev/null \
        |egrep "\s+IN\s+SOA\s" |awk '{print $1}' |sed -e 's/.in-addr.arpa.*//g' |sort -u)
    do
        IFS='.' subnet=($arpa)
        IFS=$'\n'
        if [[ ${#subnet[@]} -eq 2 ]]
        then
            timeout --kill-after=10 --foreground 1800 \
                dnsrecon -n $TARGET -r ${subnet[1]}.${subnet[0]}.0.0/16 \
                >>"$RECONDIR"/${TARGET}.dnsreconptr.${subnet[1]}.${subnet[0]} 2>&1 
        elif [[ ${#subnet[@]} -eq 3 ]]
        then
            timeout --kill-after=10 --foreground 1800 \
                dnsrecon -n $TARGET -r ${subnet[2]}.${subnet[1]}.${subnet[0]}.0/24 \
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

    timeout --kill-after=10 --foreground 900 \
        ike-scan -M -d $port $TARGET >>"$RECONDIR"/${TARGET}.${port}.ike-scan 2>&1 

    timeout --kill-after=10 --foreground 900 \
        ike-scan -d $port -A -M -P"$RECONDIR"/${TARGET}.${port}.ike-scan.key $TARGET \
        >>"$RECONDIR"/${TARGET}.${port}.ike-scan.key.out 2>&1 

    if [[ -f "$RECONDIR"/${TARGET}.${port}.ike-scan.key ]]
    then
        timeout --kill-after=10 --foreground 172800 \
            psk-crack -d /usr/share/wordlists/rockyou.txt "$RECONDIR"/${TARGET}.${port}.ike-scan.key \
            >>"$RECONDIR"/${TARGET}.${port}.ike-scan.key.crack 2>&1
    fi

    return 0
}
################################################################################

################################################################################
function rsyncScan()
{
    local port=$1
    local share

    timeout --kill-after=10 --foreground 300 \
        rsync --list-only --port=$port rsync://$TARGET \
        >>"$RECONDIR"/${TARGET}.${port}.rsync 2>&1 \
        || rm -f "$RECONDIR"/${TARGET}.${port}.rsync >/dev/null 2>&1

    if [[ -f  "$RECONDIR"/${TARGET}.${port}.rsync ]]
    then
        for share in $(awk '{print $1}' "$RECONDIR"/${TARGET}.${port}.rsync)
        do
            timeout --kill-after=10 --foreground 600 \
                rsync --list-only --port=${port%%/*} rsync://$TARGET/$share \
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
        timeout --kill-after=10 --foreground 90 \
            smbclient -N -c dir //$TARGET/"$share" >>"$RECONDIR"/${TARGET}.smbdirs 2>&1
        echo "" >>"$RECONDIR"/${TARGET}.smbdirs
        echo "" >>"$RECONDIR"/${TARGET}.smbdirs
    done
    for cmd in srvinfo \
        dsgetdcinfo \
        ntsvcs_getversion \
        wkssvc_wkstagetinfo \
        wkssvc_getjoininformation \
        wkssvc_enumeratecomputernames \
        dfsenum \
        netshareenumall \
        enumdomusers \
        enumdomgroups
    do
        echo "####################" >>"$RECONDIR"/${TARGET}.rpcclient
        echo "cmd: $cmd" >>"$RECONDIR"/${TARGET}.rpcclient
        timeout --kill-after=10 --foreground 90 \
            rpcclient -U "" $TARGET -N -c $cmd >>"$RECONDIR"/${TARGET}.rpcclient 2>&1
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

    echo "show databases" >> "$RECONDIR"/${TARGET}.mysql.$port
    timeout --kill-after=10 --foreground 300 \
        mysql -E -u root -e 'show databases;' --connect-timeout=90 -h $TARGET \
        >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1


    for db in $(cat "$RECONDIR"/${TARGET}.mysql.$port |awk '/^Database:/ {print $2}')
    do
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.mysql.$port
        echo "Tables from database $db" >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
        timeout --kill-after=10 --foreground 300 \
            mysql -E -u root -D "$db" -e 'show tables;' --connect-timeout=90 -h $TARGET \
            |grep -v 'row *' >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1
    done

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.mysql.$port
    echo "show full processlist;" >> "$RECONDIR"/${TARGET}.mysql.$port 
    timeout --kill-after=10 --foreground 300 \
        mysql -E -u root -e 'show full processlist;' --connect-timeout=90 -h $TARGET \
        >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.mysql.$port
    echo "select host,user,password from mysql.user;" >> "$RECONDIR"/${TARGET}.mysql.$port
    timeout --kill-after=10 --foreground 300 \
        mysql -E -u root -e 'select host,user,password from mysql.user;' --connect-timeout=90 -h $TARGET \
        >> "$RECONDIR"/${TARGET}.mysql.$port 2>&1

    return 0
}
################################################################################

################################################################################
function oracleScan()
{
    local port=$1
    local sid
    local file

    for file in /usr/share/nmap/nselib/data/oracle-sids /usr/share/wordlists/metasploit/sid.txt
    do
        timeout --kill-after=10 --foreground 86400 \
            hydra -I -P $file -u -t 2 -s $port $TARGET oracle-sid \
            >> "$RECONDIR"/${TARGET}.$service.$port.hydra 2>&1
    done

    # DISABLED BY DEFAULT.
    # This will likely lockout accounts
    #
    # [1580][oracle-sid] host: blah.dca.somewhere.net   login: blahdb
    #for sid in $(cat "$RECONDIR"/${TARGET}.$service.$port.hydra \
    #    |awk '/oracle-sid.*login: / {print $5}')
    #do
    #    timeout --kill-after=10 --foreground 14400 \
    #        nmap -T4 -Pn -p $port --script oracle-brute \
    #        --script-args oracle-brute.sid=$sid \
    #        --script-args brute.credfile="$RECONDIR"/tmp/defaultoracleuserpass.nmap \
    #        -oN "$RECONDIR"/${TARGET}.nmap-oracle-brute.${sid} \
    #        $TARGET 
    #done

    return 0
}
################################################################################

################################################################################
function passHydra()
{
    local port=$1
    local service=$2
    local file
    shift
    shift

    for file in $*
    do
        if [[ -f "$file" ]]
        then
            timeout --kill-after=10 --foreground 86400 \
                /usr/bin/time -v \
                hydra -I -P $file -u -t 1 -s $port $TARGET $service \
                |strings -a \
                >> "$RECONDIR"/${TARGET}.$service.$port.hydra 2>&1
        else
            echo "ERROR in passHydra: file not found: $file"
        fi
    done

#    if ! grep -q 'successfully completed' "$RECONDIR"/${TARGET}.$service.$port.hydra 2>/dev/null
#    then 
#        rm -f "$RECONDIR"/${TARGET}.$service.$port.hydra 2>/dev/null
#    fi       

    return 0
}
################################################################################

################################################################################
function doHydra()
{
    local port=$1
    local service=$2

    timeout --kill-after=10 --foreground 172800 \
        /usr/bin/time -v \
        hydra -I -C "$RECONDIR"/tmp/userpass.lst -u -t 2 -s $port $TARGET $service \
        2>&1 \
        |strings -a \
        >> "$RECONDIR"/${TARGET}.$service.$port.hydra 2>&1

#    if ! grep -q 'successfully completed' "$RECONDIR"/${TARGET}.$service.$port.hydra 2>/dev/null
#    then 
#        rm -f "$RECONDIR"/${TARGET}.$service.$port.hydra 2>/dev/null
#    fi       

    return 0
}
################################################################################

################################################################################
function postgresqlScan()
{
    local port=$1
    local db

    # set password var.  It will only be used if postgres asks for it.
    export PGPASSWORD=postgres

    timeout --kill-after=10 --foreground 300 psql -w -h $TARGET -p $port -U postgres -l -x \
        >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1

    for db in $(cat "$RECONDIR"/${TARGET}.postgresql.$port |awk '/^Name/ {print $3}')
    do
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.postgresql.$port
        echo "Tables from database $db" >> "$RECONDIR"/${TARGET}.postgresql.$port
        timeout --kill-after=10 --foreground 300 \
            psql -w -h $TARGET -p $port -U postgres -x -c 'SELECT * FROM pg_catalog.pg_tables;' -d $db \
            >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1
    done

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.postgresql.$port
    echo "select * from pg_stat_activity" >> "$RECONDIR"/${TARGET}.postgresql.$port
    timeout --kill-after=10 --foreground 300 \
        psql -w -h $TARGET -p $port -U postgres -x -c 'select * from pg_stat_activity;' \
        >> "$RECONDIR"/${TARGET}.postgresql.$port 2>&1

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.postgresql.$port
    echo "select * from pg_catalog.pg_shadow" >> "$RECONDIR"/${TARGET}.postgresql.$port
    timeout --kill-after=10 --foreground 300 \
        psql -w -h $TARGET -p $port -U postgres -x -c 'select * from pg_catalog.pg_shadow;' \
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

    timeout --kill-after=10 --foreground 300 \
        curl -A "$USERAGENT" --retry 20 --retry-connrefused -k -s ${proto}://${TARGET}:$port/info \
            2>/dev/null \
            |jq -M . \
            >> "$RECONDIR"/${TARGET}.dockerinfo.${port} 2>&1

    timeout --kill-after=10 --foreground 300 \
        curl -A "$USERAGENT" --retry 20 --retry-connrefused -k -s ${proto}://${TARGET}:$port/networks \
            2>/dev/null \
            |jq -M . \
            >> "$RECONDIR"/${TARGET}.dockernetworks.${port} 2>&1

    timeout --kill-after=10 --foreground 300 \
        curl -A "$USERAGENT" --retry 20 --retry-connrefused -k \
            -s ${proto}://${TARGET}:$port/containers/json 2>/dev/null \
            |jq -M . \
            >> "$RECONDIR"/${TARGET}.dockercontainers.${port} 2>&1

    for id in $(grep '"Id": ' "$RECONDIR"/${TARGET}.dockercontainers.${port} |cut -d'"' -f4)
    do
        timeout --kill-after=10 --foreground 300 \
            curl -A "$USERAGENT" --retry 20 --retry-connrefused -k \
                -s ${proto}://${TARGET}:${port}/containers/${id}/top 2>/dev/null \
                |jq -M . \
                >> "$RECONDIR"/dockertop.${port}.${id}
        timeout --kill-after=10 --foreground 300 \
            curl -A "$USERAGENT" --retry 20 --retry-connrefused -k \
                -s ${proto}://${TARGET}:${port}/containers/${id}/changes 2>/dev/null \
                |jq -M . \
                >> "$RECONDIR"/dockerchanges.${port}.${id}
        timeout --kill-after=10 --foreground 300 \
            curl -A "$USERAGENT" --retry 20 --retry-connrefused -k \
                -s "${proto}://${TARGET}:${port}/containers/${id}/archive?path=/etc/shadow" \
                2>/dev/null \
                |tar xf - -O \
                >> "$RECONDIR"/dockershadow.${port}.${id} 2>/dev/null

    done

    timeout --kill-after=10 --foreground 300 \
        curl -A "$USERAGENT" --retry 20 --retry-connrefused -k \
            -s ${proto}://${TARGET}:${port}/v2/_catalog 2>/dev/null \
            |jq -M . \
            >> "$RECONDIR"/${TARGET}.dockerepo.${port} 2>&1

    return 0
}
################################################################################

################################################################################
function iscsiScan()
{
    local port=$1

    timeout --kill-after=10 --foreground 900 \
        iscsiadm -m discovery -t st -p ${TARGET}:${port} \
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

    timeout --kill-after=10 --foreground 300 \
        curl -A "$USERAGENT" --retry 20 --retry-connrefused -k \
            -s "${proto}://${TARGET}:${port}/_cat/indices?v" \
            > "$RECONDIR"/${TARGET}.elasticsearch.${port} 2>&1

    timeout --kill-after=10 --foreground 300 \
        curl -A "$USERAGENT" --retry 20 --retry-connrefused -k \
            -s "${proto}://${TARGET}:${port}/_all/_settings" 2>&1 \
            |jq . \
            > "$RECONDIR"/${TARGET}.elasticsearch.${port}._all_settings 

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
            timeout --kill-after=10 --foreground 300 \
                curl -A "$USERAGENT" --retry 20 --retry-connrefused -k \
                    -s "${proto}://${TARGET}:${port}/${index}/_stats" \
                    2>/dev/null \
                    |jq . \
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
    local db

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.redis.${port}
    echo "Querying info for  database $db" >> "$RECONDIR"/${TARGET}.redis.${port}
    echo 'info' |timeout --kill-after=10 --foreground 300 \
        redis-cli -h $TARGET -p $port |strings -a \
        >> "$RECONDIR"/${TARGET}.redis.${port} 2>&1

    for db in {0..16}
    do
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.redis.${port}
        echo "Testing database $db" >> "$RECONDIR"/${TARGET}.redis.${port}
        timeout --kill-after=10 --foreground 90 \
            redis-cli -h $TARGET -p $port -n $db --scan \
            >> "$RECONDIR"/${TARGET}.redis.${port} 2>&1

        echo "$BORDER" >> "$RECONDIR"/${TARGET}.redis.${port}
        echo "Querying bigkeys for database $db" >> "$RECONDIR"/${TARGET}.redis.${port}
        timeout --kill-after=10 --foreground 90 \
            redis-cli -h $TARGET -p $port -n $db --bigkeys |tail -n +7 \
            >> "$RECONDIR"/${TARGET}.redis.${port} 2>&1
    done

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.redis.${port}
    echo "Querying client list for database $db" >> "$RECONDIR"/${TARGET}.redis.${port}
    echo 'client list' |timeout --kill-after=10 --foreground 300 \
        redis-cli -h $TARGET -p $port \
        >> "$RECONDIR"/${TARGET}.redis.${port} 2>&1

    echo "$BORDER" >> "$RECONDIR"/${TARGET}.redis.${port}.monitor
    echo "Running monitor for database $db" >> "$RECONDIR"/${TARGET}.redis.${port}.monitor
    echo 'monitor' |timeout --kill-after=60 --foreground 300 \
        redis-cli -h $TARGET -p $port \
        >> "$RECONDIR"/${TARGET}.redis.${port}.monitor 2>&1

    return 0
}
################################################################################

################################################################################
function ldapScan()
{
    local port=$1
    local context

    timeout --kill-after=10 --foreground 300 \
        ldapsearch -h $TARGET -p $port -x -s base \
        >> "$RECONDIR"/${TARGET}.ldap.${port} 2>&1

    for context in $(awk '/^namingContexts: / {print $2}' "$RECONDIR"/${TARGET}.ldap.${port})
    do
        timeout --kill-after=10 --foreground 300 \
            ldapsearch -h $TARGET -p $port -x -b "$context" \
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

    IFS=$'\n'
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
    # Get robots.txt and spider the baseurls
    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        urlfile=${url//\//,}

        echo "$BORDER" >>"$RECONDIR"/${TARGET}.robots.txt
        echo "${url}/robots.txt" >>"$RECONDIR"/${TARGET}.robots.txt
        curl -A "$USERAGENT" --retry 20 --retry-connrefused -s ${url}/robots.txt \
            >>"$RECONDIR"/${TARGET}.robots.txt 2>&1
        echo "" >>"$RECONDIR"/${TARGET}.robots.txt
        echo "$BORDER" >>"$RECONDIR"/${TARGET}.robots.txt

        for robotdir in $(curl -A "$USERAGENT" --retry 20 --retry-connrefused -s ${url}/robots.txt 2>&1 \
            |egrep '^Disallow: ' \
            |awk '{print $2}' \
            |sed -e 's/\*//g' \
            |tr -d '\r')
        do
            if [[ ! $robotdir =~ ^/$ ]] \
            && [[ ! $robotdir =~ \? ]] \
            && [[ $robotdir =~ /$ ]] 
            then
                a_robots[${#a_robots[@]}]="${url}${robotdir}"
            fi
            timeout --kill-after=10 --foreground 300 \
                wget -U "$USERAGENT" \
                    --tries=20 --retry-connrefused --no-check-certificate -r -l3 --spider --force-html \
                    -D $TARGET ${url}${robotdir} 2>&1 \
                    |grep '^--' \
                    |grep -v '(try:' \
                    |awk '{ print $3 }' \
                    >> "$RECONDIR"/tmp/${TARGET}.robotspider.raw 2>/dev/null
        done

        timeout --kill-after=10 --foreground 300 \
            wget -U "$USERAGENT" \
                --tries=20 --retry-connrefused --no-check-certificate -r -l3 --spider \
                --force-html -D $TARGET "$url" 2>&1 \
                |grep '^--' \
                |grep -v '(try:' \
                |awk '{ print $3 }' \
                |grep "/$TARGET[:/]" \
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
            timeout --kill-after=10 --foreground 1800 \
                dirb "$url" "$dirbfile" -a "$USERAGENT" -r -f -S \
                    >> "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-${shortfile}.dirb 2>&1
        done
    done

    # build html file from robots.txt files
    for url in $(cat "$RECONDIR"/tmp/${TARGET}.robotspider.raw 2>/dev/null|sort -u)
    do
        echo "<a href=\"$url\">$url</a><br>" >> "$RECONDIR"/${TARGET}.robotspider.html
    done

    for url in $(grep CODE:200 "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-*.dirb \
        |grep -v SIZE:0 \
        |awk '{print $2}' \
        |sort -u)
    do
        echo "${url%\?*}" >> "$RECONDIR"/tmp/${TARGET}.dirburls.raw
    done

    for url in $(grep '==> DIRECTORY: ' "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-*.dirb \
        |awk '{print $3}' \
        |sort -u)
    do
        echo "${url%\?*}" >> "$RECONDIR"/tmp/${TARGET}.dirburls.raw
    done

    cat "$RECONDIR"/tmp/${TARGET}.dirburls.raw 2>/dev/null \
        |sed -e 's/\/\/*$/\//g' \
        |sed -e 's/\/\.\/*$/\//g' \
        |sed -e 's/\/\%2e\/*$/\//g' \
        |sort -u \
        > "$RECONDIR"/${TARGET}.dirburls

    for url in $(cat "$RECONDIR"/${TARGET}.dirburls 2>/dev/null )
    do
        timeout --kill-after=10 --foreground 300 \
            wget -U "$USERAGENT" \
            --tries=20 --retry-connrefused --no-check-certificate -r -l2 --spider --force-html \
            -D $TARGET "$url" 2>&1 \
            | grep '^--' \
            |grep -v '(try:' \
            |egrep "$IP|$TARGET" \
            |awk '{ print $3 }' \
            >> "$RECONDIR"/tmp/${TARGET}.spider.raw 2>/dev/null
    done

    cat "$RECONDIR"/tmp/${TARGET}.spider.raw \
        "$RECONDIR"/tmp/${TARGET}.robotspider.raw \
        2>/dev/null \
        |egrep -vi '\.(css|js|png|gif|jpg|gz|ico)$' \
        |sort -u \
        |sed -e "s|$TARGET//|$TARGET/|g" \
        |grep -v '/manual/' \
        |grep -v '/icons/' \
        > "$RECONDIR"/${TARGET}.spider

    for url in $(cat "$RECONDIR"/${TARGET}.spider|sort -u)
    do
        urlfile=${url//\//,}
        echo "<a href=\"$url\">$url</a><br>" >> "$RECONDIR"/${TARGET}.spider.html
    done

    # combine wget spider and dirb
    cat "$RECONDIR"/${TARGET}.dirburls "$RECONDIR"/${TARGET}.spider 2>/dev/null  \
        |cut -d'?' -f1 \
        |cut -d'%' -f1 \
        |cut -d'"' -f1 \
        |egrep -vi '\.(css|js|png|gif|jpg|gz|ico)$' \
        |sed -e "s|$TARGET//*|$TARGET/|g" \
        |sed -e "s|\(^https:\)//\(.*\)|\1,,\2|" \
        |sed -e "s|\(^http:\)//\(.*\)|\1,,\2|" \
        |sed -e 's|//*|/|g' \
        |sed -e 's|/\./||g' \
        |sed -e 's|/\.\./||g' \
        |sed -e 's|:,,|://|' \
        |grep -v '/manual/' \
        |grep -v '/icons/' \
        |sort -u > "$RECONDIR"/tmp/${TARGET}.urls.raw

    # remove duplicates that have standard ports.  e.g. http://target:80/dir -> http://target/dir
    for url in $(cat "$RECONDIR"/tmp/${TARGET}.urls.raw 2>/dev/null )
    do
        if echo $url|egrep ':80/|:80$' |egrep -q '^http://'
        then 
            newurl=$(echo $url|sed -e 's|:80||')
        elif echo $url|egrep ':443/|:443$' |egrep -q '^https://'
        then
            newurl=$(echo $url|sed -e 's|:443||')
        else 
            newurl=$url
        fi
        echo $newurl >> "$RECONDIR"/tmp/${TARGET}.urls.stripped
    done
    cat "$RECONDIR"/tmp/${TARGET}.urls.stripped 2>/dev/null |sort -u > "$RECONDIR"/${TARGET}.urls 
    rm -f "$RECONDIR"/tmp/${TARGET}.urls.stripped >/dev/null 2>&1
    rm -f "$RECONDIR"/tmp/${TARGET}.urls.raw >/dev/null 2>&1

    for url in $(cat "$RECONDIR"/${TARGET}.urls 2>/dev/null )
    do 
        echo "<a href=\"$url\">$url</a><br>" >> "$RECONDIR"/${TARGET}.urls.html
    done

    for url in $(grep CODE:401 "$RECONDIR"/tmp/${TARGET}.dirb/${TARGET}-*.dirb 2>/dev/null \
        |awk '{print $2}' \
        |sort -u)
    do
        echo "${url%\?*}" >> "$RECONDIR"/${TARGET}.urls.401
    done

    # process all urls for 401's that dirb may have missed
    for url in $(cat "$RECONDIR"/${TARGET}.urls 2>/dev/null )
    do
        if ! egrep -q "^$url$" "$RECONDIR"/${TARGET}.urls.401 >/dev/null 2>&1 \
        && timeout --kill-after=10 --foreground 900 \
            wget -U "$USERAGENT" --tries=20 --retry-connrefused -q -O /dev/null --no-check-certificate -S \
                -D $TARGET --method=HEAD "$url" 2>&1 \
                |grep -q '401 Unauthorized' >/dev/null 2>&1
        then
            echo "$url" >> "$RECONDIR"/${TARGET}.urls.401
        fi
    done

    return 0
}
################################################################################

################################################################################
function zapScan()
{
    local url
    local port
    local epoch=$(date +"%s")

    if ! which zap-cli >/dev/null 2>&1
    then
        echo "Installing zap-cli"
        pip install --upgrade zapcli >/dev/null 2>&1
    fi

    pip install --upgrade-strategy=eager zapcli >/dev/null 2>&1 

    # Start a new zap session.  We don't want to interfere with another session
    for port in {8091..8199}
    do 
        if ! zap-cli --api-key notMyPassword -p $port status 2>&1|grep -q "ZAP is running"
        then
            echo "Starting zap proxy on port $port in screen session"
            screen -dmS ${TARGET}.zap${port} /usr/share/zaproxy/zap.sh -daemon -newsession "$RECONDIR"/tmp/zapsession -host localhost -port $port -config api.key=notMyPassword
            sleep 180
            break
        fi
    done

    if zap-cli --api-key notMyPassword -p $port status 2>&1 |grep -q "ZAP is not running"
    then
        echo "Failed to start zap proxy daemon"
        return 1
    fi

    for url in $(cat "$RECONDIR"/${TARGET}.urls)
    do
        # stop and report after 48 hours
        if [[ "$(date +"%s")" -gt "$(($epoch + 172800))" ]]
        then
            break
        fi
        zap-cli --api-key notMyPassword -p $port open-url $url >/dev/null 2>&1
        zap-cli --api-key notMyPassword -p $port active-scan $url >/dev/null 2>&1
    done

    zap-cli --api-key notMyPassword -p $port report --output "$RECONDIR"/${TARGET}.zap.html --output-format html >/dev/null 2>&1

    sleep 60

    screen -ls ${TARGET}.zap${port} |grep ${TARGET}.zap${port} |awk '{print $1}'|cut -d'.' -f1 |xargs kill

    return 0
}
################################################################################

################################################################################
function niktoScan()
{
    local url

    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.nikto
        echo "$url" >> "$RECONDIR"/${TARGET}.nikto
        timeout --kill-after=10 --foreground 3600 \
            nikto -no404 -nointeractive -useragent "$USERAGENT" -host "$url" >>"$RECONDIR"/${TARGET}.nikto 2>&1
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
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.headers
        echo "$url" >> "$RECONDIR"/${TARGET}.headers
        timeout --kill-after=10 --foreground 900 \
            wget -U "$USERAGENT" --tries=20 --retry-connrefused -q -O /dev/null --no-check-certificate -S \
                -D $TARGET --method=OPTIONS "$url" \
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
        skipfish -k 48:00:00 -g1 -f100 -o "$RECONDIR"/${TARGET}.skipfish ${a_urls[*]}
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
    local commonurl

    # Try to find commonality and just attack the top of the list
    # This will avoid attacking the same type of service on multiple urls
    for commonurl in $(cat "$RECONDIR"/${TARGET}.urls.401 |sed -e 's|/[^/]*$|/|g' |sort -u)
    do
        url=$(grep "$commonurl" "$RECONDIR"/${TARGET}.urls.401 |head -1)

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

        (
            # Test with default creds from routersploit and metasploit
            echo "$BORDER"  >> "$RECONDIR"/${TARGET}.hydra/${hydrafile}
            echo "TESTING $url with userpass.lst"  >> "$RECONDIR"/${TARGET}.hydra/${hydrafile}
            timeout --kill-after=10 --foreground 86400 \
                /usr/bin/time -v \
                hydra -I -C "$RECONDIR"/tmp/userpass.lst \
                -u -t 2 $sslflag -s $port $TARGET http-get "$path" \
                >> "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>&1
    
            # Test with separate user/pass files
            echo "$BORDER"  >> "$RECONDIR"/${TARGET}.hydra/${hydrafile}
            echo "TESTING $url with users.lst and passwds.lst"  >> "$RECONDIR"/${TARGET}.hydra/${hydrafile}
            timeout --kill-after=10 --foreground 86400 \
                /usr/bin/time -v \
                hydra -I -L "$RECONDIR"/tmp/users.lst -P "$RECONDIR"/tmp/passwds.lst \
                -e nsr -u -t 5 $sslflag -s $port $TARGET http-get "$path" \
                >> "$RECONDIR"/${TARGET}.hydra/${hydrafile} 2>&1
    
            if grep -q 'successfully completed' "$RECONDIR"/${TARGET}.hydra/${hydrafile}
            then
                cp -f "$RECONDIR"/${TARGET}.hydra/${hydrafile} \
                    "$RECONDIR"/${TARGET}.${hydrafile} 2>/dev/null
            fi
        ) &
    done

    while jobs 2>&1|grep 'hydra' |grep -q 'http-get'
    do
        wait -n $(jobs 2>&1|grep hydra |grep http-get |cut -d'[' -f2|cut -d']' -f1|head -1)
    done

    return 0
}
################################################################################

################################################################################
function sqlmapScan()
{
    local url

    for url in $(awk '/^URL: / {print $2}' "$RECONDIR"/${TARGET}.mech-dump 2>/dev/null |sort -u)
    do
        echo $BORDER >> "$RECONDIR"/tmp/${TARGET}.sqlmap.raw
        echo "# TESTING $url" >> "$RECONDIR"/tmp/${TARGET}.sqlmap.raw
        timeout --kill-after=10 --foreground 1800 \
            /usr/bin/time -v \
            sqlmap --forms --random-agent --batch --flush-session -o --threads=2 -a --technique=BEUSQ -u "$url" 2>&1 \
            |tail -n +7 \
            |sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" \
            |strings -a \
            |egrep -v '^\[\?|\[.*;' \
            >> "$RECONDIR"/tmp/${TARGET}.sqlmap.raw 
        echo $BORDER >> "$RECONDIR"/tmp/${TARGET}.sqlmap.raw 

        # Update $TARGET.sqlmap each round in case we go over time limit and die
        cat "$RECONDIR"/tmp/${TARGET}.sqlmap.raw 2>/dev/null \
            |egrep -v '\[INFO\] (testing|checking|target|flushing|heuristics|confirming|searching|dynamic|URI parameter)|\[WARNING\]|\[CRITICAL\]|shutting down|starting at|do you want to try|legal disclaimer:|404 \(Not Found\)|how do you want to proceed|it is not recommended|do you want sqlmap to try|^\|_|^ ___|^      \||^       __H|^        ___|fetched random HTTP User-Agent|there was an error checking|Do you want to follow|Do you want to try|Method Not Allowed|do you want to skip|\[INFO\] GET parameter .* is dynamic|do you want to |^> Y|as the CSV results file in multiple targets mode|you can find results of scanning in multiple targets mode|\[ERROR\] all tested parameters do not appear to be injectable' \
            |uniq > "$RECONDIR"/${TARGET}.sqlmap 2>&1
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
        timeout --kill-after=10 --foreground 1800 \
            wget -U "$USERAGENT" \
                --tries=20 --retry-connrefused -rq -D $TARGET -O "$RECONDIR"/tmp/wget.dump "$url" \
                >/dev/null 2>&1
        if [[ -f "$RECONDIR"/tmp/wget.dump ]]
        then
            html2dic "$RECONDIR"/tmp/wget.dump 2>/dev/null \
                |grep -v -P '[^\x00-\x7f]' \
                |egrep -E '....' \
                |sort -u \
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
        timeout --kill-after=10 --foreground 90 \
            cewl -d 1 -a --meta_file "$RECONDIR"/tmp/cewl/${TARGET}.${urlfile}.cewlmeta \
            -e --email_file "$RECONDIR"/tmp/cewl/${TARGET}.${urlfile}.cewlemail \
            -u "$USERAGENT" -w "$RECONDIR"/tmp/cewl/${TARGET}.${urlfile}.cewl \
            "$url" >/dev/null 2>&1 
    done

    cat "$RECONDIR"/tmp/cewl/${TARGET}.*.cewl 2>/dev/null |sort -u > "$RECONDIR"/${TARGET}.cewl
    cat "$RECONDIR"/tmp/cewl/${TARGET}.*.cewlemail 2>/dev/null |sort -u > "$RECONDIR"/${TARGET}.cewlemail
    cat "$RECONDIR"/tmp/cewl/${TARGET}.*.cewlmeta 2>/dev/null |sort -u > "$RECONDIR"/${TARGET}.cewlmeta

    return 0
}
################################################################################

################################################################################
function wfuzzURLs()
{
    local a_vars=()
    local file
    local filename
    local fuzzdict
    local i=0
    local IFS=$'\n'
    local ignore
    local inside
    local line
    local method
    local post
    local row=()
    local url
    local var
    local varpass
    local varstring
    local varuser
    local wfuzzfile

    mkdir -p "$RECONDIR"/${TARGET}.wfuzz/raws >/dev/null 2>&1

    # Pull urls from spider scan
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

    # Pull urls from mech-dump
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
            && [[ $url =~ http ]]
            then
                if [[ $line =~ (submit) ]] 
                then
                    var=$(echo $line |awk '{print $1}'|cut -d'=' -f1)
                else 
                    var=$(echo $line |awk '{print $1}'|cut -d'=' -f1)=FUZZ
                fi
                a_vars[${#a_vars[@]}]=$var


                if [[ $var =~ user ]] \
                || [[ $var =~ login ]] \
                || [[ $var =~ name ]] 
                then
                    varuser=$(echo $line |awk '{print $1}'|cut -d'=' -f1)=FUZZ
                fi
                if [[ $line =~ (password) ]]
                then
                    varpass=$(echo $line |awk '{print $1}'|cut -d'=' -f1)=FUZ2Z
                fi
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
                if [[ x$varpass != 'x' ]] \
                && [[ x$varuser != 'x' ]]
                then
                    echo "$varuser&$varpass $url" >> "$RECONDIR"/tmp/${TARGET}.FUZZ.raw.login
                fi
                a_vars=()
                varuser=''
                varpass=''
            fi
        done
    fi

    sort -u "$RECONDIR"/tmp/${TARGET}.FUZZ.raw 2>/dev/null |grep "$TARGET" \
        > "$RECONDIR"/tmp/${TARGET}.FUZZ
    sort -u "$RECONDIR"/tmp/${TARGET}.FUZZ.raw.login 2>/dev/null |grep "$TARGET" \
        > "$RECONDIR"/tmp/${TARGET}.FUZZ.login

    IFS=$'\n'
    i=0
    for line in $(cat "$RECONDIR"/tmp/${TARGET}.FUZZ.login 2>/dev/null)
    do
        post=$(echo $line|awk '{print $1}')
        url=$(echo $line|awk '{print $2}')
        wfuzzfile=$(echo ${url//\//,} |cut -d',' -f1-4 |cut -d';' -f1)

        timeout --kill-after=10 --foreground 1800 \
            wfuzz -o html --hc 404 -t 5 -z file,$RECONDIR/tmp/users.lst \
            -z file,$RECONDIR/tmp/passwds.lst -d $post "$url" \
            >> "$RECONDIR"/${TARGET}.wfuzz/raws/${wfuzzfile}.logins.wfuzz.${i}.html 2>&1

        let i++
    done

    IFS=$'\n'
    i=0
    for line in $(cat "$RECONDIR"/tmp/${TARGET}.FUZZ 2>/dev/null)
    do
        post=$(echo $line|awk '{print $1}')
        url=$(echo $line|awk '{print $2}')
        #url=${url//\&/\\&}
        wfuzzfile=$(echo ${url//\//,} |cut -d',' -f1-4 |cut -d';' -f1)
        wfuzzfile=${wfuzzfile// /,}
        wfuzzfile=${wfuzzfile//-/_}
        wfuzzfile=${wfuzzfile//\"/}
        wfuzzfile=${wfuzzfile//\&/_}

        if [[ $post == "none" ]]
        then
            post=''
        else
            post="-d \"$post\""
        fi

        for fuzzdict in /usr/share/wfuzz/wordlist/vulns/sql_inj.txt \
            /usr/share/wfuzz/wordlist/vulns/dirTraversal-nix.txt \
            /usr/share/wfuzz/wordlist/vulns/dirTraversal-win.txt \
            /usr/share/seclists/Fuzzing/DB2Enumeration.fuzzdb.txt \
            /usr/share/seclists/Fuzzing/Generic-SQLi.txt \
            /usr/share/seclists/Fuzzing/LDAP.Fuzzinging.txt \
            /usr/share/seclists/Fuzzing/MSSQL-Enumeration.fuzzdb.txt \
            /usr/share/seclists/Fuzzing/NoSQL.txt \
            /usr/share/seclists/Fuzzing/Oracle.fuzzdb.txt \
            /usr/share/seclists/Fuzzing/Postgres-Enumeration.fuzzdb.txt \
            /usr/share/seclists/Fuzzing/SSI-Injection-JHADDIX.txt \
            /usr/share/seclists/Fuzzing/XSS-BYPASS-STRINGS-BRUTELOGIC.txt \
            /usr/share/seclists/Fuzzing/XSS-JHADDIX.txt \
            /usr/share/seclists/Fuzzing/XSS-RSNAKE-.txt \
            /usr/share/seclists/Fuzzing/XSS-STRINGS-BRUTELOGIC.txt \
            /usr/share/seclists/Fuzzing/XXE-Fuzzing.txt 
        do
            if [[ ! -f "$fuzzdict" ]]
            then
                echo "ERROR: fuzz dictionary file not found: $fuzzdict"
                continue
            fi
            timeout --kill-after=10 --foreground 1800 \
                wfuzz -o html --hc 404 -t 5 -w $fuzzdict $post "$url" \
                >> "$RECONDIR"/${TARGET}.wfuzz/raws/${wfuzzfile}.${fuzzdict##*/}.wfuzz.${i}.html 2>&1
        done
        let i++
    done

    for file in "$RECONDIR"/${TARGET}.wfuzz/raws/*.wfuzz.*.html
    do
        [[ ! -f "$file" ]] && break

        dos2unix -f "$file" >/dev/null 2>&1
        # change dark theme to light theme
        cat "$file" \
            |sed -e 's/bgcolor=#000000/bgcolor=#FFFFFF/g' \
            |sed -e 's/text=#FFFFFF/text=#000000/g' \
            >> ${file}.1 2>&1
            mv -f ${file}.1 ${file} 2>&1

        # POST wfuzz does multiline.  
        # This will compact the html so we can use the ignore feature.
        if egrep -q '^<td>[[:space:]]*[[:digit:]]+L</td>$' "$file"
        then
            IFS=$'\n'
            inside=0
            row=()
            for line in $(cat "$file")
            do
                if [[ $line =~ ^\<tr\> ]]
                then
                    inside=1
                    row[${#row[@]}]="$line"
                elif [[ $inside == 1 ]]
                then
                    row[${#row[@]}]="$line"
                else
                    echo "$line" >> ${file}.tmp
                fi
                if [[ $line =~ ^\</tr\> ]]
                then
                    row[${#row[@]}]="$line"
                    echo "${row[@]}" >> ${file}.tmp
                    echo "" >> ${file}.tmp
                    row=()
                    inside=0
                fi
            done
            mv ${file}.tmp ${file} >/dev/null 2>&1
        fi

        ignore=$(cat "$file" \
            |egrep -E "\d*L" \
            |sed -e 's/.*[^0-9]\([0-9]*L\).*[^0-9]\([0-9]*W\).*/\1 \2/'\
            |sort \
            |uniq -c \
            |sort -k1 -n \
            |tail -1 \
            |awk '{print $2".*"$3}')

        filename=${file##*/}
        echo "$ignore" >> "${file}.ignored"
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
        |egrep -v '/\?C=' \
        |tr -d '\0')
    do
        output=$(timeout --kill-after=10 --foreground 90 \
            mech-dump --agent "$USERAGENT" --absolute --forms "$url" 2>/dev/null)
        if [[ ${#output} -gt 0 ]]
        then
            echo "$BORDER" >> "$RECONDIR"/${TARGET}.mech-dump
            echo "URL: $url" >> "$RECONDIR"/${TARGET}.mech-dump
            echo "$output" >> "$RECONDIR"/${TARGET}.mech-dump
        fi
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
        timeout --kill-after=10 --foreground 90 \
            davtest -cleanup -url "$url" 2>&1|grep SUCCEED >> "$RECONDIR"/${TARGET}.davtest
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.davtest 

        echo "$BORDER" >> "$RECONDIR"/${TARGET}.cadaver 
        echo "TESTING $url" >> "$RECONDIR"/${TARGET}.cadaver 
        echo ls | timeout --kill-after=10 --foreground 90 \
            cadaver "$url" 2>&1 \
            |egrep -v 'command can only be used when connected to the server.|^Try running|^Could not access|^405 Method|^Connection to' \
            >> "$RECONDIR"/${TARGET}.cadaver
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.cadaver 

        port=$(getPortFromUrl "$url")
        output=$(timeout --kill-after=10 --foreground 90 nmap -T2 -p $port -Pn \
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
        timeout --kill-after=10 --foreground 90 \
            wget -U "$USERAGENT" --tries=20 --retry-connrefused -q --no-check-certificate \
                -D $TARGET -O /tmp/${TARGET}.exiftestfile "$url"
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

################################################################################
function wigScan()
{
    local url

    for url in $(cat "$RECONDIR"/${TARGET}.baseurls 2>/dev/null)
    do
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.wig 
        echo "Testing $url" >> "$RECONDIR"/${TARGET}.wig 
        timeout --kill-after=10 --foreground 1800 \
            /usr/bin/time -v \
            wig -q -t 1 -a -d $url 2>&1 \
            |sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" \
            |strings -a \
            >> "$RECONDIR"/${TARGET}.wig 
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.wig 
    done

    return 0
}
################################################################################

################################################################################
function scanURLs()
{
    local url

    screen -dmS ${TARGET}.urlsew.$RANDOM timeout --kill-after=10 --foreground 172800 \
        eyewitness --user-agent "$USERAGENT" --threads 2 -d "$RECONDIR"/${TARGET}.urlsEyeWitness \
        --max-retries 10 --timeout 20 \
        --no-dns --no-prompt --headless -f "$RECONDIR"/${TARGET}.urls

    # run whatweb on top dirs
    for url in $(egrep '/$' "$RECONDIR"/${TARGET}.urls)
    do
        if [[ "$(echo $url |grep -o '.' |grep -c '/')" -le 4 ]] \
        && ! egrep -q "^$url" "$RECONDIR"/${TARGET}.whatweb 2>/dev/null
        then
            timeout --kill-after=10 --foreground 3600 \
                whatweb -U "$USERAGENT" -a3 -t2 --color=never "$url" \
                |strings -a \
                >> "$RECONDIR"/${TARGET}.whatweb 2>/dev/null
            echo '' >> "$RECONDIR"/${TARGET}.whatweb 2>/dev/null
        fi
    done

    # run wpscan on first found wordpress
    for url in $(egrep -i 'wordpress|/wp' "$RECONDIR"/${TARGET}.whatweb 2>/dev/null |head -1 |awk '{print $1}')
    do
        echo "Running wpscan on $url"
        echo "... outputs $RECONDIR/$TARGET.wpscan"
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.wpscan
        echo "URL: $url" >> "$RECONDIR"/${TARGET}.wpscan
        timeout --kill-after=10 --foreground 1800 \
            /usr/bin/time -v \
            wpscan -a "$USERAGENT" -r -t3 --follow-redirection --disable-tls-checks -e \
            --no-banner --no-color --batch --url "$url" \
            |strings -a \
            >> "$RECONDIR"/${TARGET}.wpscan 2>&1 

        echo "Running wpscan admin crack on $url"
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.wpscan
        echo "CRACKING ADMIN FOR URL: $url" >> "$RECONDIR"/${TARGET}.wpscan
        timeout --kill-after=10 --foreground 1800 \
            /usr/bin/time -v \
            wpscan -a "$USERAGENT" -r -t 3 --disable-tls-checks --wordlist "$RECONDIR"/tmp/passwds.lst \
            --username admin --url "$url" \
            |strings -a \
            >> "$RECONDIR"/${TARGET}.wpscan 2>&1
    done

    # run joomscan on first found joomla
    for url in $(grep -i joomla "$RECONDIR"/${TARGET}.whatweb 2>/dev/null |head -1 |awk '{print $1}')
    do
        echo "Running joomscan on $url"
        echo "... outputs $RECONDIR/$TARGET.joomscan"
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.joomscan
        echo "URL: $url" >> "$RECONDIR"/${TARGET}.joomscan
        timeout --kill-after=10 --foreground 1800 \
            /usr/bin/time -v \
            joomscan -ec -r -a "$USERAGENT" -u "$url" \
            |sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" \
            |strings -a \
            >> "$RECONDIR"/${TARGET}.joomscan 2>&1 
    done

    return 0
}
################################################################################

################################################################################
function fimapScan()
{
    local url

    # run fimap on anything with php
    for url in $(egrep -i '\.php$' "$RECONDIR"/${TARGET}.urls |awk '{print $1}')
    do
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.fimap
        echo "URL: $url" >> "$RECONDIR"/${TARGET}.fimap
        timeout --kill-after=10 --foreground 900 \
            echo '' \
            |fimap --force-run -4 -A "$USERAGENT" -u "$url" 2>/dev/null \
            |egrep -v '^fimap |^Another fimap|^:: |^Starting harvester|^No links found|^AutoAwesome is done' \
            |strings -a \
            >> "$RECONDIR"/${TARGET}.fimap
    done

    return 0
}
################################################################################

################################################################################
function mesosScan()
{
    local port=$1
    local cmd
    local output

    for cmd in version env trace health status info flags features dump system/stats metrics/snapshot
    do
        output=$(timeout --kill-after=10 --foreground 1800 \
            curl -A "$USERAGENT" \
                --retry 20 --retry-connrefused -k -s http://${TARGET}:${port}/$cmd 2>/dev/null \
                |jq -M . 2>&1)
        if [[ ${#output} -gt 0 ]] \
        && [[ ! "$output" =~ .status.:.404, ]]
        then
            cmd=${cmd/\//-}
            echo "$output" > "$RECONDIR"/${TARGET}.${port}.mesos.${cmd}
        fi
    done

    return 0
}
################################################################################

################################################################################
function zookeeperScan()
{
    local port=$1
    local cmd

    for cmd in envi stat req dump
    do
        echo $cmd |ncat ${TARGET} $port >"$RECONDIR"/${TARGET}.${port}.zookeeper.${cmd} 2>&1
    done

    return 0
}
################################################################################

################################################################################
function memcacheScan()
{
    local cmdfile="$RECONDIR"/tmp/memcached.${port}.metasploit
    local port=$1

    echo "color false" > $cmdfile
    echo "use auxiliary/gather/memcached_extractor" >> $cmdfile
    echo "set RHOSTS $TARGET" >> $cmdfile
    echo "set RHOST $TARGET" >> $cmdfile
    echo "set RPORT $TARGET" >> $cmdfile
    echo "set VERBOSE false" >> $cmdfile
    echo "set UserAgent $USERAGENT" >> $cmdfile
    echo "run" >> $cmdfile
    echo "exit" >> $cmdfile

    timeout --kill-after=10 --foreground 3600 \
        /usr/share/metasploit-framework/msfconsole -q -n -r $cmdfile -o "$RECONDIR"/tmp/${TARGET}.memcached.${port}.msf.raw >/dev/null 2>&1

    # strip hex and convert newlines to real newlines
    perl -pi -e 's|\\r\\n|\n|g' "$RECONDIR"/tmp/${TARGET}.memcached.${port}.msf.raw
    perl -pi -e 's|\\x..| |g' "$RECONDIR"/tmp/${TARGET}.memcached.${port}.msf.raw

    cat "$RECONDIR"/tmp/${TARGET}.memcached.${port}.msf.raw 2>&1 \
        |egrep -v '^resource \(|\[\*\] exec:|Did you mean RHOST|^THREADS|^VERBOSE|^RPORT|^RHOST|^SSL |^UserAgent |^\[\*\].* module execution completed|^\[\*\] Scanned 1 of 1 hosts' \
        > "$RECONDIR"/${TARGET}.memcached.${port}.msf

    return 0
}
################################################################################

################################################################################
function ipmiScan()
{
    local cmdfile="$RECONDIR"/tmp/ipmi.metasploit

    echo "color false" > $cmdfile
    echo "use auxiliary/scanner/ipmi/ipmi_dumphashes" >> $cmdfile
    echo "set RHOSTS $TARGET" >> $cmdfile
    echo "set RHOST $TARGET" >> $cmdfile
    echo "set OUTPUT_HASHCAT_FILE $RECONDIR/${TARGET}.ipmi.hashcat" >> $cmdfile
    echo "set OUTPUT_JOHN_FILE $RECONDIR/${TARGET}.ipmi.john" >> $cmdfile
    echo "run" >> $cmdfile
    echo "exit" >> $cmdfile

    timeout --kill-after=10 --foreground 900 \
        /usr/share/metasploit-framework/msfconsole -q -n -r $cmdfile >"$RECONDIR"/tmp/msf.ipmi.out 2>&1

    if [[ -f $RECONDIR/${TARGET}.ipmi.john ]]
    then
        timeout --kill-after=10 --foreground 86400 \
            john --wordlist=$RECONDIR/tmp/passwds.lst --rules=Single $RECONDIR/${TARGET}.ipmi.john \
            >>"$RECONDIR"/tmp/ipmi.john.out 2>&1
        timeout --kill-after=10 --foreground 86400 \
            john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Single $RECONDIR/${TARGET}.ipmi.john \
            >>"$RECONDIR"/tmp/ipmi.john.out 2>&1
        john --show $RECONDIR/${TARGET}.ipmi.john >$RECONDIR/${TARGET}.ipmi.john.cracked 2>&1
    fi

    return 0
}
################################################################################

################################################################################
function msfRMIScan()
{
    local port
    local cmdfile="$RECONDIR/tmp/rmiscanscript"
    local msfscan

    echo "color false" > $cmdfile
    for msfscan in auxiliary/gather/java_rmi_registry auxiliary/scanner/misc/java_rmi_server
    do
        for port in ${RMIPORTS[@]}
        do
            echo "echo \"$BORDER\"" >> "$cmdfile"
            echo "echo 'TESTING $TARGET:$port WITH $msfscan'" >> "$cmdfile"
            echo "use $msfscan" >> "$cmdfile"
            echo "set RPORT $port" >> "$cmdfile"
            echo "set RHOSTS $TARGET" >> "$cmdfile"
            echo "set RHOST $TARGET" >> $cmdfile
            echo "set VERBOSE false" >> $cmdfile
            echo "set UserAgent $USERAGENT" >> $cmdfile
            echo "run" >> "$cmdfile"
            echo "echo ''" >> "$cmdfile"
        done
    done
    echo "exit" >> "$cmdfile"


    timeout --kill-after=10 --foreground 3600 \
        /usr/share/metasploit-framework/msfconsole -q -n -r $cmdfile -o "$RECONDIR"/tmp/${TARGET}.rmi.msf.raw >/dev/null 2>&1

    cat "$RECONDIR"/tmp/${TARGET}.rmi.msf.raw 2>&1 \
        |egrep -v '^resource \(|\[\*\] exec:|Did you mean RHOST|^THREADS|^VERBOSE|^RPORT|^RHOST|^SSL |^UserAgent |^\[\*\].* module execution completed|^\[\*\] Scanned 1 of 1 hosts' \
        > "$RECONDIR"/${TARGET}.rmi.msf

    return 0
}
################################################################################

################################################################################
function msfHttpScan()
{
    local httpscans=()
    local msfscan
    local port
    local url
    local ssl
    local cmdfile="$RECONDIR/tmp/msfHttpScanScript"

    for msfscan in $(/usr/share/metasploit-framework/msfconsole -q -n \
        -x 'search auxiliary/scanner/http/; exit' \
        |awk '{print $1}' \
        |grep 'auxiliary/scanner/http/' \
        |egrep -v 'brute|udp_amplification|_amp$|dir_webdav_unicode_bypass|http/xpath|http/hp_' \
        )
    do
        httpscans[${#httpscans[@]}]=$msfscan
    done

    echo "color false" > $cmdfile

    IFS=$'\n'
    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        if [[ $url =~ ^https ]]
        then
            ssl='true'
        else
            ssl='false'
        fi
        port=${url##*:}
        for msfscan in ${httpscans[@]}
        do
            echo "echo \"$BORDER\"" >> "$cmdfile"
            echo "echo 'TESTING $url WITH $msfscan'" >> "$cmdfile"
            echo "use $msfscan" >> "$cmdfile"
            echo "set RPORT $port" >> "$cmdfile"
            echo "set RHOSTS $TARGET" >> "$cmdfile"
            echo "set RHOST $TARGET" >> $cmdfile
            echo "set SSL $ssl" >> "$cmdfile"
            echo "set VERBOSE false" >> $cmdfile
            echo "set THREADS 2" >> $cmdfile
            echo "set UserAgent $USERAGENT" >> $cmdfile
            echo "run" >> "$cmdfile"
            echo "echo ''" >> "$cmdfile"
        done
    done
    echo "exit" >> "$cmdfile"

    timeout --kill-after=10 --foreground 172800 \
        /usr/share/metasploit-framework/msfconsole -q -n -r $cmdfile -o "$RECONDIR"/tmp/${TARGET}.http.msf.raw >/dev/null 2>&1

    cat "$RECONDIR"/tmp/${TARGET}.http.msf.raw 2>&1 \
        |egrep -v '^resource \(|\[\*\] exec:|Did you mean RHOST|^THREADS|^VERBOSE|^RPORT|^RHOST|^SSL |^UserAgent |^\[\*\].* module execution completed|^\[\*\] Scanned 1 of 1 hosts' \
        > "$RECONDIR"/${TARGET}.http.msf

    return 0
}
################################################################################

################################################################################
function msfHPScan()
{
    local hpcans=()
    local msfscan
    local port
    local cmdfile="$RECONDIR/tmp/msfHPScanScript"

    for msfscan in $(/usr/share/metasploit-framework/msfconsole -q -n \
        -x 'search auxiliary/scanner/http/; exit' \
        |grep 'http/hp_' \
        |awk '{print $1}')
    do
        hpscans[${#hpscans[@]}]=$msfscan
    done

    echo "color false" > $cmdfile

    for msfscan in ${hpscans[@]}
    do
        for port in ${HTTPSPORTS[@]}
        do
            echo "echo \"$BORDER\"" >> "$cmdfile"
            echo "echo 'TESTING $TARGET:$port WITH $msfscan'" >> "$cmdfile"
            echo "use $msfscan" >> "$cmdfile"
            echo "set RPORT $port" >> "$cmdfile"
            echo "set RHOSTS $TARGET" >> "$cmdfile"
            echo "set RHOST $TARGET" >> $cmdfile
            echo "set SSL true" >> "$cmdfile"
            echo "set VERBOSE false" >> $cmdfile
            echo "set UserAgent $USERAGENT" >> $cmdfile
            echo "run" >> "$cmdfile"
            echo "echo ''" >> "$cmdfile"
        done
        for port in ${HTTPPORTS[@]}
        do
            echo "echo \"$BORDER\"" >> "$cmdfile"
            echo "echo 'TESTING $TARGET:$port WITH $msfscan'" >> "$cmdfile"
            echo "use $msfscan" >> "$cmdfile"
            echo "set RPORT $port" >> "$cmdfile"
            echo "set RHOSTS $TARGET" >> "$cmdfile"
            echo "set RHOST $TARGET" >> $cmdfile
            echo "set SSL false" >> "$cmdfile"
            echo "set VERBOSE false" >> $cmdfile
            echo "set UserAgent $USERAGENT" >> $cmdfile
            echo "run" >> "$cmdfile"
            echo "echo ''" >> "$cmdfile"
        done
    done
    echo "exit" >> "$cmdfile"

    timeout --kill-after=10 --foreground 172800 \
        /usr/share/metasploit-framework/msfconsole -q -n -r $cmdfile -o "$RECONDIR"/tmp/${TARGET}.hp.msf.raw >/dev/null 2>&1

    cat "$RECONDIR"/tmp/${TARGET}.hp.msf.raw 2>&1 \
        |egrep -v '^resource \(|\[\*\] exec:|Did you mean RHOST|^THREADS|^VERBOSE|^RPORT|^RHOST|^SSL |^UserAgent |^\[\*\].* module execution completed|^\[\*\] Scanned 1 of 1 hosts' \
        > "$RECONDIR"/${TARGET}.hp.msf

    return 0
}
################################################################################

################################################################################
function msfSapScan()
{
    local sapscans=()
    local msfscan
    local port
    local cmdfile="$RECONDIR/tmp/msfSapScanScript"

    for msfscan in $(/usr/share/metasploit-framework/msfconsole -q -n \
        -x 'search auxiliary/scanner/sap/; exit' \
        |grep 'auxiliary/scanner/sap/' \
        |awk '{print $1}')
    do
        sapscans[${#sapscans[@]}]=$msfscan
    done

    echo "color false" > $cmdfile

    for msfscan in ${sapscans[@]}
    do
        for port in ${HTTPSPORTS[@]}
        do
            echo "echo \"$BORDER\"" >> "$cmdfile"
            echo "echo 'TESTING $TARGET:$port WITH $msfscan'" >> "$cmdfile"
            echo "use $msfscan" >> "$cmdfile"
            echo "set RPORT $port" >> "$cmdfile"
            echo "set RHOSTS $TARGET" >> "$cmdfile"
            echo "set RHOST $TARGET" >> $cmdfile
            echo "set SSL true" >> "$cmdfile"
            echo "set VERBOSE false" >> $cmdfile
            echo "set UserAgent $USERAGENT" >> $cmdfile
            echo "run" >> "$cmdfile"
            echo "echo ''" >> "$cmdfile"
        done
        for port in ${HTTPPORTS[@]}
        do
            echo "echo \"$BORDER\"" >> "$cmdfile"
            echo "echo 'TESTING $TARGET:$port WITH $msfscan'" >> "$cmdfile"
            echo "use $msfscan" >> "$cmdfile"
            echo "set RPORT $port" >> "$cmdfile"
            echo "set RHOSTS $TARGET" >> "$cmdfile"
            echo "set RHOST $TARGET" >> $cmdfile
            echo "set SSL false" >> "$cmdfile"
            echo "set VERBOSE false" >> $cmdfile
            echo "set UserAgent $USERAGENT" >> $cmdfile
            echo "run" >> "$cmdfile"
            echo "echo ''" >> "$cmdfile"
        done
    done
    echo "exit" >> "$cmdfile"

    timeout --kill-after=10 --foreground 172800 \
        /usr/share/metasploit-framework/msfconsole -q -n -r $cmdfile -o "$RECONDIR"/tmp/${TARGET}.sap.msf.raw >/dev/null 2>&1

    cat "$RECONDIR"/tmp/${TARGET}.sap.msf.raw 2>&1 \
        |egrep -v '^resource \(|\[\*\] exec:|Did you mean RHOST|^THREADS|^VERBOSE|^RPORT|^RHOST|^SSL |^UserAgent |^\[\*\].* module execution completed|^\[\*\] Scanned 1 of 1 hosts' \
        > "$RECONDIR"/${TARGET}.sap.msf

    return 0
}
################################################################################

################################################################################
function msfJuniperScan()
{
    local msfscan
    local cmdfile="$RECONDIR"/tmp/juniper.msf

    echo "color false" > $cmdfile
    echo "use auxiliary/scanner/ssh/juniper_backdoor" >> "$cmdfile"
    echo "set RHOST $TARGET" >> "$cmdfile"
    echo "set RHOSTS $TARGET" >> "$cmdfile"
    echo "set VERBOSE false" >> $cmdfile
    echo "set UserAgent $USERAGENT" >> $cmdfile
    echo "run" >> "$cmdfile"
    echo "exit" >> "$cmdfile"

    timeout --kill-after=10 --foreground 3600 \
        /usr/share/metasploit-framework/msfconsole -q -n -r $cmdfile -o "$RECONDIR"/${TARGET}.juniper.msf \
        >/dev/null 2>&1

    return 0
}
################################################################################

################################################################################
function msfCiscoScan()
{
    local msfscan
    local cmdfile="$RECONDIR"/tmp/cisco.msf

    echo "color false" > $cmdfile

    for msfscan in \
        auxiliary/admin/cisco/cisco_asa_extrabacon \
        auxiliary/admin/cisco/cisco_secure_acs_bypass \
        auxiliary/admin/cisco/vpn_3000_ftp_bypass \
        auxiliary/admin/scada/moxa_credentials_recovery \
        auxiliary/scanner/dlsw/dlsw_leak_capture \
        auxiliary/scanner/http/cisco_asa_asdm \
        auxiliary/scanner/http/cisco_device_manager \
        auxiliary/scanner/http/cisco_firepower_download \
        auxiliary/scanner/http/cisco_firepower_login \
        auxiliary/scanner/http/cisco_ios_auth_bypass \
        auxiliary/scanner/http/cisco_ironport_enum \
        auxiliary/scanner/http/cisco_nac_manager_traversal \
        auxiliary/scanner/http/cisco_ssl_vpn \
        auxiliary/scanner/http/cisco_ssl_vpn_priv_esc \
        auxiliary/scanner/http/linksys_e1500_traversal \
        auxiliary/scanner/ike/cisco_ike_benigncertain \
        auxiliary/scanner/misc/cisco_smart_install \
        auxiliary/scanner/snmp/cisco_config_tftp \
        auxiliary/scanner/snmp/cisco_upload_file
    do
        echo "echo \"$BORDER\"" >> "$cmdfile"
        echo "echo 'TESTING $TARGET WITH $msfscan'" >> "$cmdfile"
        echo "use $msfscan" >> "$cmdfile"
        echo "set RHOST $TARGET" >> "$cmdfile"
        echo "set RHOSTS $TARGET" >> "$cmdfile"
        echo "set VERBOSE false" >> $cmdfile
        echo "set UserAgent $USERAGENT" >> $cmdfile
        echo "run" >> "$cmdfile"
        echo "echo ''" >> "$cmdfile"
    done
    echo "exit" >> "$cmdfile"

    timeout --kill-after=10 --foreground 172800 \
        /usr/share/metasploit-framework/msfconsole -q -n -r $cmdfile -o "$RECONDIR"/tmp/${TARGET}.cisco.msf.raw >/dev/null 2>&1

    cat "$RECONDIR"/tmp/${TARGET}.cisco.msf.raw 2>&1 \
        |egrep -v '^resource \(|\[\*\] exec:|Did you mean RHOST|^THREADS|^VERBOSE|^RPORT|^RHOST|^SSL |^UserAgent |^\[\*\].* module execution completed|^\[\*\] Scanned 1 of 1 hosts' \
        > "$RECONDIR"/${TARGET}.cisco.msf

    return 0
}
################################################################################

################################################################################
function tnscmd10gScan()
{
    local port=$1

    timeout --kill-after=10 --foreground 7200 \
        tnscmd10g -h ${TARGET} -p $port >"$RECONDIR"/${TARGET}.oracle.tnscmd10g.$port 2>&1

    return 0
}
################################################################################

################################################################################
function WAScan()
{
    local url
    local scan

    if [[ ! -d /tmp/WAScan ]]
    then
        git clone https://github.com/m4ll0k/WAScan /tmp/WAScan >/dev/null 2>&1
    fi

    if [[ ! -f /tmp/WAScan/wascan.py ]]
    then
        echo "FAILED TO GIT CLONE WAScan"
        return 1
    fi

    chmod -R 700 /tmp/WAScan

    pip install -r /tmp/WAScan/requirements.txt >/dev/null 2>&1

    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        port=${url##*:}
        echo "$BORDER"  >> "$RECONDIR"/${TARGET}.${port}.WAScan
        echo "TESTING $url"  >> "$RECONDIR"/${TARGET}.${port}.WAScan
        timeout --kill-after=10 --foreground 14400 \
            /usr/bin/time -v \
            /tmp/WAScan/wascan.py -A "$USERAGENT" -n -r --url "$url" 2>&1 \
            |tail -n +11 \
            |sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" \
            |strings -a \
            |uniq \
            >> "$RECONDIR"/${TARGET}.${port}.WAScan 
    done

    return 0
}
################################################################################

################################################################################
function badKeyScan()
{
    local yml
    local key
    local user
    local port

    if [[ ! -d /tmp/ssh-badkeys/authorized ]]
    then
        git clone https://github.com/rapid7/ssh-badkeys /tmp/ssh-badkeys >/dev/null 2>&1
    fi
    if [[ ! -d /tmp/ssh-badkeys/authorized ]]
    then
        echo "FAILED TO GIT CLONE ssh-badkeys"
        return 1
    fi
    chmod -R 700 /tmp/ssh-badkeys
    for yml in /tmp/ssh-badkeys/authorized/*.yml
    do
        key=${yml/.yml/}.key
        port=$(cat $yml |awk '/^:port: / {print $2}')
        user=$(cat $yml |awk '/^:user: / {print $2}')

        # Run ssh with verbose.  
        # If it gets to the "Sending command", then key was successful
        if timeout --kill-after=10 --foreground 300 \
            ssh -o PasswordAuthentication=no -o BatchMode=yes -v -p $port -i $key -l $user $TARGET 'uname' 2>&1|grep -q 'Sending command:'
        then
            echo "FOUND KEY WITH $yml" >> $RECONDIR/${TARGET}.ssh.badKeys
        fi
    done

    return 0
}
################################################################################

################################################################################
function crackers()
{
    screen -dmS ${TARGET}.ncrack.$RANDOM -L -Logfile "$RECONDIR"/${TARGET}.ncrack \
        timeout --kill-after=10 --foreground 172800 \
        ncrack -iN "$RECONDIR"/${TARGET}.nmap -U "$RECONDIR"/tmp/users.lst \
        -P "$RECONDIR"/tmp/passwds.lst -v -g CL=2,cr=5,to=47h

    # brutespray uses service-specific wordlists in /usr/share/brutespray/wordlist
    timeout --kill-after=10 --foreground 172800 \
        brutespray --file "$RECONDIR"/${TARGET}.ngrep --threads 2 -c -o "$RECONDIR"/${TARGET}.brutespray.d >/dev/null 2>&1

    return 0
}
################################################################################

################################################################################
function wafw00fScan()
{
    local url

    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        echo "$BORDER" >> "$RECONDIR"/${TARGET}.wafw00f
        echo "TESTING $url" >> "$RECONDIR"/${TARGET}.wafw00f
        timeout --kill-after 10 --foreground 14400 \
            wafw00f "$url" >> "$RECONDIR"/${TARGET}.wafw00f 2>&1
    done

    return 0
}
################################################################################

################################################################################
function wapitiScan()
{
    local url
    local port

    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        port=${url##*:}
        timeout --kill-after 10 --foreground 14400 \
            wapiti "$url" -o "$RECONDIR"/${TARGET}.${port}.wapiti -f html \
            > "$RECONDIR"/tmp/wapiti.${port}.out 2>&1
    done

    return 0
}
################################################################################

################################################################################
function arachniScan()
{
    local url
    local count=0
    local i=0
    local file
    local report

    mkdir -p "$RECONDIR"/${TARGET}-arachni.d >/dev/null 2>&1
    mkdir -p "$RECONDIR"/tmp/arachni.d >/dev/null 2>&1

    for url in $(cat "$RECONDIR"/${TARGET}.baseurls)
    do
        let count++
        timeout --kill-after 10 --foreground 172800 \
            arachni --http-user-agent "$USERAGENT" --audit-links --audit-forms --audit-ui-forms \
            --audit-ui-inputs --audit-xmls --audit-jsons --timeout=47:30:0 --output-only-positives \
            --http-request-concurrency=1 --report-save-path="$RECONDIR"/tmp/arachni.d $url \
            >"$RECONDIR"/tmp/arachni.$count.out 2>&1 &
    done

    while jobs 2>&1|grep -q 'arachni'
    do
        wait -n $(jobs 2>&1|grep arachni |cut -d'[' -f2|cut -d']' -f1|head -1)
    done

    i=0
    for file in "$RECONDIR"/tmp/arachni.d/*.afr
    do
        # arachni_reporter outputs to a zip file in /usr/share/arachni/bin
        # I hope they fix this bug someday
        let i++
        report=$(arachni_reporter  --reporter html "$file" 2>&1 |grep 'HTML: Saved in' |cut -d"'" -f2)
        unzip -d "$RECONDIR"/${TARGET}-arachni.d/$i /usr/share/arachni/bin/"$report" >/dev/null 2>&1
        rm -f /usr/share/arachni/bin/"$report" >/dev/null 2>&1
    done

    return 0
}
################################################################################

################################################################################
function portcheck()
{
    local port=$1
    local array=$2
    local pc

    for pc in ${array[@]}
    do
        if [[ $port == $pc ]]
        then
            return 1
        fi
    done

    return 0
}
################################################################################

################################################################################
function domainNameScan()
{
    local domain
    local record

    if [[ ${TARGET} =~ [a-zA-Z] ]]
    then
        if [[ $(echo $TARGET |grep -o '.' |grep -c '\.') -eq 1 ]]
        then
            domain=$TARGET
        elif [[ $(echo $TARGET |grep -o '.' |grep -c '\.') -ge 2 ]]
        then
            domain=${TARGET#*.}
        elif [[ $(echo $TARGET |grep -o '.' |grep -c '\.') -eq 0 ]]
        then
            return 1
        fi
    else
        return 1
    fi

    echo "$BORDER" >>"$RECONDIR"/${TARGET}.dnsinfo
    echo "host -a ${TARGET}" >>"$RECONDIR"/${TARGET}.dnsinfo
    host -a ${TARGET} >>"$RECONDIR"/${TARGET}.dnsinfo 2>&1

    echo "$BORDER" >>"$RECONDIR"/${TARGET}.dnsinfo >>"$RECONDIR"/${TARGET}.dnsinfo
    echo "host -a $domain" >>"$RECONDIR"/${TARGET}.dnsinfo
    host -a $domain >>"$RECONDIR"/${TARGET}.dnsinfo 2>&1

    echo "$BORDER" >>"$RECONDIR"/${TARGET}.dnsinfo >>"$RECONDIR"/${TARGET}.dnsinfo
    echo "host -t MX $domain" >>"$RECONDIR"/${TARGET}.dnsinfo
    host -t MX $domain >>"$RECONDIR"/${TARGET}.dnsinfo 2>&1

    echo "$BORDER" >>"$RECONDIR"/${TARGET}.dnsinfo >>"$RECONDIR"/${TARGET}.dnsinfo
    echo "host -t TXT $domain" >>"$RECONDIR"/${TARGET}.dnsinfo
    host -t TXT $domain >>"$RECONDIR"/${TARGET}.dnsinfo 2>&1

    echo "$BORDER" >>"$RECONDIR"/${TARGET}.dnsinfo >>"$RECONDIR"/${TARGET}.dnsinfo
    echo "host -t TXT _kerberos.$domain" >>"$RECONDIR"/${TARGET}.dnsinfo
    host -t TXT _kerberos.$domain >>"$RECONDIR"/${TARGET}.dnsinfo 2>&1

    for record in \
        _aix._tcp \
        _autodiscover._tcp \
        _caldavs._tcp \
        _caldav._tcp \
        _carddavs._tcp \
        _carddav._tcp \
        _ceph-mon_.tcp \
        _certificates._tcp \
        _citrixreceiver._tcp \
        _cmp._tcp \
        _crls._tcp \
        _crl._tcp \
        _finger._tcp \
        _ftp._tcp \
        gc._msdcs \
        _gc._tcp \
        _h323be._tcp \
        _h323be._udp \
        _h323cs._tcp \
        _h323cs._udp \
        _h323ls._tcp \
        _h323ls._udp \
        _h323rs._udp \
        _hkps._tcp \
        _hkp._tcp \
        _https._tcp \
        _http._tcp \
        _imap._tcp \
        _imap.tcp \
        _jabber-client._tcp \
        _jabber-client._udp \
        _jabber._tcp \
        _jabber._udp \
        _kerberos-master._tcp \
        _kerberos-master._udp \
        _kerberos._tcp \
        _kerberos._tcp.dc._msdcs \
        _kerberos.tcp.dc._msdcs \
        _kerberos._udp \
        _kpasswd._tcp \
        _kpasswd._udp \
        _ldap._tcp \
        _ldap._tcp.dc._msdcs \
        _ldap._tcp.ForestDNSZones \
        _ldap._tcp.gc._msdcs \
        _ldap._tcp.pdc._msdcs \
        _matrix._tcp \
        _minecraft._tcp \
        _nntp._tcp \
        _ocsp._tcp \
        _pexapp._tcp \
        _pgpkeys._tcp \
        _pgprevokations._tcp \
        _PKIXREP._tcp \
        _sipfederationtls._tcp \
        _sipinternal._tcp \
        _sipinternaltls._tcp \
        _sips._tcp \
        _sip._tcp \
        _sip._tls \
        _sip._udp \
        _smtp._tcp \
        _stun._tcp \
        _stun._udp \
        _svcp._tcp \
        _telnet._tcp \
        _test._tcp \
        _turns._tcp \
        _turn._tcp \
        _turn._udp \
        _whois._tcp \
        _xmpp-client._tcp \
        _xmpp-client._udp \
        _xmpp-server._tcp \
        _xmpp-server._udp \
        _x-puppet._tcp \
        _ntp._udp 
    do
        if ! host -t SRV $record.$domain 2>&1 |grep -q NXDOMAIN
        then
            echo "$BORDER" >>"$RECONDIR"/${TARGET}.dnsinfo
            echo "host -t SRV $record.$domain" >>"$RECONDIR"/${TARGET}.dnsinfo
            host -t SRV $record.$domain >>"$RECONDIR"/${TARGET}.dnsinfo 2>&1
        fi
    done

    return 0
}
################################################################################

################################################################################
function defaultCreds()
{
    local IFS=$'\n'
    local name
    local defpassfile='/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv'
    local logfile="$RECONDIR"/${TARGET}.defaultCreds

    for name in $(cat $defpassfile \
        |dos2unix -f |cut -d',' -f1 |tr '[A-Z]' '[a-z]' |sed -e 's/"//g' |sort -u)
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

export PYTHONHTTPSVERIFY=0
export PERL_LWP_SSL_VERIFY_HOSTNAME=0
shopt -s nocasematch

MAIN $*
stty sane >/dev/null 2>&1

set > /tmp/set2

