#!/bin/bash

umask 077

HTTPPORTS=()
HTTPSPORTS=()
NONSSLPORTS=()
portinfo=()
SSLPORTS=()
USERAGENT='Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/5.0)'


IFS=$'\n'
for line in $(cat "$1" |egrep '\sPorts:\s')
do
    ip=$(echo $line|awk '{print $2}')
    for ports in $(echo $line |egrep '\sPorts:\s' |sed -e 's/.*Ports: //')
    do   
        IFS=','
        for fields in $ports
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
        
            if [[ $state =~ filtered ]] \
            || [[ $version =~ Splunkd ]] \
            || [[ $protocol == 'udp' ]]  \
        	|| [[ $service == 'ftp' ]] \
        	|| [[ $service == 'ssh' ]] \
        	|| [[ $port == '3389' ]] \
        	|| [[ $service == 'smtp' ]] \
        	|| [[ $service == 'rpcbind' ]] \
        	|| [[ $service == 'msrpc' ]] \
        	|| [[ $service == 'microsoft-ds' ]] \
        	|| [[ $service == 'netbios-ssn' ]] \
        	|| [[ $service == 'telnet' ]] \
        	|| [[ $service == 'ms-sql' ]] \
        	|| [[ $service == 'mysql' ]] \
        	|| [[ $service == 'oracle-tns' ]] \
        	|| [[ $service =~ 'cassandra' ]] \
        	|| [[ $service == 'vnc' ]] \
        	|| [[ $service == 'mountd' ]] \
        	|| [[ $service == 'nfs' ]] \
        	|| [[ $service =~ mongodb ]] \
        	|| [[ $service =~ memcached ]] \
        	|| [[ $service =~ rtsp ]]
            then 
                continue
            fi   
        
            # web
            if [[ $protocol == 'tcp' ]] \
            && [[ $service == 'http' ]]
            then
                echo "http://${ip}:${port}"
            elif [[ $protocol == 'tcp' ]] \
            && [[ $service =~ ssl.http ]]
            then
                echo "https://${ip}:${port}"
            else
                # sometimes nmap can't identify a web service, so just try anyways
                if [[ $protocol == 'tcp' ]] \
                && echo "# testing $ip $port $service for http with wget" \
                && timeout --kill-after=10 --foreground 30 \
                    wget -U "$USERAGENT" --tries=3 --retry-connrefused -O /dev/null \
                        -S -D $ip --method=HEAD http://${ip}:${port} 2>&1 \
                        |egrep -qi 'HTTP/|X-|Content|Date' 
                then
                    echo "http://${ip}:${port}" 
                fi
                if [[ $protocol == 'tcp' ]] \
                && echo "# testing $ip $port for https with wget" \
                && timeout --kill-after=10 --foreground 30 \
                    wget -U "$USERAGENT" --tries=3 --retry-connrefused -O /dev/null --no-check-certificate \
                        -S  -D $ip  --method=HEAD https://${ip}:${port} 2>&1 \
                        |egrep -qi 'HTTP/|X-|Content|Date' 
                then
                    echo "https://${ip}:${port}" 
                fi
            fi
        done    
    done 
done
