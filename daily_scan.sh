#!/bin/bash

file="$1"
ouput="nuclei_output.txt"
output_domains="new_domain.txt"


function prepare_template {
    echo "step prepare templates ?"
    rm -rf ./ncl_temp 2&> /dev/null
    mkdir ./ncl_temp
    cp -r ~/nuclei-templates/ ./ncl_temp
    cp -r ~/ncl/templates ./ncl_temp
    cp -r ~/tools/pikpik/nuclei/nuclei/ ./ncl_temp
    cd  ./ncl_temp
    if [[ -f ../.templates ]]; then
        for i in $(cat ../.templates);do
            find ./ -iname "$i" -exec rm -rf {} \;
        done
    else
        touch ../.templates
    fi
    cd -
}

function update_templates {
    echo " update template"
    nuclei -update-templates
    cd ~/tools/pikpik/nuclei/ && git pull
    cd ~/ncl && git pull

}

function scan {
    echo "scan "
    cat Hosts |nuclei  -t ./ncl_temp -c 500   -stats -timeout 5  -severity critical,high,medium,low | anew $ouput |notify -silent
}

function update_log {
    echo "update Log"
    cd  ./ncl_temp && find ./ -iname "*.yaml"  |grep -r  "$4" |cut -d ":" -f 1 | rev | cut -d'/' -f1 | rev   >> ../.templates 
    cd  .. && cat .templates |sort -uo .templates
    rm -rf ./ncl_temp 

}
function crl() {
        echo "rapide"
        curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u >> $output_domains
        echo "threatcrowd"
        curl --silent "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1" |jq -r .subdomains[] |sort -u >>  $output_domains
        echo "bufferover"
        curl -s  "https://dns.bufferover.run/dns?q=.$1" |jq -r .FDNS_A[]|cut -d',' -f2|sort -u >> $output_domains
        echo "riddle"
        curl -s "https://riddler.io/search/exportcsv?q=pld:$1" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> $output_domains
        echo "virustotal"
        curl -s "https://www.virustotal.com/ui/domains/$1/subdomains?limit=400" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> $output_domains
        echo "certspoter"
        # curl -s "https://certspotter.com/api/v0/certs?domain=$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> $output_domains
        # echo "archive"
        curl -s "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u >> $output_domains
        echo "jldc"
        curl -s "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> $output_domains
        echo "secutrails"
        curl -s "https://securitytrails.com/list/apex_domain/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".$1" | sort -u >> $output_domains
        echo "crt"
        curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> $output_domains
        echo "recon"
        curl "https://recon.dev/api/search?key=$rec_dev_key&domain=$1" |jq -r '.[].raw$output_domains[]' | sed 's/ //g' | sort -u >> $output_domains
        echo "sonar"
        curl --silent "https://sonar.omnisint.io/subdomains/$1" |grep -oE "[a-zA-Z0-9._-]+\.$1" | sort -u >> $output_domains
        echo "synapsint"
    #       curl --silent  -X POST "https://synapsint.com/report.php" -d "name=https%3A%2F%2F$1"  |grep -oE "[a-zA-Z0-9._-]+\.$1"  | sort -u >> $output_domains
}

function new_assets {
        echo "search for new asset "
        for domain in $(cat ./scope);do
                crl $domain
                echo "$domain" |subfinder |tee -a $output_domains
                git_domains -d $domains -t $github_api |tee -a $output_domains
        done
        cat Hosts > a 
        cat $output_domains | httpx -threads 200  -timeout 5 -silent |anew a |tee -a daily_hosts.txt
        cat dialy_hosts.txt |grep -f scope |sort -uo dialy_hosts.txt
        cat dialy_hosts.txt >> new_Hosts
        rm a 
        

}

function scan_new_assets {
    echo "scan new asset"
    cat daily_hosts.txt  | nuclei  -t ~/nuclei-templates/ -t ~/ncl/templates -t ~/tools/pikpik/nuclei/ -c 500   -stats -timeout 5  -severity critical | anew new_host_output.txt |notify -silent
    cat daily_hosts.txt  | nuclei  -t ~/nuclei-templates/ -t ~/ncl/templates -t ~/tools/pikpik/nuclei/ -c 500   -stats -timeout 5  -severity high | anew new_host_output.txt |notify -silent
    cat daily_hosts.txt  | nuclei  -t ~/nuclei-templates/ -t ~/ncl/templates -t ~/tools/pikpik/nuclei/ -c 500   -stats -timeout 5  -severity medium | anew new_host_output.txt |notify -silent
    cat daily_hosts.txt  | anew  Hosts
    rm dialy_hosts.txt
}


update_templates
prepare_template 
scan 
update_log
new_assets 
scan_new_assets