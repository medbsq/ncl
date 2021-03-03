#!/bin/bash
 
function help(){
echo "usage:"
echo "this script take list of template and test it on list of url  "
echo -e "\t u \t update  templates"
echo -e "\t l \t provide list of url (require) "
echo -e "\t c \t occurance number (10 default)"
echo -e "\t p\t report"
}
function report(){
	cat $(find ./ -name "cve.txt") |cut -d " " -f 1 |tee -a report
	echo "-----------------------------------------------------"

	cat $(find ./ -name "security-misconfiguration.txt") |cut -d " " -f 1 |sort -u |tee -a report
	echo "-----------------------------------------------------"

	cat $(find ./ -name "vulnerabilities.txt") |cut -d " " -f 1 |sort -u |tee -a report
	echo "-----------------------------------------------------"

	cat $(find ./ -name "subdomain-takeover.txt") |cut -d " " -f 1 |sort -u |tee -a report
	echo "-----------------------------------------------------"
}

function templates(){
#	mkdir -p ./tempates 
	cp -r ~/nuclei-templates ./templates
	#for i in $(cat ./nuclei_Hosts/.logs);do
	#find ./templates -name "$i" -delete
	#done
}

function ncl(){
	mkdir -p  nuclei_$1
	cat $1| nuclei -t ./templates/cves  -c  $2 -retries 3 -o  ./nuclei_$1/cve.txt
	ls ./templates/cves   |xargs -n1 -I {} bash -c "echo '{}' >> ./nuclei_$1/.logs"
	cat $1| nuclei -t ./templates/security-misconfiguration -c  $2  -retries 3 -o  ./nuclei_$1/security-misconfiguration.txt
	ls  ./templates/security-misconfiguration   |xargs -n1 -I {} bash -c "echo '{}' >> ./nuclei_$1/.logs"
	cat $1| nuclei -t ./templates/vulnerabilities           -c  $2  -retries 3 -o  ./nuclei_$1/vulnerabilities.txt
	ls  ./templates/vulnerabilities |xargs -n1 -I {} bash -c "echo '{}' >> ./nuclei_$1/.logs"
	cat $1| nuclei -t ./templates/subdomain-takeover        -c  $2  -retries 3  -o  ./nuclei_$1/subdomain-takeover.txt
	ls ./templates/subdomain-takeover  |xargs -n1 -I {} bash -c "echo '{}' >> ./nuclei_$1/.logs"
	cat $1| nuclei -t ./templates/technologies              -c  $2  -retries 3 -o  ./nuclei_$1/technologies.txt
	ls  ./templates/technologies.  |xargs -n1 -I {} bash -c "echo '{}' >> ./nuclei_$1/.logs"
	cat $1| nuclei -t ./templates/generic-detections        -c  $2  -retries 3 -o  ./nuclei_$1/generic-detections.txt
	ls ./templates/generic-detections  |xargs -n1 -I {} bash -c "echo '{}' >> ./nuclei_$1/.logs"
	 
#	rm -rf ./templates

}

function update_tmp(){
        cd ~/nuclei-templates  && git pull
        cd - &> /dev/null

}

occurence=40

while getopts ":l:c:u" OPTION
do
        case $OPTION in
		c)
                        occurence="$OPTARG"
                        ;;

                l)
                        url="$OPTARG"
                        ;;
		p)
                        report
			exit
			;;
		u)
                        #update_tmp
			update_tmp
			exit
		u)
                        #update_tmp
			update_tmp
			exit
		u)
                        #update_tmp
			update_tmp
			exit
		u)
                        #update_tmp
			update_tmp
			exit
		u)
                        #update_tmp
			update_tmp
			exit
                        ;;
                :)
                        help
                        exit 1
                        ;;
                \?)
                        help
                        exit 1
                        ;;

        esac
done

#update_tmp
templates 
ncl  $url $occurence 

