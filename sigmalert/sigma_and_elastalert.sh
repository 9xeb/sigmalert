#!/bin/bash

echo "[*] Updating Elasticsearch client credentials"
#cp network/suricata/suricata.yaml.template network/suricata/suricata.yaml
sed -i 's/es_username: .*/es_username: '${ELASTICSEARCH_USERNAME}'/g' /opt/elastalert/config.yaml
sed -i "s/es_password: .*/es_password: '"${ELASTICSEARCH_PASSWORD}"'/g" /opt/elastalert/config.yaml

echo "[*] Cloning default SigmaHQ ruleset"
git clone https://github.com/SigmaHQ/sigma 2>&1

#/push_sigma_rules.py

# WEB + SURICATA (ecs-proxy.yml)
#find $(pwd)/web -name *.yml | parallel '>&2 echo "[*] Converting "{}; sigma convert -t elasticsearch --without-pipeline -f dsl_lucene {} -o {}.dsl' > /dev/null
echo "[DIR] "$(pwd)

mkdir /opt/elastalert/rules
rm /opt/elastalert/rules/*.yaml

{
find /opt/elastalert/sigma/rules/web -type d -links 2 ! -empty | parallel '>&2 echo "[web-rules] "{}; sigmac -t elastalert -c /nsm_and_web.yml -r {}';
find /opt/elastalert/sigma/rules/proxy -type d -links 2 ! -empty | parallel '>&2 echo "[proxy-rules] "{}; sigmac -t elastalert -c /nsm_and_web.yml -r {}';
find /opt/elastalert/sigma/rules/windows -type d -links 2 ! -empty | parallel '>&2 echo "[windows-rules] "{}; sigmac -t elastalert -c /opt/elastalert/sigma/tools/config/winlogbeat-modules-enabled.yml -r {}';
#find /opt/elastalert/sigma/rules/network/zeek -type d | parallel '>&2 echo "[zeek-rules] "{}; sigmac -t elastalert -c /opt/elastalert/sigma/tools/config/ecs-zeek-elastic-beats-implementation.yml -r {}';
} | csplit --prefix='/opt/elastalert/rules/rule' --suffix=%d.yaml - '/^alert:/' '{*}'

rm /opt/elastalert/rules/rule0.yaml
for rulefile in /opt/elastalert/rules/rule*.yaml;
do
  echo "$rulefile"
  # if low or medium priority then remove for now
  if grep -e '^priority: 3' -e '^priority: 4' "$rulefile" > /dev/null;
  then
    rm "$rulefile"
    echo "Removing low priority rule: ""$rulefile"
  fi
done
/opt/elastalert/run.sh
exit
