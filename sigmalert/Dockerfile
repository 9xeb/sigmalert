FROM jertel/elastalert2
USER root
RUN apt update && apt -y install git parallel python3-pip nano
RUN python3 -m pip install sigmatools sqlalchemy psycopg2-binary pyyaml
COPY ./sigma_and_elastalert.sh /sigma_and_elastalert.sh

# copy default elastalert config file
COPY ./elastalert.yaml /opt/elastalert/config.yaml

#COPY ./sigma_engine.py /sigma_engine.py
COPY ./push_sigma_rules.py /push_sigma_rules.py	

# copy configuration files for specific query parameters
COPY ./nsm_and_web.yml /nsm_and_web.yml
#COPY ./zeek.yml /zeek.yml

RUN chown -R elastalert:elastalert /opt/elastalert && chmod +x /push_sigma_rules.py
USER elastalert
ENTRYPOINT ["/bin/bash", "/sigma_and_elastalert.sh"]
