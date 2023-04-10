# Sigmalert
This repo contains an Elasticsearch + Elastalert + SIGMA rules setup for host based intrustion detection.
Though I'm not particularly interested in this, I wrote it to prove myself I could do it if necessary.

## How it works
There is one Elasticsearch server instance with basic authentication.
A custom elastalert2 image is deployed. It is aware of SIGMA rules that are published in the main SIGMA project's github repo and periodically queries the Elasticsearch server to find matches.
Being elastalert2 at its core, results are pushed to Elasticsearch in the "elastalert_status" index.
A default kibana interface is provided for testing purposes.

## How to use
Edit and .env file containing ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD.
Run with docker-compose

