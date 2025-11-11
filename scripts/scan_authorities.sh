#!/bin/bash

MAX_PER_SITE=5
MAX_TOTAL=80
SLEEP_TIME_S=400

echo "Starting scan ..."

python3 -m scanner.main ./resources/uk_sites.csv --csv-column url --offset 0 --row-limit 347 --max-concurrency ${MAX_TOTAL} --max-per-site ${MAX_PER_SITE} --output-json ./results/uk_authority_results.json

echo "Scan of UK complete"

sleep ${SLEEP_TIME_S}

python3 -m scanner.main ./resources/us_sites.csv --csv-column url --offset 0 --row-limit 599 --max-concurrency ${MAX_TOTAL} --max-per-site ${MAX_PER_SITE} --output-json ./results/us_authority_results.json

echo "Scan of US complete"

sleep ${SLEEP_TIME_S}

python3 -m scanner.main ./resources/ca_sites.csv --csv-column url --offset 0 --row-limit 606 --max-concurrency ${MAX_TOTAL} --max-per-site ${MAX_PER_SITE} --output-json ./results/ca_authority_results.json

echo "Scan of CA complete"
