#!/usr/bin/bash

# CA
python3 -m scanner.main ./resources/ca_sites.csv --csv-column url --offset 0 --row-limit 607 --max-conurrency 15 --max-per-site 3 --output-json results/ca/auth/ca_auth.json
sleep 1m
python3 -m scanner.main ./resources/ca_sites.csv --csv-column url --offset 608 --row-limit 156 --max-conurrency 20 --max-per-site 5 --output-json results/ca/fin/ca_fin.json
sleep 1m
python3 -m scanner.main ./resources/ca_sites.csv --csv-column url --offset 763 --row-limit 96 --max-conurrency 20 --max-per-site 5 --output-json results/ca/edu/ca_edu.json
sleep 1m
python3 -m scanner.main ./resources/ca_sites.csv --csv-column url --offset 861 --row-limit 261 --max-conurrency 20 --max-per-site 5 --output-json results/ca/energy/ca_energy.json
sleep 5m

# US
python3 -m scanner.main ./resources/us_sites.csv --csv-column url --offset 0 --row-limit 601 --max-conurrency 15 --max-per-site 3 --output-json results/us/auth/us_auth.json
sleep 1m
python3 -m scanner.main ./resources/us_sites.csv --csv-column url --offset 601 --row-limit 99 --max-conurrency 20 --max-per-site 5 --output-json results/us/fin/us_fin.json
sleep 1m
python3 -m scanner.main ./resources/us_sites.csv --csv-column url --offset 700 --row-limit 51 --max-conurrency 20 --max-per-site 5 --output-json results/us/edu/us_edu.json
sleep 1m
python3 -m scanner.main ./resources/us_sites.csv --csv-column url --offset 751 --row-limit 144 --max-conurrency 20 --max-per-site 5 --output-json results/us/energy/us_energy.json
sleep 5m

# UK
python3 -m scanner.main ./resources/uk_sites.csv --csv-column url --offset 0 --row-limit 349 --max-conurrency 15 --max-per-site 3 --output-json results/uk/auth/uk_auth.json
sleep 1m
python3 -m scanner.main ./resources/uk_sites.csv --csv-column url --offset 349 --row-limit 359 --max-conurrency 20 --max-per-site 5 --output-json results/uk/edu/uk_edu.json
sleep 1m
python3 -m scanner.main ./resources/uk_sites.csv --csv-column url --offset 858 --row-limit 709 --max-conurrency 20 --max-per-site 5 --output-json results/uk/fin/uk_fin.json
sleep 1m
