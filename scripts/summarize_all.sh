#!/bin/bash

# UK Auth
python3 scripts/summarize_headers.py results/uk/auth/uk_auth.json --out-dir results/uk/auth/headers
python3 scripts/summarize_hsts_https.py results/uk/auth/uk_auth.json --out-dir results/uk/auth/hsts_https
python3 scripts/summarize_redirects.py results/uk/auth/uk_auth.json --out-dir results/uk/auth/redirects
python3 scripts/summarize_securitytxt.py results/uk/auth/uk_auth.json --out-dir results/uk/auth/securitytxt
python3 scripts/summarize_tls_cipher.py results/uk/auth/uk_auth.json --out-dir results/uk/auth/tls_cipher
python3 scripts/summarize_error_leaks.py results/uk/auth/uk_auth.json --out-dir results/uk/auth/error_leak

# UK Edu
python3 scripts/summarize_headers.py results/uk/edu/uk_edu.json --out-dir results/uk/edu/headers
python3 scripts/summarize_hsts_https.py results/uk/edu/uk_edu.json --out-dir results/uk/edu/hsts_https
python3 scripts/summarize_redirects.py results/uk/edu/uk_edu.json --out-dir results/uk/edu/redirects
python3 scripts/summarize_securitytxt.py results/uk/edu/uk_edu.json --out-dir results/uk/edu/securitytxt
python3 scripts/summarize_tls_cipher.py results/uk/edu/uk_edu.json --out-dir results/uk/edu/tls_cipher
python3 scripts/summarize_error_leaks.py results/uk/edu/uk_edu.json --out-dir results/uk/edu/error_leak

# UK Fin
python3 scripts/summarize_headers.py results/uk/fin/uk_fin.json --out-dir results/uk/fin/headers
python3 scripts/summarize_hsts_https.py results/uk/fin/uk_fin.json --out-dir results/uk/fin/hsts_https
python3 scripts/summarize_redirects.py results/uk/fin/uk_fin.json --out-dir results/uk/fin/redirects
python3 scripts/summarize_securitytxt.py results/uk/fin/uk_fin.json --out-dir results/uk/fin/securitytxt
python3 scripts/summarize_tls_cipher.py results/uk/fin/uk_fin.json --out-dir results/uk/fin/tls_cipher
python3 scripts/summarize_error_leaks.py results/uk/fin/uk_fin.json --out-dir results/uk/fin/error_leak

# CA Auth
python3 scripts/summarize_headers.py results/ca/auth/ca_auth.json --out-dir results/ca/auth/headers
python3 scripts/summarize_hsts_https.py results/ca/auth/ca_auth.json --out-dir results/ca/auth/hsts_https
python3 scripts/summarize_redirects.py results/ca/auth/ca_auth.json --out-dir results/ca/auth/redirects
python3 scripts/summarize_securitytxt.py results/ca/auth/ca_auth.json --out-dir results/ca/auth/securitytxt
python3 scripts/summarize_tls_cipher.py results/ca/auth/ca_auth.json --out-dir results/ca/auth/tls_cipher
python3 scripts/summarize_error_leaks.py results/ca/auth/ca_auth.json --out-dir results/ca/auth/error_leak

# CA Edu
python3 scripts/summarize_headers.py results/ca/edu/ca_edu.json --out-dir results/ca/edu/headers
python3 scripts/summarize_hsts_https.py results/ca/edu/ca_edu.json --out-dir results/ca/edu/hsts_https
python3 scripts/summarize_redirects.py results/ca/edu/ca_edu.json --out-dir results/ca/edu/redirects
python3 scripts/summarize_securitytxt.py results/ca/edu/ca_edu.json --out-dir results/ca/edu/securitytxt
python3 scripts/summarize_tls_cipher.py results/ca/edu/ca_edu.json --out-dir results/ca/edu/tls_cipher
python3 scripts/summarize_error_leaks.py results/ca/edu/ca_edu.json --out-dir results/ca/edu/error_leak

# CA Fin
python3 scripts/summarize_headers.py results/ca/fin/ca_fin.json --out-dir results/ca/fin/headers
python3 scripts/summarize_hsts_https.py results/ca/fin/ca_fin.json --out-dir results/ca/fin/hsts_https
python3 scripts/summarize_redirects.py results/ca/fin/ca_fin.json --out-dir results/ca/fin/redirects
python3 scripts/summarize_securitytxt.py results/ca/fin/ca_fin.json --out-dir results/ca/fin/securitytxt
python3 scripts/summarize_tls_cipher.py results/ca/fin/ca_fin.json --out-dir results/ca/fin/tls_cipher
python3 scripts/summarize_error_leaks.py results/ca/fin/ca_fin.json --out-dir results/ca/fin/error_leak

# CA Energy
python3 scripts/summarize_headers.py results/ca/energy/ca_energy.json --out-dir results/ca/energy/headers
python3 scripts/summarize_hsts_https.py results/ca/energy/ca_energy.json --out-dir results/ca/energy/hsts_https
python3 scripts/summarize_redirects.py results/ca/energy/ca_energy.json --out-dir results/ca/energy/redirects
python3 scripts/summarize_securitytxt.py results/ca/energy/ca_energy.json --out-dir results/ca/energy/securitytxt
python3 scripts/summarize_tls_cipher.py results/ca/energy/ca_energy.json --out-dir results/ca/energy/tls_cipher
python3 scripts/summarize_error_leaks.py results/ca/energy/ca_energy.json --out-dir results/ca/energy/error_leak

# US Auth
python3 scripts/summarize_headers.py results/us/auth/us_auth.json --out-dir results/us/auth/headers
python3 scripts/summarize_hsts_https.py results/us/auth/us_auth.json --out-dir results/us/auth/hsts_https
python3 scripts/summarize_redirects.py results/us/auth/us_auth.json --out-dir results/us/auth/redirects
python3 scripts/summarize_securitytxt.py results/us/auth/us_auth.json --out-dir results/us/auth/securitytxt
python3 scripts/summarize_tls_cipher.py results/us/auth/us_auth.json --out-dir results/us/auth/tls_cipher
python3 scripts/summarize_error_leaks.py results/us/auth/us_auth.json --out-dir results/us/auth/error_leak

# US Edu
python3 scripts/summarize_headers.py results/us/edu/us_edu.json --out-dir results/us/edu/headers
python3 scripts/summarize_hsts_https.py results/us/edu/us_edu.json --out-dir results/us/edu/hsts_https
python3 scripts/summarize_redirects.py results/us/edu/us_edu.json --out-dir results/us/edu/redirects
python3 scripts/summarize_securitytxt.py results/us/edu/us_edu.json --out-dir results/us/edu/securitytxt
python3 scripts/summarize_tls_cipher.py results/us/edu/us_edu.json --out-dir results/us/edu/tls_cipher
python3 scripts/summarize_error_leaks.py results/us/edu/us_edu.json --out-dir results/us/edu/error_leak

# US Fin
python3 scripts/summarize_headers.py results/us/fin/us_fin.json --out-dir results/us/fin/headers
python3 scripts/summarize_hsts_https.py results/us/fin/us_fin.json --out-dir results/us/fin/hsts_https
python3 scripts/summarize_redirects.py results/us/fin/us_fin.json --out-dir results/us/fin/redirects
python3 scripts/summarize_securitytxt.py results/us/fin/us_fin.json --out-dir results/us/fin/securitytxt
python3 scripts/summarize_tls_cipher.py results/us/fin/us_fin.json --out-dir results/us/fin/tls_cipher
python3 scripts/summarize_error_leaks.py results/us/fin/us_fin.json --out-dir results/us/fin/error_leak

# US Energy
python3 scripts/summarize_headers.py results/us/energy/us_energy.json --out-dir results/us/energy/headers
python3 scripts/summarize_hsts_https.py results/us/energy/us_energy.json --out-dir results/us/energy/hsts_https
python3 scripts/summarize_redirects.py results/us/energy/us_energy.json --out-dir results/us/energy/redirects
python3 scripts/summarize_securitytxt.py results/us/energy/us_energy.json --out-dir results/us/energy/securitytxt
python3 scripts/summarize_tls_cipher.py results/us/energy/us_energy.json --out-dir results/us/energy/tls_cipher
python3 scripts/summarize_error_leaks.py results/us/energy/us_energy.json --out-dir results/us/energy/error_leak