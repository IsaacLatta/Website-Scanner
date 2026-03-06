# Web Security Audit Client

This repository contains the code, data, scripts, and outputs used for the measurement study on web security configuration in Canadian public-sector websites, with comparative analysis against the United States and the United Kingdom. This scanner evaluates transport security, HTTPS and HSTS behavior, TLS support, vulnerability disclosure via `security.txt`, security-related HTTP headers, cookie security attributes, and the presence information leaks. The resulting data was then used to produce the summaries, plots, and findings reported in the associated paper.

> Special thanks to the CSA Group for funding this work through the CSA Group Undergraduate Research Scholarship.

## Repository contents

- `src/` contains the source code for the scanner
- `tests/` contains the test suite for the scanner
- `scripts/` contains the Bash scripts used to run the scans, including the exact scan commands and the scripts used to generate summary data for later analysis and plotting
- `resources/` contains the input materials used during the project, including CSV files of target URIs and miscellaneous planning and extraction files such as notes and saved HTML sources
- `results/` contains the scan outputs, organized by country and by measurement category such as TLS, headers, and related models
- `csa_report/` contains the original LateX source of the report for the CSA Group

This repository is intended to preserve the full workflow used for the research, from target collection through final scan outputs.

## Requirements

- Python 3.10 or newer
- Bash
- A unix-like environment recommended for running the provided scripts (can of course be ran on windows, but the following commands assume unix).

Project dependencies are defined in `pyproject.toml`.

## Setup

Clone the repository and enter it:

```bash
git clone Website-Scanner
cd Web-Security-Audit-Client
````

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project and its dependencies:

```bash
pip install --upgrade pip
pip install -e .
```

Make the scripts executable:

```bash
chmod +x scripts/*
```

## Running Tests

This project uses `pytest`. After installation, run:

```bash
pytest
```

The pytest configuration is defined in `pyproject.toml`.

## Running The Scanner

The exact scan commands used for the study are preserved in the `scripts/` directory, specifically in `scan_all.sh`. 

Typical usage is therefore:

```bash
# Warning, this command will trigger the scanning of our ~3000 site list
./scripts/scan_all.sh
```

## Artifacts

The repository includes both input and output artifacts used in the study.

* Input website lists and extracted source materials are stored under `resources/`
* Scan outputs are stored under `results/`
* Summary generation scripts are stored under `scripts/`

This structure is intended to support reproducibility by keeping the source code, scan commands, input datasets, and produced results together in one place.

## Notes on Reproducibility

To reproduce the workflow as closely as possible:

1. Set up the Python environment from `pyproject.toml`
2. Make all scripts in `scripts/` executable
3. Run the scan scripts from `scripts/`
4. Use the summary-generation scripts in `scripts/` to produce derived data for analysis and plotting.
5. Inspect `results/` for the raw scan outputs and aggregated outputs

Because website configurations change over time, rerunning the scans may not produce identical results to those reported in the paper. The repository preserves the original code, commands, and collected results of the study.
