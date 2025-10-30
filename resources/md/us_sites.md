# US Authorities

* The USA government maintains an index into all of their organizations webpages.
  * Found [here](https://www.usa.gov/agency-index)
  * ~600 US Authority sites

# US Financial Institutions

## Banks

* The US Government has a public api for querying about available banks.
  * API found [here](https://catalog.data.gov/dataset/fdic-bankfind-suite-api)
    * API Host has moved from where the docs report it to here -> `https://api.fdic.gov/banks/institutions`

* Example query format:
```bash
curl -G 'https://api.fdic.gov/banks/institutions' \
  --data-urlencode 'filters=STALP:NY AND ACTIVE:1' \
  --data-urlencode 'fields=NAME,CERT,STALP,ASSET,DEP,OFFICES,DATEUPDT,WEBADDR' \
  --data-urlencode 'sort_by=ASSET' \
  --data-urlencode 'sort_order=DESC' \
  --data-urlencode 'limit=10000' \
  --data-urlencode 'format=csv' \
  --data-urlencode 'download=true' \
  --data-urlencode 'filename=fdic_ny_banks_by_assets'
```

* I took the top 10 states by population from the US Population Stats ([here](https://www.census.gov/topics/population.html)).
* I then queried the api sorting by the top 10 banks by assets under management per state.
  * This return ~100 banks.

## Credit Unions

>**NOTE:** The US has many many credit unions. I did find some sources I could possibly use for this, but I skipped it as it was extremely time consuming. 

* The US Government also maintains a list of credit unions
  * Found [here](https://mapping.ncua.gov/)

* The National Credit Union Administration maintains a "Call Report Quarterly Data" found [here](https://ncua.gov/analysis/credit-union-corporate-call-report-data/quarterly-data)

# US Educational Insitutions

* The college scorecard api lists tons of information about educational institutions accros the US, and is maintained by the US government.
  * Found [here](https://collegescorecard.ed.gov/data/api-documentation)

* An example api call:
```bash
curl -sG 'https://api.data.gov/ed/collegescorecard/v1/schools' \
  --data-urlencode "api_key=$US_SCORECARD_API_KEY" \
  --data-urlencode 'school.state=CA' \
  --data-urlencode 'fields=id,school,latest.student.size' \
  --data-urlencode 'keys_nested=true' \
  --data-urlencode 'sort=latest.student.size:desc' \
  --data-urlencode 'per_page=1'
```

* I took the top 10 states by population and grabbed the top 5 schools by population.

# US Critical Infrastructure

* The Edison Institute does have a list.
  * found [here](https://www.eei.org/-/media/Project/EEI/Documents/About/member-company-web-sites.pdf)