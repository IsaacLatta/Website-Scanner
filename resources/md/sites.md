
# Canadian Authorities

> **NOTE**: The below authoritative sources work out to around ~615 sites (before deduplication and following 3xx codes). This ~615 includes healthcare authorities (e.g. Interior Health), which could potentially be extracted into another dedicated sector (similar to finance and education). After deduplication and removal of health authorities I would estimate there is around 400-450 unique canadian authority sites here (not including the other sections). One idea which could be great but I haven't done (just tedious and laborious) is grabbing the top N (100?) populated candadian city's municipality websites—could help tell a story.

## Departments

* List of canadian dept [here](https://www.canada.ca/en/government/dept.html)

## Instituions

* List of canadian institutions [here](https://www.canada.ca/en/treasury-board-secretariat/services/access-information-privacy/access-information/info-source/list-institutions.html)

## Crown Corportations

* List of crown corporations [here](https://www.canada.ca/en/treasury-board-secretariat/services/guidance-crown-corporations/list-crown-corporations.html)

> **NOTE**: The above 3 sources comprise ~420 sites of the list.

## Airport Authorities

* List of small airport authorities [here](https://tc.canada.ca/en/aviation/operating-airports-aerodromes/list-airports-owned-transport-canada#_Small_airports_owned)

* List of large airport authorities (NAC) [here](https://tc.canada.ca/en/aviation/operating-airports-aerodromes/list-airports-owned-transport-canada#National_Airports_System)

## Maritime Port Authorities

* List of maritime port authorities [here](https://tc.canada.ca/en/marine-transportation/ports-harbours-anchorages/list-canada-port-authorities)

## Healthcare Authorities

* Each province maintains there own healthcare services
  * I did this manually for each province (except ontario and quebec as they have many authorities, not sure how closely tied to the government).
  
## Security Commissioners

* Each province maintains there own security commissions administrator. The canada security administrators has a "contact us" page that lists each province's authority found [here](https://www.securities-administrators.ca/about/contact-us/)

## Election Agencies

* Each province has their own elections agency. I did this manually for each agency. Typically under "elections(provincename|.province_abbreviation)".

## Privacy Commissioners

* Each province has their own privancy commisioner. I did this manually as well.

## Courts

* The canadian gov has a site that hyperlinks each province's courts (prov, supreme, etc) site.
  * Found [here](https://laws-lois.justice.gc.ca/eng/Court/)
  
## Auditor General

* PEI lists other provinces auditor general sites.
  * Found [here](https://www.assembly.pe.ca/other-canadian-auditor-general-offices)

## Emergency Management

* List found [here](https://www.canada.ca/en/services/policing/emergencies/preparedness/get-prepared/emergency-planning-resources/emergency-management-organizations.html)


# Financial Institutions

> **NOTE**: I have ~160 financial institutions for canada (most are unique).

## Banks

* Canadian Banks Association (CBA) list found [here](https://cba.ca/article/member-banks)
  * Schedule I is domestic (parsed).
  * Schedule II is foreign domestic hosts (parsed).
  * Schedule III contains international banks, many of whom are not in north america (did not parse).

* ~43 here, great authoritative list.

## Credit Unions

* BC [here](https://www.bcfsa.ca/public-resources/credit-unions/bc-authorized-credit-unions/find-credit-union-search-results?type=credit_union)

* New Brunswick [here](https://www.nbcudic.ca/protected-institutions)

* Saskatchewan [here](https://saskcentral.com/listing_credit_unions.html)

* Ontario [here](https://www.central1.com/list-on/)
    * Can cross-reference [here](https://www.fsrao.ca/consumers/credit-unions-and-deposit-insurance/find-credit-union-or-caisses-populaires-ontario) if needed (more official source).

The 4 above cover ~115 credit unions.

# Education Institutions

I have 97 canadian university websites from Universities Canada.

* Found [here](https://univcan.ca/about-universities-canada/our-members/)

# Critical Infrastructure (Energy) (CA)

## Electricity

* Electricity Canada maintains a list per province.
  * Found [here](https://www.electricity.ca/membership/list-of-members/).

## Natural Gas

* Canadian Gas Association maintains a list.
  * Found [here](https://www.cga.ca/resources/industry-links/)
  
## Pipelines

* The Canadian Energy regulator maintains a list of pipelines whom they regulate.
  * Found [here](https://www.cer-rec.gc.ca/en/about/who-we-are-what-we-do/pipeline-companies-regulated-cer.html)

## Nuclear Powerplants

* The Canadian Nuclear Infrastructure maintains a list as well.
  * Found [here](https://www.cnsc-ccsn.gc.ca/eng/resources/nuclear-facilities/)# US Authorities

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
  * found [here](https://www.eei.org/-/media/Project/EEI/Documents/About/member-company-web-sites.pdf)# UK Authorities

* The UK government maintains a list located [here](https://www.gov.uk/government/organisations). 
  * Most of the orgs linked on this site just point to unique endpoints within the same .gov.uk host.
* They UK gov also maintains an api whos documentation can be found [here](https://docs.publishing.service.gov.uk/repos/collections/api.html).
  * I used this api, parsed all of the pages, and kept only those organizations marked "live".
    * This worked out to ~347 endpoints. I say endpoints since they all live at the same host.

# UK Educational Institutes

* The UK gov maintains a dataset (and api I think) titled "Discover Uni" found [here](https://discoveruni.gov.uk/) 
  * In this dataset there is a file titled `INSTITUTION.csv`, which contains a bunch of info about universities in the UK. This information also includes the name and URL's of each university's website (which I parsed).
  * This worked out to around ~350 sites.

# UK Financial Institutions

* The Bank of England's internal PRA maintains exhaustive lists of who they regulate. Two of these lists include banks and credit unions.
  * [banks](https://www.bankofengland.co.uk/-/media/boe/files/prudential-regulation/authorisations/which-firms-does-the-pra-regulate/2025/list-of-pra-regulated-banks.csv)
  * [credit unions](https://www.bankofengland.co.uk/-/media/boe/files/prudential-regulation/authorisations/which-firms-does-the-pra-regulate/2025/list-of-pra-regulated-credit-unions.csv)

> **NOTE**: I could only obtain these resources via CURL (python, the browser, and headless chromium all returned 401/403).

* The Financial Conduct Authority (FCA) (UK Gov) has a publicly available API [here](https://register.fca.org.uk/Developer/s/).
* I signed up, pulled the list of banks FRN's(linked above), then cross referenced these with the FCA API to obtain the websites. 

* I did not do this for the credit unions (although I could—same process), but since this yielded ~150 sites, leading to ~850 UK sites, and ~2800 total, I figured this was enough. Note that I didnt do credit unions for the US either (only did it for Canada), meaning _"only banks"_ is consistent.


# UK Electricity

> **NOTE**: None of the sources I found for UK energy included links. And those that did were not as official as the sources I used previously. Meaning there are no energy companies for the UK.

* Link to Company House API [here](https://developer-specs.company-information.service.gov.uk/companies-house-public-data-api/reference)
  * Getting started [docs](https://developer.company-information.service.gov.uk/get-started)
* [Bad source](https://www.businessenergyuk.com/electricity-companies/)
* [Good source](https://www.ofgem.gov.uk/sites/default/files/2024-06/electricity_licencees.pdf) no links  :(
