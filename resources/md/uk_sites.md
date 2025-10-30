# UK Authorities

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
