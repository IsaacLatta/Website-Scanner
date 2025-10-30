# UK Authorities

* The UK government maintains a list located [here](https://www.gov.uk/government/organisations). 
  * Most of the orgs linked on this site just point to unique endpoints with the same .gov.uk host.
* They UK gov also maintains an api whos documentation can be found [here](https://docs.publishing.service.gov.uk/repos/collections/api.html).
  * I used this api, parsed all of the pages, and kept only those organizations are marked "live".
    * This worked out to ~347 endpoints. I say endpoints since they all live at the same host.

# UK Educational Institutes

* The UK gov maintains a dataset (and api I think) titled "Discover Uni" found [here](https://discoveruni.gov.uk/) 
  * In this dataset there is a file titled `INSTITUTION.csv`, which contains a bunch of info about universities in the UK. This information also includes the name and URL's of each university's website (which I parsed).
  
# UK Financial Institutions

