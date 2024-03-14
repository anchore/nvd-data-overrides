# Grype DB NVD Overrides

This repository is for filling the gap NVD has left in the Grype vulnerability dataset. On Feb 15, 2024 [NVD](https://nvd.nist.gov) stopped their regular process of enriching most CVE IDs with additional metadata. This data was used by Grype to match artifacts not covered by other ecosystems.

This repo is meant to provide additional data that is currently missing from NVD, and ensure Grype can use that enrichment.

Please note, this data does not provide severity information. By definition only NVD can supply NVD CVSS scores.

# Contributing

If you are looking to contribute to this project and want to open a GitHub pull request ("PR"). Please make sure you create a signed-off commit with -s or --signoff passed to the git command.

# Future vulnerability data effort

We have a Google Document that describes some ideas and concepts for a later vulnerability enrichment project. This particular repository is a short term stopgap to quickly deal with the missing NVD enrichment. Long term we would like to provide vulnerability enrichment in a much more sustainable way. The data in this repository will be included in the future efforts, so the work is not wasted effort.

https://docs.google.com/document/d/1ccW_ng9HVwuTWiL2dGC5Tqb_CKef6pAEwRQ4tg_aDgw/edit#heading=h.7lelh5vxqxu4


# License
The content in this repo is licensed [CC0](https://creativecommons.org/public-domain/cc0/) as noted in the [LICENSE](LICENSE) file