# NVD Data Overrides

This repository is for filling the gap NVD has left in the public vulnerability dataset. On Feb 15, 2024 [NVD](https://nvd.nist.gov) stopped their regular process of enriching most CVE IDs with additional metadata.

This repo is meant to provide additional data that is currently missing from NVD.

Please note, this data does not provide severity information. By definition only NVD can supply NVD CVSS scores.

The tooling that drives this repo as well as ideas for capturing the vulnerability data in a nicer way is being tracked in a repo called [vulnerability-data-tools](https://github.com/anchore/vulnerability-data-tools). Please use that repo for future ideas.

# Repository layout

This repository contains the data for the NVD overrides. This is data meant to enrich the JSON currently being returned by NVD.

The `.snapshot` directory is meant to hold any existing upstream NVD data for an override. At the moment all the files are empty as there has not been any NVD CPE data added for these IDs. The intent of capturing the original data so if the NVD API isn't available, the original data may be referenced if an override exists.

In the `data` directory the override files are separated by year. The JSON in these files is meant to be inserted into the JSON from NVD for a given CVE ID. The CVE ID is not recorded in the JSON file, it should be extracted from the filename. Think of this as additional data that can be inserted into the NVD records as returned by the [NVD API](https://nvd.nist.gov/developers/vulnerabilities).

At the moment the focus is on the CPE matching data. Additional data such as vendor severity and CWE would be welcome additions.

# Contributing

If you're looking to get involved this probably isn't the best place to start. The [vulnerability-data-tools](https://github.com/anchore/vulnerability-data-tools) repo is where the tools and planning exists. You should probably start there.

If you are looking to contribute to this project and want to open a GitHub pull request ("PR"). Please make sure you create a signed-off commit with -s or --signoff passed to the git command.

# FAQ

### Why are you doing this?
 This data provided by NVD was used by Grype to match artifacts not covered by other data sources. We refer to this as the "matcher of last resort". As such, we need this data for a properly functioning Grype. Since we need this data, Grype is an open source project, and it would be beneficial to cooperate. Creating an open source project seemed like the best option.

### What happens if NVD goes back to normal?
In the event NVD returns, or some other project takes over the current task of NVD, we expect to continue to maintain this project. Not every vulnerability database supports every ecosystem, so being able to enrich vulnerability data makes sense.

For example there could be vulnerability data about a binary they build, but if that binary is also downloaded from the project directly, that information may not be tracked anywhere else.

### Isn't PURL better than CPE? Why don't you just use PURL
The intent of this repo is to mimic the data NVD provided. There are many tools that expect data in the same format as NVD.

Other data formats, such as OSV, can support PURL. One of our goals is to store metadata in a way that different formats can be the output of the project.

### Is this meant to replace CVE?
Not at all. The purpose is to enrich only existing vulnerability identifiers. Every current vulnerability identification project has a constrained scope. This is meant to fill some of the gaps left by those constraints.

### Shouldn't this project be part of some larger foundation?
Probably yes. However, the best way to create a successful open source project is to do the work. Finding a long term home for this effort will come once we have proven assumptions and have a functioning process.

### How can I help?
You're welcome to submit PRs to this repo as well as the [vulnerability-data-tools](https://github.com/anchore/vulnerability-data-tools) repo. There is also a Slack channel in the Anchore Community Slack called [#vulnerability-data-project](https://anchorecommunity.slack.com/archives/C06Q9UTQD2L). Feel free to join and ask questions or share ideas there.

# License
The content in this repo is licensed [CC0](https://creativecommons.org/public-domain/cc0/) as noted in the [LICENSE](LICENSE) file