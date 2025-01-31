# NVD Data Overrides

This repository contains enriched vulnerability data in NVD-compatible format. It provides additional information and corrections that supplement the official National Vulnerability Database (NVD).

## About This Repository

The data here is automatically generated from the [cve-data-enrichment](https://github.com/anchore/cve-data-enrichment) repository using tools from the [vulnerability-data-tools](https://github.com/anchore/vulnerability-data-tools) project. It focuses on providing:

- CPE configurations for vulnerabilities not yet analyzed by NVD
- Corrections to existing CPE configurations when needed
- Additional metadata that helps with accurate vulnerability matching

## Using This Data

The data is structured to be compatible with existing tools that use NVD data. Each JSON file follows the NVD schema and can be used to supplement or override official NVD records.

### Repository Structure

```
data/
  2024/           # Organized by CVE year
    CVE-*.json    # One file per CVE
  2025/
    CVE-*.json
```

Each JSON file contains only the additional or corrected data needed to supplement the official NVD record.

## Contributing

This repository is automatically generated. To contribute:

1. Visit the [vulnerability-data-tools](https://github.com/anchore/vulnerability-data-tools) repository
2. Follow the contribution guidelines there
3. Submit your changes through that project

Direct pull requests to this repository will not be accepted since all data here is generated automatically.

## License

The vulnerability data in this repository is licensed under [CC0](LICENSE) to ensure maximum reusability by the community.
