import json
import os
import uuid

from copy import deepcopy
from glob import glob

from cpe.comp.cpecomp2_3_fs import CPEComponent2_3_FS
from cpe import CPE


namespace = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/anchore/nvd-data-overrides"
)


class MatchCriteriaIdGenerator:
    def __init__(self):
        self._nvd_known_id_lookup = None

    def _load_known_nvd_id_lookups(self):
        self._nvd_known_id_lookup: dict[str, str] = {}

        for nvd_file in glob(
            "national-vulnerability-database/data/**/CVE-*.json", recursive=True
        ):
            with open(nvd_file) as f:
                data = json.load(f)

            cpe_configs = data.get("cve", {}).get("configurations", [])

            for c in cpe_configs:
                for n in c.get("nodes", []):
                    for m in n.get("cpeMatch", []):
                        match_id = m["matchCriteriaId"]
                        del m["matchCriteriaId"]
                        del m["vulnerable"]
                        self._nvd_known_id_lookup[json.dumps(m, sort_keys=True)] = (
                            match_id
                        )

    def generate(self, match_criteria: dict) -> str:
        """
        Creates a stable UUID for a given set of match criteria.  It will use any known values from the NVD
        before attempting to create a new one. If in future we discover exactly how the NVD
        generation works then in theory we should be able to exactly match any of their existing ids,
        but I have not found any documentation around that so far.  This will ensure they at least
        match across the override dataset.  We are not using the criteriaMatchId for anything, but others
        might so we'll at least make them non-random
        """
        data = deepcopy(match_criteria)
        if self._nvd_known_id_lookup is None:
            self._load_known_nvd_id_lookups()

        if "matchCriteriaId" in data:
            del data["matchCriteriaId"]

        if "vulnerable" in data:
            del data["vulnerable"]

        s = json.dumps(data, sort_keys=True)
        return self._nvd_known_id_lookup.get(s, str(uuid.uuid5(namespace, s))).upper()


def generate():
    generator = MatchCriteriaIdGenerator()

    for anchore_enriched in glob("cve-data-enrichment/data/anchore/**/CVE-*.json"):
        with open(anchore_enriched) as f:
            enriched = json.load(f)

        additional_medatata = enriched["additionalMetadata"]
        cve_id = additional_medatata["cveId"]
        year = cve_id.split("-")[1]

        override = {
            "_annotation": {
                "cve_id": additional_medatata["cveId"],
                "reason": additional_medatata["reason"],
                "generated_from": f"https://raw.githubusercontent.com/anchore/cve-data-enrichment/main/data/anchore/{year}/{cve_id}.json",
            },
            "cve": {},
        }

        description = additional_medatata.get("description")
        if description:
            override["_annotation"]["description"] = description

        cna = additional_medatata.get("cna")
        if cna:
            override["_annotation"]["cna"] = cna

        references = additional_medatata.get("references")
        if references:
            override["_annotation"]["references"] = references

        published = additional_medatata.get("upstream", {}).get("datePublished")
        if published:
            override["_annotation"]["published"] = published

        modified = additional_medatata.get("upstream", {}).get("dateUpdated")
        if modified:
            override["_annotation"]["modified"] = modified

        rejection = additional_medatata.get("rejection")
        ignore = additional_medatata.get("ignore")

        if rejection:
            override["_annotation"]["reason"] = "Emptying previously overridden CVE record because the CVE has been rejected."
        elif ignore:
            # For now it is necessary to put some sort of CPE config in so that the override will take 
            # precendence over NVD
            override["cve"]["configurations"] = [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "cpe:2.3:a:null:null:*:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "D946F4FD-8E0C-537B-ACD4-D734367DE712",
                                    "vulnerable": False,
                                }
                            ], 
                            "negate": False, 
                            "operator": "OR"
                        }
                    ],
                }
            ]
        else:
            affected = enriched["adp"]["affected"]

            if affected:
                override["cve"]["configurations"] = []

                for affected in affected:
                    cpes = affected.get("cpes")
                    if not cpes:
                        continue

                    versions = affected.get("versions")
                    if not versions:
                        continue

                    configuration = {"nodes": []}

                    for cpe in cpes:
                        node = {"cpeMatch": [], "negate": False, "operator": "OR"}

                        for version in versions:
                            cpe_match = {
                                "criteria": cpe,
                                "vulnerable": version["status"] == "affected",
                            }

                            less_than = version.get("lessThan")
                            less_than_or_equal = version.get("lessThanOrEqual")
                            v = version["version"].strip().replace("(", "\\(").replace(")", "\\)")

                            if not less_than and not less_than_or_equal:
                                # This is a single affected version so set the version component in the CPE
                                c = CPE(cpe)

                                if c.is_application():
                                    c.get("app")[0]["version"] = CPEComponent2_3_FS(
                                        v, "version"
                                    )
                                    cpe_match["criteria"] = c.as_fs()
                                elif c.is_operating_system():
                                    c.get("os")[0]["version"] = CPEComponent2_3_FS(
                                        v, "version"
                                    )
                                    cpe_match["criteria"] = c.as_fs()
                                elif c.is_hardware():
                                    c.get("hw")[0]["version"] = CPEComponent2_3_FS(
                                        v, "version"
                                    )
                                    cpe_match["criteria"] = c.as_fs()
                            elif v != "0":
                                cpe_match["versionStartIncluding"] = v

                            if less_than and less_than.strip() != "*":
                                cpe_match["versionEndExcluding"] = less_than.strip()
                            elif less_than_or_equal and less_than_or_equal.strip() != "*":
                                cpe_match["versionEndIncluding"] = (
                                    less_than_or_equal.strip()
                                )

                            cpe_match["matchCriteriaId"] = generator.generate(cpe_match)
                            node["cpeMatch"].append(cpe_match)

                        configuration["nodes"].append(node)

                    # Handle creating platform cpe config for specific cases.  This won't handle multi-node configs,
                    # but that isn't necessary for the current dataset and we can always expand it later if needed.
                    platforms = affected.get("platforms")
                    match platforms:
                        case ["Android"]:
                            configuration["operator"] = "AND"
                            configuration["nodes"].append(
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:o:google:android:-:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "F8B9FEC8-73B6-43B8-B24E-1F7C20D91D26",
                                        }
                                    ],
                                    "negate": False,
                                    "operator": "OR",
                                }
                            )
                        case ["iOS"]:
                            configuration["operator"] = "AND"
                            configuration["nodes"].append(
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "B5415705-33E5-46D5-8E4D-9EBADC8C5705",
                                        }
                                    ],
                                    "negate": False,
                                    "operator": "OR",
                                }
                            )
                        case ["MacOS"]:
                            configuration["operator"] = "AND"
                            configuration["nodes"].append(
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "387021A0-AF36-463C-A605-32EA7DAC172E",
                                        }
                                    ],
                                    "negate": False,
                                    "operator": "OR",
                                }
                            )
                        case ["Windows"]:
                            configuration["operator"] = "AND"
                            configuration["nodes"].append(
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "A2572D17-1DE6-457B-99CC-64AFD54487EA",
                                        }
                                    ],
                                    "negate": False,
                                    "operator": "OR",
                                }
                            )
                        case ["Gentoo"]:
                            configuration["operator"] = "AND"
                            configuration["nodes"].append(
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:o:gentoo:linux:-:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "92121D8A-529E-454A-BC8D-B6E0017E615D",
                                        }
                                    ],
                                    "negate": False,
                                    "operator": "OR",
                                }
                            )

                    platform_cpes = affected.get("platformCpes", [])
                    if platform_cpes:
                        configuration["operator"] = "AND"
                        matches = []
                        for cpe in platform_cpes:
                            match = {
                                "vulnerable": False,
                                "criteria": cpe,
                            }
                            match["matchCriteriaId"] = generator.generate(cpe_match)
                            matches.append(match)

                        configuration["nodes"].append(
                            {
                                "cpeMatch": matches,
                                "negate": False,
                                "operator": "OR",
                            }
                        )

                    override["cve"]["configurations"].append(configuration)

            references = enriched["adp"].get("references")
            if references:
                refs = []

                for r in references:
                    refs.append({
                        "url": r["url"],
                        "source": "anchoreadp",
                    })

                if refs:
                    override["cve"]["references"] = refs

        override_path = f"data/{year}"

        if not os.path.exists(override_path):
            os.makedirs(override_path)

        with open(os.path.join(override_path, f"{cve_id}.json"), "w") as f:
            json.dump(override, f, ensure_ascii=False, sort_keys=True, indent=2)


if __name__ == "__main__":
    generate()
