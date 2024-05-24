import json
import os
import uuid

from copy import deepcopy
from glob import glob

from cpe.comp.cpecomp2_3_fs import CPEComponent2_3_FS
from cpe import CPE


namespace = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/anchore/nvd-data-overrides")


class MatchCriteriaIdGenerator:
    def __init__(self):
        self._nvd_known_id_lookup = None

    def _load_known_nvd_id_lookups(self):
        self._nvd_known_id_lookup: dict[str, str] = {}

        for nvd_file in glob("national-vulnerability-database/data/**/CVE-*.json", recursive=True):
            with open(nvd_file) as f:
                data = json.load(f)

            cpe_configs = data.get("cve", {}).get("configurations", [])

            for c in cpe_configs:
                for n in c.get("nodes", []):
                    for m in n.get("cpeMatch", []):
                        match_id = m["matchCriteriaId"]
                        del m["matchCriteriaId"]
                        del m["vulnerable"]
                        self._nvd_known_id_lookup[json.dumps(m, sort_keys=True)] = match_id

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

        cve_id = enriched["additionalMetadata"]["cveId"]
        year = cve_id.split("-")[1]

        override = {
            "_annotation": {
                "cve_id": enriched["additionalMetadata"]["cveId"],
                "reason": enriched["additionalMetadata"]["reason"],
                "generated_from": f"https://raw.githubusercontent.com/anchore/cve-data-enrichment/main/data/anchore/{year}/{cve_id}.json",
            },
            "cve": {},
        }

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

                configuration = {
                    "nodes": []
                }
                
                for cpe in cpes:
                    node = {
                        "cpeMatch": [],
                        "negate": False,
                        "operator": "OR"
                    }

                    for version in versions:
                        match = {
                            "criteria": cpe,
                            "vulnerable": version["status"] == "affected"
                        }

                        less_than = version.get("lessThan")
                        less_than_or_equal = version.get("lessThanOrEqual")
                        v = version["version"].strip()

                        if not less_than and not less_than_or_equal:
                            # This is a single affected version so set the version component in the CPE
                            c = CPE(cpe)

                            if c.is_application():
                                c.get("app")[0]["version"] = CPEComponent2_3_FS(v, "version")
                                match["criteria"] = c.as_fs()
                            elif c.is_operating_system():
                                c.get("os")[0]["version"] = CPEComponent2_3_FS(v, "version")
                                match["criteria"] = c.as_fs()
                            elif c.is_hardware():
                                c.get("hw")[0]["version"] = CPEComponent2_3_FS(v, "version")
                                match["criteria"] = c.as_fs()
                        elif v != "0":
                            match["versionStartIncluding"] = v

                        if less_than and less_than.strip() != "*":
                            match["versionEndExcluding"] = less_than.strip()
                        elif less_than_or_equal and less_than_or_equal.strip() != "*":
                            match["versionEndIncluding"] = less_than_or_equal.strip()

                        match["matchCriteriaId"] = generator.generate(match)
                        node["cpeMatch"].append(match)
                    
                    configuration["nodes"].append(node)

                override["cve"]["configurations"].append(configuration)

        override_path = f"data/{year}"

        if not os.path.exists(override_path):
            os.makedirs(override_path)

        with open(os.path.join(override_path, f"{cve_id}.json"), "w") as f:
            json.dump(override, f, ensure_ascii=False, sort_keys=True, indent=2)


if __name__ == "__main__":
    generate()