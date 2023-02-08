import pickle
from itertools import groupby
from operator import methodcaller
from typing import TypeAlias

from vuln_compare.model import UnifiedVulnerabilityModel

Groups: TypeAlias = list[UnifiedVulnerabilityModel]


def difference_cvssV3(groups: Groups):
    cvss1 = groups[0].get_cvss_by_type("CVSS_V3")
    cvss2 = groups[1].get_cvss_by_type("CVSS_V3")
    return cvss1 is not None \
        and cvss2 is not None \
        and cvss1.score_is_not_equals(cvss2)


def count_greater_than_1(groups: Groups) -> bool:
    return len(groups) > 1


def load_models() -> list[UnifiedVulnerabilityModel]:
    with open('../dumps/models.pkl', 'rb') as f:
        return pickle.load(f)


def main():

    models = load_models()
    # TODO
    grouper = methodcaller(UnifiedVulnerabilityModel.compare_by_identifier_and_purl.__name__)
    sorted_models = sorted(models, key=grouper)
    grouped = [list(group) for key, group in groupby(sorted_models, grouper)]

    filtered_by_count = filter(count_greater_than_1, grouped)
    unique_by_cvssV3 = filter(difference_cvssV3, filtered_by_count)


if __name__ == "__main__":
    main()
