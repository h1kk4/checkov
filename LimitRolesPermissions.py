from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check

class LimitRolesPermissions(BaseK8Check):

    def __init__(self):
        # CIS-1.20 5.1.8
        name = "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster"
        # Cluster roles and roles with the impersonate, bind or escalate permissions should not be granted unless strictly required. Each of these permissions allow a particular subject to escalate their privileges beyond those explicitly granted by cluster administrators
        id = "CKV_K8S_X1"
        supported_kind = ['Role', 'ClusterRole']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def scan_spec_conf(self, conf):
        if isinstance(conf.get("rules"), list) and len(conf.get("rules")) > 0:
            for rules in conf["rules"]:
                if ("impersonate" in rules["verbs"]) or ("bind" in rules["verbs"]) or ("escalate" in rules["verbs"]):
                    return CheckResult.FAILED

        return CheckResult.PASSED

check = LimitRolesPermissions()