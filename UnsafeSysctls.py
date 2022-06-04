from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check


class UnsafeSysctls(BaseK8Check):

    def __init__(self):
        name = "Do not use unsafe system calls (sysctl)"
        id = "CKV_K8S_X2"
        supported_kind = ['PodSecurityPolicy']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def scan_spec_conf(self, conf):
        spec = {}
        if "spec" in conf:
            spec = conf["spec"]
            if ("allowedUnsafeSysctls" in spec):
                if isinstance(spec["allowedUnsafeSysctls"], list) and len(spec["allowedUnsafeSysctls"]) > 0:
                    return CheckResult.FAILED
    
        return CheckResult.PASSED

check = UnsafeSysctls()