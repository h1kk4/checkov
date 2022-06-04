from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check


class UnsafeProcMountTypes(BaseK8Check):

    def __init__(self):
        name = "Do not change the procMount from the Default settings, unless you have very specific configurations"
        id = "CKV_K8S_X4"
        supported_kind = ['PodSecurityPolicy']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def scan_spec_conf(self, conf):
        spec = {}
        if "spec" in conf:
            spec = conf["spec"]
            if ("allowedProcMountTypes" in spec):
                if isinstance(spec["allowedProcMountTypes"], list) and len(spec["allowedProcMountTypes"]) > 0:
                    if ("Unmasked" in spec["allowedProcMountTypes"]):
                        return CheckResult.FAILED
        
        return CheckResult.PASSED

check = UnsafeProcMountTypes()