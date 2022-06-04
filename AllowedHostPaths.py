from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check


class AllowedHostPaths(BaseK8Check):

    def __init__(self):
        name = "Limits containers to specific paths of the host file system"
        id = "CKV_K8S_X3"
        supported_kind = ['PodSecurityPolicy']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def scan_spec_conf(self, conf):
        spec = {}
        if "spec" in conf:
            spec = conf["spec"]
            if "allowedHostPaths" in spec:
                policies = spec["allowedHostPaths"]
                for policy in policies:
                    if ("pathPrefix" not in policy) or ("readOnly" not in policy):
                        return CheckResult.FAILED
                    else:    
                        if policy["readOnly"] is False:
                            return CheckResult.FAILED
                        
        return CheckResult.PASSED 

check = AllowedHostPaths()