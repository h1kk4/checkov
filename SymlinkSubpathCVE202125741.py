from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check


class SymlinkSubpathCVE202125741(BaseK8Check):

    def __init__(self):
        name = "Symlink Exchange Can Allow Host Filesystem Access. See CVE-2021-25741"
        id = "CKV_K8S_X5"
        supported_kind = ['Pod']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def scan_spec_conf(self, conf):
        spec = {}
        if "spec" in conf:
            spec = conf["spec"]
            if spec.get("containers"):      
                containers = spec["containers"]
                for container in containers:
                    if container.get("volumeMounts") is not None:
                        volumes = container["volumeMounts"]
                        for volume in volumes:
                            if "subPath" in volume:
                                return CheckResult.FAILED

        return CheckResult.PASSED

check = SymlinkSubpathCVE202125741()