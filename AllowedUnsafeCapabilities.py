from typing import Dict, Any

from checkov.common.models.enums import CheckResult
from checkov.kubernetes.checks.resource.base_container_check import BaseK8sContainerCheck
import re

class AllowedUnsafeCapabilities(BaseK8sContainerCheck):
    def __init__(self) -> None:
        name = "Capabilities should be set according to the principle of least privileges (drop 'ALL', after which all the necessary capacities for the application to work are enumerated, while it is prohibited to use:CAP_FSETID,CAP_SETUID,CAP_SETGID,CAP_SYS_CHROOT,CAP_SYS_PTRACE,CAP_CHOWN,CAP_NET_RAW,CAP_NET_ADMIN,CAP_SYS_ADMIN,CAP_NET_BIND_SERVICE)"
        # This provides the most privilege and is similar to root
        # https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
        id = "CKV_K8S_X6"
        # Location: container .securityContext.capabilities
        super().__init__(name=name, id=id)

    def scan_container_conf(self, metadata: Dict[str, Any], conf: Dict[str, Any]) -> CheckResult:
        badCapabilities = "FSETID|SETUID|SETGID|SYS_CHROOT|SYS_PTRACE|CHOWN|NET_RAW|NET_ADMIN|SYS_ADMIN|NET_BIND_SERVICE"

        self.evaluated_container_keys = ["securityContext/capabilities/add"]
        if conf.get("securityContext"):
            if conf["securityContext"].get("capabilities"):
                if conf["securityContext"]["capabilities"].get("add"):
                    for capability in conf["securityContext"]["capabilities"]["add"]:
                        if re.search(badCapabilities, capability):
                            return CheckResult.FAILED
        return CheckResult.PASSED

check = AllowedUnsafeCapabilities()