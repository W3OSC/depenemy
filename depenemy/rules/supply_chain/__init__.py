from depenemy.rules.supply_chain.s001_install_scripts import S001InstallScripts
from depenemy.rules.supply_chain.s002_no_source_repo import S002NoSourceRepo
from depenemy.rules.supply_chain.s003_archived_repo import S003ArchivedRepo
from depenemy.rules.supply_chain.s004_dependency_confusion import S004DependencyConfusion
from depenemy.rules.supply_chain.s005_malicious_package import S005MaliciousPackage

__all__ = [
    "S001InstallScripts",
    "S002NoSourceRepo",
    "S003ArchivedRepo",
    "S004DependencyConfusion",
    "S005MaliciousPackage",
]
