from depenemy.rules.supply_chain.s001_install_scripts import S001InstallScripts
from depenemy.rules.supply_chain.s002_no_source_repo import S002NoSourceRepo
from depenemy.rules.supply_chain.s003_archived_repo import S003ArchivedRepo
from depenemy.rules.supply_chain.s004_dependency_confusion import S004DependencyConfusion
from depenemy.rules.supply_chain.s005_malicious_package import S005MaliciousPackage
from depenemy.rules.supply_chain.s006_missing_provenance import S006MissingProvenance
from depenemy.rules.supply_chain.s007_ghost_repo import S007GhostRepo
from depenemy.rules.supply_chain.s008_bulk_publish import S008BulkPublish
from depenemy.rules.supply_chain.s009_identity_mismatch import S009IdentityMismatch

__all__ = [
    "S001InstallScripts",
    "S002NoSourceRepo",
    "S003ArchivedRepo",
    "S004DependencyConfusion",
    "S005MaliciousPackage",
    "S006MissingProvenance",
    "S007GhostRepo",
    "S008BulkPublish",
    "S009IdentityMismatch",
]
