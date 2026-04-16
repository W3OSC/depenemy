"""All depenemy rules."""

from depenemy.rules.base import BaseRule
from depenemy.rules.behavioral import B001RangeSpecifier, B002Unpinned, B003LaggingVersion
from depenemy.rules.reputation import (
    R001YoungAuthor,
    R002YoungPackage,
    R003LowWeeklyDownloads,
    R004LowTotalDownloads,
    R005StalePackage,
    R006FewContributors,
    R007BelowSecurityPatch,
    R008Deprecated,
    R009Typosquatting,
    R010RecentlyPublishedVersion,
)
from depenemy.rules.supply_chain import (
    S001InstallScripts,
    S002NoSourceRepo,
    S003ArchivedRepo,
    S004DependencyConfusion,
    S005MaliciousPackage,
)

ALL_RULES: list[BaseRule] = [
    B001RangeSpecifier(),
    B002Unpinned(),
    B003LaggingVersion(),
    R001YoungAuthor(),
    R002YoungPackage(),
    R003LowWeeklyDownloads(),
    R004LowTotalDownloads(),
    R005StalePackage(),
    R006FewContributors(),
    R007BelowSecurityPatch(),
    R008Deprecated(),
    R009Typosquatting(),
    R010RecentlyPublishedVersion(),
    S001InstallScripts(),
    S002NoSourceRepo(),
    S003ArchivedRepo(),
    S004DependencyConfusion(),
    S005MaliciousPackage(),
]

__all__ = ["ALL_RULES", "BaseRule"]
