"""All depenemy rules."""

from depenemy.rules.base import BaseRule
from depenemy.rules.behavioral import B001RangeSpecifier, B002Unpinned, B003LaggingVersion
from depenemy.rules.quality import Q001SingleMaintainer
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
)
from depenemy.rules.supply_chain import (
    S001InstallScripts,
    S002NoSourceRepo,
    S003ArchivedRepo,
    S004DependencyConfusion,
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
    S001InstallScripts(),
    S002NoSourceRepo(),
    S003ArchivedRepo(),
    S004DependencyConfusion(),
    Q001SingleMaintainer(),
]

__all__ = ["ALL_RULES", "BaseRule"]
