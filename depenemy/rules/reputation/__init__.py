from depenemy.rules.reputation.r001_young_author import R001YoungAuthor
from depenemy.rules.reputation.r002_young_package import R002YoungPackage
from depenemy.rules.reputation.r003_low_weekly_downloads import R003LowWeeklyDownloads
from depenemy.rules.reputation.r004_low_total_downloads import R004LowTotalDownloads
from depenemy.rules.reputation.r005_stale_package import R005StalePackage
from depenemy.rules.reputation.r006_few_contributors import R006FewContributors
from depenemy.rules.reputation.r007_below_security_patch import R007BelowSecurityPatch
from depenemy.rules.reputation.r008_deprecated import R008Deprecated
from depenemy.rules.reputation.r009_typosquatting import R009Typosquatting

__all__ = [
    "R001YoungAuthor",
    "R002YoungPackage",
    "R003LowWeeklyDownloads",
    "R004LowTotalDownloads",
    "R005StalePackage",
    "R006FewContributors",
    "R007BelowSecurityPatch",
    "R008Deprecated",
    "R009Typosquatting",
]
