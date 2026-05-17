import semver from 'semver';

/**
 * Check if installedVersion falls within vulnerable_versions range.
 * vulnerable_versions is a semver range string like ">=4.0.0 <4.17.21".
 */
export function isVulnerable(installedVersion, vulnerableVersions) {
  if (!vulnerableVersions || !installedVersion) return false;
  try {
    const clean = semver.coerce(installedVersion);
    if (!clean) return false;
    return semver.satisfies(clean, vulnerableVersions, { includePrerelease: false });
  } catch {
    return false;
  }
}

/**
 * Find nearest patched version from patchedVersions semver range.
 * Returns the lower bound of the patched range if parseable.
 */
export function extractFixVersion(patchedVersions) {
  if (!patchedVersions) return null;
  try {
    const minVersion = semver.minVersion(patchedVersions);
    return minVersion ? minVersion.version : patchedVersions;
  } catch {
    return patchedVersions;
  }
}

/**
 * Compare two versions. Returns -1, 0, 1.
 */
export function compareVersions(a, b) {
  try {
    return semver.compare(semver.coerce(a), semver.coerce(b));
  } catch {
    return 0;
  }
}
