/**
 * Deduplicate advisories from multiple adapter sources by advisory ID.
 * Merges data from multiple sources, preferring the most complete record.
 */
export function dedupAdvisories(advisoryArrays) {
  const map = new Map();
  for (const advisories of advisoryArrays) {
    for (const adv of advisories) {
      const id = adv.id || adv.ghsaId || adv.cveId;
      if (!id) continue;
      if (!map.has(id)) {
        map.set(id, { ...adv, sources: [adv.source].filter(Boolean) });
      } else {
        const existing = map.get(id);
        const merged = mergeAdvisory(existing, adv);
        map.set(id, merged);
      }
    }
  }
  return Array.from(map.values());
}

function mergeAdvisory(a, b) {
  const sources = [...new Set([...(a.sources || []), ...(b.sources || []), b.source].filter(Boolean))];
  return {
    ...a,
    ...filterDefined(b),
    id: a.id || b.id,
    severity: pickHigherSeverity(a.severity, b.severity),
    cvssScore: a.cvssScore ?? b.cvssScore,
    references: mergeArrays(a.references, b.references),
    aliases: [...new Set([...(a.aliases || []), ...(b.aliases || [])])],
    sources,
  };
}

function filterDefined(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined && v !== null));
}

function mergeArrays(a, b) {
  return [...new Set([...(a || []), ...(b || [])])];
}

const SEVERITY_ORDER = ['unknown', 'none', 'low', 'moderate', 'medium', 'high', 'critical'];

function pickHigherSeverity(a, b) {
  const ai = SEVERITY_ORDER.indexOf((a || '').toLowerCase());
  const bi = SEVERITY_ORDER.indexOf((b || '').toLowerCase());
  return ai >= bi ? a : b;
}
