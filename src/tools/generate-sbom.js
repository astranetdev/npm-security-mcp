import { z } from 'zod';
import { NpmRegistryAdapter } from '../adapters/npm-registry.js';
import { randomUUID } from 'node:crypto';

export const generateSbomSchema = z.object({
  package_json: z.string().min(1),
  format: z.enum(['cyclonedx', 'spdx']).optional().default('cyclonedx'),
});

const registry = new NpmRegistryAdapter();

export async function generateSbom({ package_json, format = 'cyclonedx' }) {
  let pkg;
  try {
    pkg = JSON.parse(package_json);
  } catch {
    return '## SBOM Error\n\nInvalid JSON in package.json';
  }

  const deps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
  };

  const depNames = Object.keys(deps);
  if (!depNames.length) {
    return '## SBOM\n\nNo dependencies found.';
  }

  // Resolve metadata for each dependency
  const components = await Promise.all(
    depNames.map(async (name) => {
      const rangeSpec = deps[name];
      try {
        const meta = await registry.getPackage(name);
        const version = meta['dist-tags']?.latest;
        const vMeta = version ? meta.versions?.[version] : null;
        return {
          name,
          version,
          description: meta.description || '',
          license: vMeta?.license || meta.license || 'NOASSERTION',
          purl: `pkg:npm/${encodeURIComponent(name)}@${version}`,
          dist: vMeta?.dist || {},
          homepage: meta.homepage || '',
          repository: meta.repository?.url || '',
          maintainers: meta.maintainers || [],
        };
      } catch {
        return {
          name,
          version: rangeSpec.replace(/^[\^~>=<*]/, ''),
          description: '',
          license: 'NOASSERTION',
          purl: `pkg:npm/${encodeURIComponent(name)}`,
          dist: {},
        };
      }
    })
  );

  let sbom;
  if (format === 'cyclonedx') {
    sbom = buildCycloneDX(pkg, components);
  } else {
    sbom = buildSPDX(pkg, components);
  }

  return `## SBOM Generated (${format.toUpperCase()})\n\n\`\`\`json\n${JSON.stringify(sbom, null, 2)}\n\`\`\``;
}

function buildCycloneDX(pkg, components) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'npm-security-mcp', name: 'npm-security-mcp', version: '1.0.0' }],
      component: {
        type: 'application',
        name: pkg.name || 'unknown',
        version: pkg.version || '0.0.0',
      },
    },
    components: components.map(c => ({
      type: 'library',
      name: c.name,
      version: c.version,
      description: c.description,
      purl: c.purl,
      licenses: c.license && c.license !== 'NOASSERTION'
        ? [{ license: { id: c.license } }]
        : [],
      hashes: [
        ...(c.dist.shasum ? [{ alg: 'SHA-1', content: c.dist.shasum }] : []),
        ...(c.dist.integrity ? [{ alg: 'SHA-512', content: c.dist.integrity.replace('sha512-', '') }] : []),
      ],
      externalReferences: [
        ...(c.homepage ? [{ type: 'website', url: c.homepage }] : []),
        ...(c.repository ? [{ type: 'vcs', url: c.repository }] : []),
        ...(c.dist.tarball ? [{ type: 'distribution', url: c.dist.tarball }] : []),
      ],
      supplier: c.maintainers?.[0]?.name
        ? { name: c.maintainers[0].name, contact: c.maintainers[0].email ? [{ email: c.maintainers[0].email }] : [] }
        : undefined,
    })),
  };
}

function buildSPDX(pkg, components) {
  const docName = pkg.name || 'unknown';
  const spdxVersion = 'SPDX-2.3';

  return {
    spdxVersion,
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: docName,
    documentNamespace: `https://spdx.org/spdxdocs/${docName}-${randomUUID()}`,
    creationInfo: {
      created: new Date().toISOString(),
      creators: ['Tool: npm-security-mcp-1.0.0'],
    },
    packages: [
      {
        SPDXID: 'SPDXRef-Package-root',
        name: pkg.name || 'unknown',
        versionInfo: pkg.version || '0.0.0',
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        primaryPackagePurpose: 'APPLICATION',
      },
      ...components.map((c, i) => ({
        SPDXID: `SPDXRef-Package-${i}`,
        name: c.name,
        versionInfo: c.version,
        downloadLocation: c.dist.tarball || 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: c.license || 'NOASSERTION',
        licenseDeclared: c.license || 'NOASSERTION',
        copyrightText: 'NOASSERTION',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: c.purl,
          },
        ],
        checksums: [
          ...(c.dist.shasum ? [{ algorithm: 'SHA1', checksumValue: c.dist.shasum }] : []),
        ],
      })),
    ],
    relationships: [
      { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-Package-root' },
      ...components.map((_, i) => ({
        spdxElementId: 'SPDXRef-Package-root',
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: `SPDXRef-Package-${i}`,
      })),
    ],
  };
}
