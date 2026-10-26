import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';
import fs from 'node:fs';
import path from 'node:path';

// Docs for tresor-server - the production duckdb-secrets/1 service behind tresor. The same look as tresor's
// site (hugr-lab.github.io/tresor/); published by this repo's Pages workflow to
// https://hugr-lab.github.io/tresor-server/. The protocol is tresor's: this site links to it, never restates it.

// The same docs are built twice: for GitHub Pages (default) and for hugr-lab.com on IONOS (DOCS_TARGET=ionos).
// The IONOS copy makes no request to another host (its CSP, and the site's privacy notice, say so): links only.
const ionos = process.env.DOCS_TARGET === 'ionos';
// While the hugr-lab.com copy exists (DOCS_IONOS on), pages.yml sets DOCS_CANONICAL for the GitHub Pages build:
// its pages then name the hugr-lab.com copy as canonical (src/theme/SiteMetadata), and it has no sitemap of its own.
const canonicalBase = ionos ? '' : process.env.DOCS_CANONICAL ?? '';
const site = ionos
  ? {url: 'https://hugr-lab.com', baseUrl: '/docs/tresor-server/', home: 'https://hugr-lab.com/', impressum: 'https://hugr-lab.com/impressum/', datenschutz: 'https://hugr-lab.com/datenschutz/'}
  : {url: 'https://hugr-lab.github.io', baseUrl: '/tresor-server/', home: 'https://hugr-lab.github.io/', impressum: 'https://hugr-lab.github.io/impressum/', datenschutz: 'https://hugr-lab.github.io/datenschutz/'};

// Versions (spec 035): pages.yml snapshots each release tag's docs at deploy time (versions.json, versioned_docs/:
// generated, gitignored). The latest release serves at the root; main's docs as "Next" under /next/. Only the
// latest release is indexed (the owner's decision, 2026-10-26): next and older releases get noindex and leave
// the sitemap. Without versions.json (a pull request's build) the current docs are the only version.
const versionsFile = path.join(__dirname, 'versions.json');
const released: string[] = fs.existsSync(versionsFile) ? JSON.parse(fs.readFileSync(versionsFile, 'utf8')) : [];
const noIndexVersions = Object.fromEntries(
  released.length ? ['current', ...released.slice(1)].map((v) => [v, {noIndex: true}]) : [],
);

const config: Config = {
  title: 'tresor-server',
  tagline: 'The secrets service behind tresor: state in your database, material under your KMS, on Azure first.',
  favicon: 'img/tresor-favicon.svg',

  url: site.url,
  baseUrl: site.baseUrl,
  trailingSlash: true,
  baseUrlIssueBanner: false,
  customFields: {docsTarget: ionos ? 'ionos' : 'github', canonicalBase},

  organizationName: 'hugr-lab',
  projectName: 'tresor-server',

  // 'throw': docs-build.yml is the PR gate for website/, and a gate that passes a broken link gates nothing
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          routeBasePath: '/',
          editUrl: 'https://github.com/hugr-lab/tresor-server/tree/main/website/',
          showLastUpdateTime: true,
          versions: noIndexVersions,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
        sitemap: canonicalBase ? false : undefined,
      } satisfies Preset.Options,
    ],
  ],

  themes: ['@docusaurus/theme-mermaid'],

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  themeConfig: {
    metadata: [
      {name: 'keywords', content: 'DuckDB, secrets, tresor, OIDC, Entra ID, Azure Key Vault, Container Apps, PostgreSQL, SQL Server'},
      {name: 'description', content: 'The production duckdb-secrets/1 service behind tresor: state in SQLite, PostgreSQL or SQL Server, material sealed under a KMS key or left in Azure Key Vault.'},
    ],
    navbar: {
      title: 'tresor-server',
      logo: {
        alt: 'tresor',
        src: 'img/tresor-icon.svg',
        srcDark: 'img/tresor-icon-dark.svg',
        href: '/',
      },
      items: [
        {type: 'docSidebar', sidebarId: 'docsSidebar', position: 'left', label: 'Docs'},
        {to: '/configuration/', label: 'Configuration', position: 'left'},
        ...(released.length ? [{type: 'docsVersionDropdown' as const, position: 'right' as const}] : []),
        {href: 'https://hugr-lab.com/tresor/', label: 'tresor', position: 'right'},
        {href: 'https://hugr-lab.com/', label: 'hugr-lab.com', position: 'right'},
        {href: 'https://github.com/hugr-lab/tresor-server', label: 'GitHub', position: 'right'},
      ],
    },
    colorMode: {
      defaultMode: 'light',
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Getting started', to: '/getting-started/'},
            {label: 'Configuration', to: '/configuration/'},
            {label: 'Azure Container Apps', to: '/azure-container-apps/'},
            {label: 'Security', to: '/security/'},
          ],
        },
        {
          title: 'tresor',
          items: [
            {label: 'tresor', href: 'https://hugr-lab.com/tresor/'},
            {label: 'tresor docs', href: 'https://hugr-lab.com/docs/tresor/'},
            {label: 'The protocol', href: 'https://hugr-lab.com/docs/tresor/protocol/'},
            {label: 'Microsoft Entra ID', href: 'https://hugr-lab.com/docs/tresor/entra/'},
          ],
        },
        {
          title: 'Hugr Lab',
          items: [
            {label: 'Main site', href: 'https://hugr-lab.com/'},
            {label: 'GitHub', href: 'https://github.com/hugr-lab/tresor-server'},
          ],
        },
        {
          title: 'Legal',
          items: [
            {label: 'Impressum', href: site.impressum},
            {label: 'Datenschutz', href: site.datenschutz},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Hugr Lab. Business Source License 1.1.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['sql', 'bash', 'json', 'yaml'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
