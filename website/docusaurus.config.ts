import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// Docs for tresor-server - the production duckdb-secrets/1 service behind tresor. The same look as tresor's
// site (hugr-lab.github.io/tresor/); published by this repo's Pages workflow to
// https://hugr-lab.github.io/tresor-server/. The protocol is tresor's: this site links to it, never restates it.

const config: Config = {
  title: 'tresor-server',
  tagline: 'The secrets service behind tresor: state in your database, material under your KMS, on Azure first.',
  favicon: 'img/favicon.ico',

  url: 'https://hugr-lab.github.io',
  baseUrl: '/tresor-server/',
  trailingSlash: true,

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
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
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
        alt: 'Hugr Lab',
        src: 'img/logo-circle.svg',
        href: '/',
      },
      items: [
        {type: 'docSidebar', sidebarId: 'docsSidebar', position: 'left', label: 'Docs'},
        {to: '/configuration/', label: 'Configuration', position: 'left'},
        {href: 'https://hugr-lab.github.io/tresor/', label: 'tresor', position: 'right'},
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
            {label: 'tresor', href: 'https://hugr-lab.github.io/tresor/'},
            {label: 'The protocol', href: 'https://hugr-lab.github.io/tresor/protocol/'},
            {label: 'Microsoft Entra ID', href: 'https://hugr-lab.github.io/tresor/entra/'},
          ],
        },
        {
          title: 'Hugr Lab',
          items: [
            {label: 'Main site', href: 'https://hugr-lab.github.io/'},
            {label: 'GitHub', href: 'https://github.com/hugr-lab/tresor-server'},
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
