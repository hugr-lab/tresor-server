import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'index',
    'getting-started',
    'docker',
    'configuration',
    'state',
    'encryption',
    'references',
    'variables',
    'generated',
    'token-exchange',
    'console',
    'console-guide',
    'vault',
    'aws',
    'gcp',
    'azure-container-apps',
    'kubernetes',
    'operations',
    {
      type: 'category',
      label: 'Administration',
      link: {type: 'doc', id: 'administration/index'},
      items: [
        'administration/commands',
        'administration/configuration',
        'administration/issuers-and-sources',
        'administration/kek',
        'administration/data-keys',
        'administration/credentials',
        'administration/upgrading',
        'administration/backup-restore',
        'administration/incidents',
      ],
    },
    'observability',
    'security',
    'support',
    'development',
  ],
};

export default sidebars;
