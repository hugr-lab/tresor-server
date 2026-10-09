import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'index',
    'getting-started',
    'configuration',
    'state',
    'encryption',
    'references',
    'variables',
    'token-exchange',
    'console',
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
    'development',
  ],
};

export default sidebars;
