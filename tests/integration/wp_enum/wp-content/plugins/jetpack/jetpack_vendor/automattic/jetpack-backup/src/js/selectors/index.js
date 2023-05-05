import APISelectors from './api';
import connectedPluginsSelectors from './connected-plugins';
import jetpackStatusSelectors from './jetpack-status';
import siteBackupSelectors from './site-backup';
import siteDataSelectors from './site-data';

const selectors = {
	...APISelectors,
	...jetpackStatusSelectors,
	...connectedPluginsSelectors,
	...siteDataSelectors,
	...siteBackupSelectors,
};

export default selectors;
