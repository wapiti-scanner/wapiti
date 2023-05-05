import { combineReducers } from '@wordpress/data';
import API from './api';
import assets from './assets';
import connectedPlugins from './connected-plugins';
import jetpackStatus from './jetpack-status';
import siteBackupPolicies from './site-backup-policies';
import siteBackupSize from './site-backup-size';
import siteBackupStorage from './site-backup-storage';
import siteData from './site-data';

const reducer = combineReducers( {
	connectedPlugins,
	API,
	jetpackStatus,
	assets,
	siteData,
	siteBackupSize,
	siteBackupPolicies,
	siteBackupStorage,
} );

export default reducer;
