import { combineReducers } from '@wordpress/data';
import notices from 'components/global-notices/store/reducer';
import features from './feature';
import jetpackSettings from './jetpack-settings';
import siteData from './site-data';
import userData from './user-data';

const reducer = combineReducers( {
	siteData,
	jetpackSettings,
	userData,
	features,
	notices,
} );

export default reducer;
