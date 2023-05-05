import restApi from '@automattic/jetpack-api';

export const FETCH_WORDADS_SETTINGS = 'FETCH_WORDADS_SETTINGS';
export const UPDATE_WORDADS_SETTINGS = 'UPDATE_WORDADS_SETTINGS';

/**
 * fetchJetpackSettings action
 *
 * @returns {object} - an action object.
 */
export const fetchWordAdsSettings = () => {
	return {
		type: FETCH_WORDADS_SETTINGS,
	};
};

/**
 * updateJetpackSettings action
 *
 * @param {*} settings - Jetpack settings object.
 * @returns {object} - an action object.
 */
export const updateWordAdsSettings = settings => {
	return {
		type: UPDATE_WORDADS_SETTINGS,
		settings,
	};
};

export default {
	[ FETCH_WORDADS_SETTINGS ]: function () {
		return restApi.fetchWordAdsSettings();
	},
	[ UPDATE_WORDADS_SETTINGS ]: function ( action ) {
		return restApi.updateWordAdsSettings( action.settings );
	},
};
