/*eslint lodash/import-scope: [2, "method"]*/
import { select } from '@wordpress/data';
import { __ } from '@wordpress/i18n';
import {
	removeUpdatingNotice,
	updatingNotice,
	errorNotice,
	successNotice,
} from 'components/global-notices/store/actions';
import pick from 'lodash/pick';
import { STORE_ID } from '../../store';
import {
	fetchWordAdsSettings,
	updateWordAdsSettings as updateJetpackSettingsControl,
} from '../controls';

export const SET_WORDADS_SETTINGS = 'SET_WORDADS_SETTINGS';
export const TOGGLE_WORDADS_MODULE = 'TOGGLE_WORDADS_MODULE';

/**
 * Yield actions to update WordAds Settings
 *
 * @param {object} settings - settings to apply.
 * @yields {object} - an action object.
 * @returns {object} - an action object.
 */
export function* updateJetpackSettings( settings ) {
	try {
		yield updatingNotice();
		yield setUpdatingJetpackSettings();
		yield setJetpackSettings( settings );
		yield updateJetpackSettingsControl( settings );
		const updatedSettings = yield fetchWordAdsSettings();
		yield setJetpackSettings( updatedSettings );
		return successNotice( __( 'Updated settings.', 'jetpack-wordads' ) );
	} catch ( e ) {
		const oldSettings = pick( select( STORE_ID ).getWordAdsModuleStatus(), [ 'module_active' ] );
		yield setJetpackSettings( oldSettings );
		return errorNotice( __( 'Error Update settings…', 'jetpack-wordads' ) );
	} finally {
		yield removeUpdatingNotice();
		yield setUpdatingJetpackSettingsDone();
	}
}

/**
 * Set state updating action
 *
 * @returns {object} - an action object.
 */
export function setUpdatingJetpackSettings() {
	return setJetpackSettings( { is_updating: true } );
}

/**
 * Set state updating finished
 *
 * @returns {object} - an action object.
 */
export function setUpdatingJetpackSettingsDone() {
	return setJetpackSettings( { is_updating: false } );
}

/**
 * Set Jetpack settings action
 *
 * @param {object} options - Jetpack settings.
 * @returns {object} - an action object.
 */
export function setJetpackSettings( options ) {
	return { type: SET_WORDADS_SETTINGS, options };
}

export default { updateJetpackSettings, setJetpackSettings };
