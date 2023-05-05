/*eslint lodash/import-scope: [2, "method"]*/
import { __ } from '@wordpress/i18n';
import uniqueId from 'lodash/uniqueId';

export const CREATE_NOTICE = 'CREATE_NOTICE';
export const REMOVE_NOTICE = 'REMOVE_NOTICE';

/**
 * Create global notice
 *
 * @param {*} status - success, error, info or warning.
 * @param {*} text - the text to show.
 * @param {*} options - Options.
 * @returns {object} - action object.
 */
export function createNotice( status, text, options = {} ) {
	const notice = {
		id: options.id || uniqueId(),
		duration: options.duration ?? 2000,
		showDismiss: typeof options.showDismiss === 'boolean' ? options.showDismiss : true,
		isPersistent: options.isPersistent || false,
		displayOnNextPage: options.displayOnNextPage || false,
		status: status,
		text: text,
	};

	return {
		type: CREATE_NOTICE,
		notice: notice,
	};
}

/**
 * Remove notice by ID
 *
 * @param {*} noticeId - noticeID.
 * @returns {object} - action object.
 */
export function removeNotice( noticeId ) {
	return { type: REMOVE_NOTICE, notice: { id: noticeId } };
}

export const successNotice = createNotice.bind( null, 'is-success' );
export const errorNotice = createNotice.bind( null, 'is-error' );
export const infoNotice = createNotice.bind( null, 'is-info' );
export const warningNotice = createNotice.bind( null, 'is-warning' );
export const updatingNotice = ( text = __( 'Updating settings…', 'jetpack-wordads' ) ) =>
	createNotice( 'is-info', text, { duration: 30000, id: 'search-updating-settings' } );
export const removeUpdatingNotice = () => removeNotice( 'search-updating-settings' );

export default {
	createNotice,
	removeNotice,
	successNotice,
	errorNotice,
	warningNotice,
	updatingNotice,
	removeUpdatingNotice,
};
