import { IDCScreen } from '@automattic/jetpack-idc';
import * as WPElement from '@wordpress/element';
import React from 'react';

import './admin-bar.scss';
import './style.scss';

/**
 * The initial renderer function.
 */
function render() {
	const container = document.getElementById( 'jp-identity-crisis-container' );

	if ( null === container || ! window.hasOwnProperty( 'JP_IDENTITY_CRISIS__INITIAL_STATE' ) ) {
		return;
	}

	const {
		WP_API_root,
		WP_API_nonce,
		wpcomHomeUrl,
		currentUrl,
		redirectUri,
		tracksUserData,
		tracksEventData,
		isSafeModeConfirmed,
		consumerData,
		isAdmin,
		possibleDynamicSiteUrlDetected,
	} = window.JP_IDENTITY_CRISIS__INITIAL_STATE;

	if ( ! isSafeModeConfirmed ) {
		// @todo: Remove fallback when we drop support for WP 6.1
		const component = (
			<IDCScreen
				wpcomHomeUrl={ wpcomHomeUrl }
				currentUrl={ currentUrl }
				apiRoot={ WP_API_root }
				apiNonce={ WP_API_nonce }
				redirectUri={ redirectUri }
				tracksUserData={ tracksUserData || {} }
				tracksEventData={ tracksEventData }
				customContent={
					consumerData.hasOwnProperty( 'customContent' ) ? consumerData.customContent : {}
				}
				isAdmin={ isAdmin }
				logo={ consumerData.hasOwnProperty( 'logo' ) ? consumerData.logo : undefined }
				possibleDynamicSiteUrlDetected={ possibleDynamicSiteUrlDetected }
			/>
		);
		if ( WPElement.createRoot ) {
			WPElement.createRoot( container ).render( component );
		} else {
			WPElement.render( component, container );
		}
	}
}

render();
