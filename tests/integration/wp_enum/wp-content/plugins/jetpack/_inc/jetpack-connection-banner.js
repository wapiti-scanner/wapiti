/* global jp_banner */

( function ( $ ) {
	var fullScreenContainer = $( '.jp-connect-full__container' ),
		fullScreenDismiss = $( '.jp-connect-full__dismiss, .jp-connect-full__dismiss-paragraph' ),
		wpWelcomeNotice = $( '#welcome-panel' ),
		connectionBanner = $( '.jp-connection-banner' ),
		connectionBannerDismiss = $( '.jp-connection-banner__dismiss' );

	// Move the banner below the WP Welcome notice on the dashboard
	$( window ).on( 'load', function () {
		wpWelcomeNotice.insertBefore( connectionBanner );
	} );

	// Dismiss the connection banner via AJAX
	connectionBannerDismiss.on( 'click', function () {
		$( connectionBanner ).hide();

		var data = {
			action: 'jetpack_connection_banner',
			nonce: jp_banner.connectionBannerNonce,
			dismissBanner: true,
		};

		$.post( jp_banner.ajax_url, data, function ( response ) {
			if ( true !== response.success ) {
				$( connectionBanner ).show();
			}
		} );
	} );

	/**
	 * Full-screen connection prompt
	 */
	fullScreenDismiss.on( 'click', function () {
		$( fullScreenContainer ).hide();
	} );

	$( document ).keyup( function ( e ) {
		if ( e.code === 'Escape' ) {
			$( fullScreenDismiss ).click();
		}
	} );
} )( jQuery );
