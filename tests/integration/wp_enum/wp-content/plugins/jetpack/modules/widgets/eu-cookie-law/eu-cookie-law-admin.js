/* eslint no-var: 0 */

( function ( $ ) {
	var $document = $( document );

	$document.on( 'ready', function () {
		var maybeShowNotice = function ( e, policyUrl ) {
			var $policyUrl = $( policyUrl || this ).closest( '.eu-cookie-law-widget-policy-url' );

			if ( $policyUrl.find( 'input[type="radio"][value="default"]' ).is( ':checked' ) ) {
				$policyUrl.find( '.notice.default-policy' ).css( 'display', 'block' );
				$policyUrl.find( '.notice.custom-policy' ).hide();
			} else {
				$policyUrl.find( '.notice.default-policy' ).hide();
				$policyUrl.find( '.notice.custom-policy' ).css( 'display', 'block' );
			}
		};

		$document.on(
			'click',
			'.eu-cookie-law-widget-policy-url input[type="radio"]',
			maybeShowNotice
		);
		$document.on( 'widget-updated widget-added', function ( e, widget ) {
			var widgetId = $( widget ).attr( 'id' );
			if ( widgetId && widgetId.indexOf( 'eu_cookie_law_widget' ) !== -1 ) {
				maybeShowNotice( null, $( '#' + widgetId + ' .eu-cookie-law-widget-policy-url' ) );
			}
		} );
		$( '.eu-cookie-law-widget-policy-url' ).each( maybeShowNotice );
	} );
} )( jQuery );
