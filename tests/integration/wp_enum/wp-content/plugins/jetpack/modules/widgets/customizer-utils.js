/* global wp, gapi, FB, twttr, PaypalExpressCheckout */

/**
 * Utilities to work with widgets in Customizer.
 */

/**
 * Checks whether this Customizer supports partial widget refresh.
 * @returns {boolean}
 */
wp.customizerHasPartialWidgetRefresh = function () {
	return (
		'object' === typeof wp &&
		'function' === typeof wp.customize &&
		'object' === typeof wp.customize.selectiveRefresh &&
		'object' === typeof wp.customize.widgetsPreview &&
		'function' === typeof wp.customize.widgetsPreview.WidgetPartial
	);
};

/**
 * Verifies that the placed widget ID contains the widget name.
 * @param {object} placement
 * @param {string} widgetName
 * @returns {*|boolean}
 */
wp.isJetpackWidgetPlaced = function ( placement, widgetName ) {
	return placement.partial.widgetId && 0 === placement.partial.widgetId.indexOf( widgetName );
};

/**
 * Bind events for selective refresh in Customizer.
 */
( function ( $ ) {
	$( document ).ready( function () {
		if ( wp && wp.customize && wp.customizerHasPartialWidgetRefresh() ) {
			// Refresh widget contents when a partial is rendered.
			wp.customize.selectiveRefresh.bind( 'partial-content-rendered', function ( placement ) {
				if ( placement.container ) {
					// Refresh Google+
					if (
						wp.isJetpackWidgetPlaced( placement, 'googleplus-badge' ) &&
						'object' === typeof gapi &&
						gapi.person &&
						'function' === typeof gapi.person.go
					) {
						gapi.person.go( placement.container[ 0 ] );
					}

					// Refresh Facebook XFBML
					else if (
						wp.isJetpackWidgetPlaced( placement, 'facebook-likebox' ) &&
						'object' === typeof FB &&
						'object' === typeof FB.XFBML &&
						'function' === typeof FB.XFBML.parse
					) {
						FB.XFBML.parse( placement.container[ 0 ], function () {
							var $fbContainer = $( placement.container[ 0 ] ).find( '.fb_iframe_widget' ),
								fbWidth = $fbContainer.data( 'width' ),
								fbHeight = $fbContainer.data( 'height' );
							$fbContainer.find( 'span' ).css( { width: fbWidth, height: fbHeight } );
							setTimeout( function () {
								$fbContainer
									.find( 'iframe' )
									.css( { width: fbWidth, height: fbHeight, position: 'relative' } );
							}, 1 );
						} );
					}

					// Refresh Twitter
					else if (
						wp.isJetpackWidgetPlaced( placement, 'twitter_timeline' ) &&
						'object' === typeof twttr &&
						'object' === typeof twttr.widgets &&
						'function' === typeof twttr.widgets.load
					) {
						twttr.widgets.load( placement.container[ 0 ] );
					} else if ( wp.isJetpackWidgetPlaced( placement, 'eu_cookie_law_widget' ) ) {
						// Refresh EU Cookie Law
						if ( $( '#eu-cookie-law' ).hasClass( 'top' ) ) {
							$( '.widget_eu_cookie_law_widget' ).addClass( 'top' );
						} else {
							$( '.widget_eu_cookie_law_widget' ).removeClass( 'top' );
						}
						placement.container.fadeIn();
					} else if ( wp.isJetpackWidgetPlaced( placement, 'jetpack_simple_payments_widget' ) ) {
						// Refresh Simple Payments Widget
						try {
							var buttonId = $( '.jetpack-simple-payments-button', placement.container )
								.attr( 'id' )
								.replace( '_button', '' );
							PaypalExpressCheckout.renderButton( null, null, buttonId, null );
						} catch ( e ) {
							// PaypalExpressCheckout may fail.
							// For the same usage, see also:
							// https://github.com/Automattic/jetpack/blob/6c1971e6bed7d3df793392a7a58ffe0afaeeb5fe/modules/simple-payments/simple-payments.php#L111
						}
					}
				}
			} );

			// Refresh widgets when they're moved.
			wp.customize.selectiveRefresh.bind( 'partial-content-moved', function ( placement ) {
				if ( placement.container ) {
					// Refresh Twitter timeline iframe, since it has to be re-built.
					if (
						wp.isJetpackWidgetPlaced( placement, 'twitter_timeline' ) &&
						placement.container.find( 'iframe.twitter-timeline:not([src]):first' ).length
					) {
						placement.partial.refresh();
					} else if ( wp.isJetpackWidgetPlaced( placement, 'jetpack_simple_payments_widget' ) ) {
						// Refresh Simple Payments Widget
						placement.partial.refresh();
					}
				}
			} );
		}
	} );
} )( jQuery );
