/* global site_logo_header_classes */
/**
 * JS for handling the "Display Header Text" setting's realtime preview.
 */
( function ( $ ) {
	var api = wp.customize,
		$classes = site_logo_header_classes.classes;

	api( 'site_logo_header_text', function ( value ) {
		value.bind( function ( to ) {
			if ( true === to ) {
				$( $classes ).css( {
					position: 'static',
					clip: 'auto',
				} );
			} else {
				$( $classes ).css( {
					position: 'absolute',
					clip: 'rect(1px 1px 1px 1px)',
				} );
			}
		} );
	} );
} )( jQuery );
