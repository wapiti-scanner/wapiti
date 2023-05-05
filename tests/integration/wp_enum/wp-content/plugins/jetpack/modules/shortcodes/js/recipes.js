/* global jetpack_recipes_vars */
( function ( $ ) {
	$( window ).load( function () {
		$( '.jetpack-recipe-print a' ).click( function ( event ) {
			event.preventDefault();

			// Print the DIV.
			$( this ).closest( '.jetpack-recipe' ).printThis( {
				pageTitle: jetpack_recipes_vars.pageTitle,
				loadCSS: jetpack_recipes_vars.loadCSS,
			} );
		} );
	} );
} )( jQuery );
