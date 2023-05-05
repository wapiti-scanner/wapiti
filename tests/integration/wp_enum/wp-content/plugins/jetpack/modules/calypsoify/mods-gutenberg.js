/* eslint-disable no-var */
/* global wp, calypsoifyGutenberg */

jQuery( function ( $ ) {
	if (
		wp &&
		wp.data &&
		wp.data.select &&
		! wp.data.select( 'core/edit-post' ).isFeatureActive( 'fullscreenMode' )
	) {
		wp.data.dispatch( 'core/edit-post' ).toggleFeature( 'fullscreenMode' );
	}

	var editPostHeaderInception = setInterval( function () {
		// Legacy selector for Gutenberg plugin < v7.7
		var legacyButton = $( '.edit-post-fullscreen-mode-close__toolbar a' );
		// Updated selector for Gutenberg plugin => v7.7
		var newButton = $( '.edit-post-header .edit-post-fullscreen-mode-close' );

		var hasLegacyButton = legacyButton && legacyButton.length;
		var hasNewButton = newButton && newButton.length;

		// Keep trying until we find one of the close buttons.
		if ( ! ( hasLegacyButton || hasNewButton ) ) {
			return;
		}
		clearInterval( editPostHeaderInception );

		var theButton = legacyButton;
		if ( hasNewButton ) {
			theButton = newButton;
		}
		theButton.attr( 'href', calypsoifyGutenberg.closeUrl );
	} );

	$( 'body.revision-php a' ).each( function () {
		var href = $( this ).attr( 'href' );
		$( this ).attr( 'href', href.replace( '&classic-editor', '' ) );
	} );
} );
