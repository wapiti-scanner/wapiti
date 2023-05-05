/**
 * Binds iframe messages from the Customizer to SearchApp.
 *
 * @param {boolean} expanded - whether jetpack_search section is expanded and visible.
 */
function postSectionMessage( expanded ) {
	// window.wp.customize.previewer.preview is not available until both customize and customize.previewer are ready.
	window.wp.customize.previewer.preview
		.targetWindow()
		.postMessage( { key: 'jetpackSearchSectionOpen', expanded: expanded }, '*' ); // Assume ES5 envorinment.
}

/**
 * Adds functionality for Jetpack Search section detection in the Customizer.
 */
function init() {
	window.wp.customize.bind( 'ready', function () {
		// window.wp.customize.previewer will emit 'ready' multiple times, not just during initialization.
		window.wp.customize.previewer.bind( 'ready', function () {
			// window.wp.customize.previewer.loading is deinstanced after initial load.
			if ( window.wp.customize.previewer.loading ) {
				window.wp.customize.previewer.loading.done( function () {
					postSectionMessage( window.wp.customize.section( 'jetpack_search' ).expanded() );
				} );
			}

			// If the Jetpack Search section is opened/closed, emit a message to open/close the modal.
			window.wp.customize.section( 'jetpack_search' ).expanded.bind( function () {
				postSectionMessage( window.wp.customize.section( 'jetpack_search' ).expanded() );
			} );

			// If Customizer values have changed while Jetpack Search section is open, emit a message to open the modal.
			window.wp.customize.bind( 'change', function () {
				if ( window.wp.customize.section( 'jetpack_search' ).expanded() ) {
					postSectionMessage( true );
				}
			} );
		} );
	} );
}

if ( document.readyState !== 'loading' ) {
	init();
} else {
	document.addEventListener( 'DOMContentLoaded', init );
}
