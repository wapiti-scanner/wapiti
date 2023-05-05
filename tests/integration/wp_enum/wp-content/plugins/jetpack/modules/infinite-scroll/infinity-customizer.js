/* globals wp */
( function ( $ ) {
	/**
	 * Ready, set, go!
	 */
	$( document ).ready( function () {
		// Integrate with Selective Refresh in the Customizer.
		if ( 'undefined' !== typeof wp && wp.customize && wp.customize.selectiveRefresh ) {
			/**
			 * Handle rendering of selective refresh partials.
			 *
			 * Make sure that when a partial is rendered, the Jetpack post-load event
			 * will be triggered so that any dynamic elements will be re-constructed,
			 * such as ME.js elements, Photon replacements, social sharing, and more.
			 * Note that this is applying here not strictly to posts being loaded.
			 * If a widget contains a ME.js element and it is previewed via selective
			 * refresh, the post-load would get triggered allowing any dynamic elements
			 * therein to also be re-constructed.
			 *
			 * @param {wp.customize.selectiveRefresh.Placement} placement
			 */
			wp.customize.selectiveRefresh.bind( 'partial-content-rendered', function ( placement ) {
				var content;
				if ( 'string' === typeof placement.addedContent ) {
					content = placement.addedContent;
				} else if ( placement.container ) {
					content = $( placement.container ).html();
				}

				if ( content ) {
					$( document.body ).trigger( 'post-load', { html: content } );
				}
			} );

			/*
			 * Add partials for posts added via infinite scroll.
			 *
			 * This is unnecessary when MutationObserver is supported by the browser
			 * since then this will be handled by Selective Refresh in core.
			 */
			if ( 'undefined' === typeof MutationObserver ) {
				$( document.body ).on( 'post-load', function ( e, response ) {
					var rootElement = null;
					if ( response.html && -1 !== response.html.indexOf( 'data-customize-partial' ) ) {
						if ( window.infiniteScroll.settings.id ) {
							rootElement = $( '#' + window.infiniteScroll.settings.id );
						}
						wp.customize.selectiveRefresh.addPartials( rootElement );
					}
				} );
			}
		}
	} );
} )( jQuery ); // Close closure
