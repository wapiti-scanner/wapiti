/* global pagenow, ajaxurl, CalypsoifyOpts */
( function ( $ ) {
	$( window ).load( function () {
		// On Plugins.php
		if ( 'plugins' === pagenow ) {
			// pagenow === $current_screen->id
			// Remove | and () from the plugins filter bar
			$.each( $( 'ul.subsubsub li' ), function ( i, el ) {
				var li = $( el );
				li.html( li.html().replace( '|', '' ).replace( '(', '' ).replace( ')', '' ) );
			} );

			// Add in the AJAX-y goodness for toggling autoupdates.
			$( 'input.autoupdate-toggle' ).change( function ( event ) {
				var el = event.target;

				el.disabled = true;
				el.classList.add( 'is-toggling' );

				jQuery.post(
					ajaxurl,
					{
						action: 'jetpack_toggle_autoupdate',
						type: 'plugins',
						slug: el.dataset.slug,
						active: el.checked,
						_wpnonce: CalypsoifyOpts.nonces.autoupdate_plugins,
					},
					function () {
						// Add something to test and confirm that `el.dataset.slug` is missing from `response.data` ?
						el.disabled = false;
						el.classList.remove( 'is-toggling' );
					}
				);
			} );
		}

		$( '#wp-admin-bar-root-default' ).on( 'click', 'li', function ( event ) {
			location.href = $( event.target ).closest( 'a' ).attr( 'href' );
		} );

		$( '#wp-admin-bar-top-secondary' ).on( 'click', 'li#wp-admin-bar-my-account', function (
			event
		) {
			location.href = $( event.target ).closest( 'a' ).attr( 'href' );
		} );

		if ( document && document.location && document.location.search ) {
			var params_array = document.location.search.substr( 1 ).split( '&' ),
				params_object = {},
				body = $( document.body ),
				i,
				key_value,
				pluginEl;

			if ( params_array && params_array.length ) {
				for ( i = 0; i < params_array.length; i++ ) {
					key_value = params_array[ i ].split( '=' );
					params_object[ key_value[ 0 ] ] = key_value[ 1 ];
				}

				if ( params_object.s && params_object[ 'modal-mode' ] && params_object.plugin ) {
					pluginEl = $(
						'.plugin-card-' + params_object.plugin + ' .thickbox.open-plugin-details-modal'
					);
					if ( pluginEl && pluginEl.length ) {
						pluginEl.click();
					}
				}
			}

			body.on( 'thickbox:iframe:loaded', function () {
				$( '#TB_window' ).on( 'click', 'button#TB_closeWindowButton', function () {
					$( '#TB_closeWindowButton' ).click();
				} );
			} );
		}
	} );
} )( jQuery );
