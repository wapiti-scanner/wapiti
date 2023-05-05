/* global ajaxurl, contact_info_api_key_ajax_obj */

( function ( $ ) {
	$( document ).on( 'change', '.jp-contact-info-showmap', function () {
		var $checkbox = $( this ),
			isChecked = $checkbox.is( ':checked' );

		$checkbox.closest( '.widget' ).find( '.jp-contact-info-admin-map' ).toggle( isChecked );
	} );

	$( document ).on( 'widget-synced', function ( event, widgetContainer ) {
		// This event fires for all widgets, so restrict this to Contact Info widgets and the API key input.
		if (
			! widgetContainer.is( '[id*="widget_contact_info"]' ) ||
			! $( document.activeElement ).is( 'input[id*="apikey"]' )
		) {
			return;
		}

		event.preventDefault();

		var $apikey_input = widgetContainer.find( 'input[id*="apikey"]' );

		$.post(
			ajaxurl,
			{
				_ajax_nonce: contact_info_api_key_ajax_obj.nonce,
				action: 'customize-contact-info-api-key',
				apikey: $apikey_input.val(),
			},
			function ( data ) {
				var $map_element = $apikey_input
					.closest( '.jp-contact-info-admin-map' )
					.parent()
					.find( '.jp-contact-info-embed-map' );
				var $warning_span = $map_element.find( '[class*="notice"]' );

				if ( '1' !== data.result ) {
					if ( $warning_span.length === 0 ) {
						$map_element.append(
							'<span class="notice notice-warning" style="display: block;">' +
								data.result +
								'</span>'
						);
					} else if ( $warning_span.text() !== data.result ) {
						$warning_span.text( data.result );
					}
				} else {
					$map_element.empty();
				}
			}
		);
	} );
} )( window.jQuery );
