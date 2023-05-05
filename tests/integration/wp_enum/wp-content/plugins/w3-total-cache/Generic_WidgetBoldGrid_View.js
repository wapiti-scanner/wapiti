jQuery( document ).ready( function( $ ) {
	$( window ).on( 'message', function( event ) {
		var originalEvent  = event.originalEvent,
			expectedOrigin = document.location.protocol + '//' + document.location.hostname,
			message;

		if ( originalEvent.origin !== expectedOrigin ) {
			return;
		}

		if ( originalEvent.data ) {
			try {
				message = $.parseJSON( originalEvent.data );
			} catch ( e ) {
				return;
			}
		}

		if ( ! message || 'undefined' === typeof message.action ) {
			return;
		}

		if (message.action == 'install-plugin') {
			window.location = $('#w3tc-boldgrid-install').prop('href');
		}
	});
});
