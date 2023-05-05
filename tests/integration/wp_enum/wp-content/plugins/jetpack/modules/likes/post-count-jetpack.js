window.wpPostLikeCount = window.wpPostLikeCount || {};

( function ( $ ) {
	window.wpPostLikeCount = jQuery.extend( window.wpPostLikeCount, {
		request: function ( options ) {
			return $.ajax( {
				type: 'GET',
				url: window.wpPostLikeCount.jsonAPIbase + options.path,
				dataType: 'jsonp',
				data: options.data,
				success: function ( response ) {
					options.success( response );
				},
				error: function ( response ) {
					options.error( response );
				},
			} );
		},
	} );
} )( jQuery );
