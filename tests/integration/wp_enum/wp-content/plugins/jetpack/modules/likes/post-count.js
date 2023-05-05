window.wpPostLikeCount = window.wpPostLikeCount || {};

( function ( $ ) {
	window.wpPostLikeCount = jQuery.extend( window.wpPostLikeCount, {
		jsonAPIbase: 'https://public-api.wordpress.com/rest/v1',
		APIqueue: [],

		wpPostLikeCount: function () {
			$( '.post-like-count' ).each( function () {
				var post_id = $( this ).attr( 'data-post-id' );
				var blog_id = $( this ).attr( 'data-blog-id' );
				window.wpPostLikeCount.APIqueue.push(
					'/sites/' + blog_id + '/posts/' + post_id + '/likes'
				);
			} );
			window.wpPostLikeCount.getCounts();
		},

		showCount: function ( post_id, count ) {
			if ( count > 0 ) {
				$( '#post-like-count-' + post_id )
					.find( '.comment-count' )
					.hide();
				$( '#post-like-count-' + post_id )
					.find( '.comment-count' )
					.text( count );
				$( '#post-like-count-' + post_id )
					.find( '.comment-count' )
					.fadeIn();
			}
		},

		getCounts: function () {
			var batchRequest = {
				path: '/batch',
				data: '',
				success: function ( response ) {
					for ( var path in response ) {
						if ( ! response[ path ].error_data ) {
							var urlPieces = path.split( '/' ); // pieces[4] = post id;
							var post_id = urlPieces[ 4 ];
							window.wpPostLikeCount.showCount( post_id, response[ path ].found );
						}
					}
				},
				error: function (/*response*/) {},
			};

			var amp = '';
			for ( var i = 0; i < window.wpPostLikeCount.APIqueue.length; i++ ) {
				if ( i > 0 ) {
					amp = '&';
				}
				batchRequest.data += amp + 'urls[]=' + window.wpPostLikeCount.APIqueue[ i ];
			}

			window.wpPostLikeCount.request( batchRequest );
		},
	} );
} )( jQuery );

jQuery( document ).ready( function (/*$*/) {
	window.wpPostLikeCount.wpPostLikeCount();
} );
