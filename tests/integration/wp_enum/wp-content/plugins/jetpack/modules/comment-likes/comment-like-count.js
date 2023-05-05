jQuery( document ).ready( function ( $ ) {
	var jsonAPIbase = 'https://public-api.wordpress.com/rest/v1',
		APIqueue = [];

	function getCommentLikeCounts() {
		$( '.comment-like-count' ).each( function () {
			var blogId = $( this ).attr( 'data-blog-id' ),
				commentId = $( this ).attr( 'data-comment-id' );

			APIqueue.push( '/sites/' + blogId + '/comments/' + commentId + '/likes' );
		} );

		return $.ajax( {
			type: 'GET',
			url: jsonAPIbase + '/batch',
			dataType: 'jsonp',
			data: 'urls[]=' + APIqueue.map( encodeURIComponent ).join( '&urls[]=' ),
			success: function ( response ) {
				for ( var path in response ) {
					if ( ! response[ path ].error_data ) {
						var urlPieces = path.split( '/' ),
							commentId = urlPieces[ 4 ],
							likeCount = response[ path ].found;

						if ( likeCount < 1 ) {
							return;
						}

						$( '#comment-like-count-' + commentId )
							.find( '.like-count' )
							.hide()
							.text( likeCount )
							.fadeIn();
					}
				}
			},
			error: function () {},
		} );
	}

	getCommentLikeCounts();
} );
