( function ( $ ) {
	var resizeTimer;

	function responsiveVideos() {
		$( '.jetpack-video-wrapper' )
			.find( 'embed, iframe, object' )
			.each( function () {
				var _this, videoWidth, videoHeight, videoRatio, videoWrapper, videoMargin, containerWidth;

				_this = $( this );
				videoMargin = 0;

				if (
					_this.parents( '.jetpack-video-wrapper' ).prev( 'p' ).css( 'text-align' ) === 'center'
				) {
					videoMargin = '0 auto';
				}

				if ( ! _this.attr( 'data-ratio' ) ) {
					_this
						.attr( 'data-ratio', this.height / this.width )
						.attr( 'data-width', this.width )
						.attr( 'data-height', this.height )
						.css( {
							display: 'block',
							margin: videoMargin,
						} );
				}

				videoWidth = _this.attr( 'data-width' );
				videoHeight = _this.attr( 'data-height' );
				videoRatio = _this.attr( 'data-ratio' );
				videoWrapper = _this.parent();
				containerWidth = videoWrapper.width();

				if ( videoRatio === 'Infinity' ) {
					videoWidth = '100%';
				}

				_this.removeAttr( 'height' ).removeAttr( 'width' );

				if ( videoWidth > containerWidth ) {
					_this.width( containerWidth ).height( containerWidth * videoRatio );
				} else {
					_this.width( videoWidth ).height( videoHeight );
				}
			} );
	}

	$( document ).ready( function () {
		$( window )
			.on( 'load.jetpack', responsiveVideos )
			.on( 'resize.jetpack', function () {
				clearTimeout( resizeTimer );
				resizeTimer = setTimeout( responsiveVideos, 500 );
			} )
			.on( 'post-load.jetpack', responsiveVideos )
			.resize();
	} );
} )( jQuery );
