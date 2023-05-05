( function () {
	function recalculate() {
		if ( this.complete ) {
			// Support for lazy loading: if there is a lazy-src attribute and it's value
			// is not the same as the current src we should wait until the image load event
			var lazySrc = this.getAttribute( 'data-lazy-src' );
			if ( lazySrc && this.src !== lazySrc ) {
				this.addEventListener( 'onload', recalculate );
				return;
			}

			// Copying CSS width/height into element attributes.
			var width = this.width;
			var height = this.height;
			if ( width && width > 0 && height && height > 0 ) {
				this.setAttribute( 'width', width );
				this.setAttribute( 'height', height );

				reset_for_retina( this );
			}
		} else {
			this.addEventListener( 'onload', recalculate );
			return;
		}
	}

	/**
	 * For images lacking explicit dimensions and needing them, try to add them.
	 */
	var restore_dims = function () {
			var elements = document.querySelectorAll( 'img[data-recalc-dims]' );
			for ( var i = 0; i < elements.length; i++ ) {
				recalculate.call( elements[ i ] );
			}
		},
		/**
		 * Modify given image's markup so that devicepx-jetpack.js will act on the image and it won't be reprocessed by this script.
		 */
		reset_for_retina = function ( img ) {
			img.removeAttribute( 'data-recalc-dims' );
			img.removeAttribute( 'scale' );
		};

	/**
	 * Check both when page loads, and when IS is triggered.
	 */
	if ( typeof window !== 'undefined' && typeof document !== 'undefined' ) {
		// `DOMContentLoaded` may fire before the script has a chance to run
		if ( document.readyState === 'loading' ) {
			document.addEventListener( 'DOMContentLoaded', restore_dims );
		} else {
			restore_dims();
		}
	}

	document.body.addEventListener( 'is.post-load', restore_dims );
} )();
