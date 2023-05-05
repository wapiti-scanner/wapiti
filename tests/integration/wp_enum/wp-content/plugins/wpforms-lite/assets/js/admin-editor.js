;( function( $ ) {

	$( function() {

		// Close modal.
		var wpformsModalClose = function() {

			if ( $( '#wpforms-modal-select-form' ).length ) {
				$( '#wpforms-modal-select-form' ).get( 0 ).selectedIndex = 0;
				$( '#wpforms-modal-checkbox-title, #wpforms-modal-checkbox-description' ).prop( 'checked', false );
			}

			$( '#wpforms-modal-backdrop, #wpforms-modal-wrap' ).css( 'display', 'none' );
			$( document.body ).removeClass( 'modal-open' );
		};

		// Open modal when media button is clicked.
		$( document ).on( 'click', '.wpforms-insert-form-button', function( event ) {

			event.preventDefault();
			$( '#wpforms-modal-backdrop, #wpforms-modal-wrap' ).css( 'display', 'block' );
			$( document.body ).addClass( 'modal-open' );
		} );

		// Close modal on close or cancel links.
		$( document ).on( 'click', '#wpforms-modal-close, #wpforms-modal-cancel a', function( event ) {

			event.preventDefault();
			wpformsModalClose();
		} );

		// Insert shortcode into TinyMCE.
		$( document ).on( 'click', '#wpforms-modal-submit', function( event ) {

			event.preventDefault();

			var shortcode;

			shortcode = '[wpforms id="' + $( '#wpforms-modal-select-form' ).val() + '"';

			if ( $( '#wpforms-modal-checkbox-title' ).is( ':checked' ) ) {
				shortcode = shortcode + ' title="true"';
			}

			if ( $( '#wpforms-modal-checkbox-description' ).is( ':checked' ) ) {
				shortcode = shortcode + ' description="true"';
			}

			shortcode = shortcode + ']';

			wp.media.editor.insert( shortcode );
			wpformsModalClose();
		} );

	} );

}( jQuery ) );
