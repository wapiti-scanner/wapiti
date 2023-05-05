import jQuery from 'jquery';

jQuery( function ( $ ) {
	const state = window.jetpackSocialClassicEditorInitialState ?? {};
	const form = $( '#publicize-form' );

	if ( ! state || state.sharesRemaining > state.numberOfConnections ) {
		return;
	}

	const checkboxes = $( '#publicize-form' ).find( 'input[type="checkbox"]' );

	// If we're all out of shares, disable all connections and call it a day.
	if ( state.sharesRemaining === 0 ) {
		checkboxes.each( function () {
			$( this ).parent().addClass( 'wpas-disabled' );
			$( this ).prop( 'disabled', true );
		} );

		return;
	}

	form.click( function ( event ) {
		const target = $( event.target );

		if ( ! target.is( 'input' ) || target.is( ':disabled' ) ) {
			return;
		}

		const enabledConnections = form.find( 'input[type="checkbox"]:checked' );
		const outOfConnections = enabledConnections.length >= state.sharesRemaining;

		checkboxes.each( function () {
			// Don't do anything for the current target.
			if ( this.id === target.attr( 'id' ) ) {
				return;
			}

			// If it's checked, don't change anything.
			if ( this.checked ) {
				return;
			}

			$( this ).parent().toggleClass( 'wpas-disabled', outOfConnections );
			$( this ).prop( 'disabled', outOfConnections );
		} );
	} );
} );
