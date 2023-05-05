// Clear URL - remove wpforms_form_id
( function() {
	var loc = window.location,
		query = loc.search;

	if ( query.indexOf( 'wpforms_form_id=' ) !== -1 ) {
		query = query.replace( /([&?]wpforms_form_id=[0-9]*$|wpforms_form_id=[0-9]*&|[?&]wpforms_form_id=[0-9]*(?=#))/, '' );
		history.replaceState( {}, null, loc.origin + loc.pathname + query );
	}
}() );

( function( $ ) {
	$( function() {
		if ( $( 'div.wpforms-confirmation-scroll' ).length ) {
			$( 'html,body' ).animate(
				{ scrollTop: ( $( 'div.wpforms-confirmation-scroll' ).offset().top ) - 100 },
				1000
			);
		}
	} );
}( jQuery ) );
