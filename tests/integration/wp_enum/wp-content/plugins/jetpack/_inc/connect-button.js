/* global jpConnect */

const connectButtons = document.querySelectorAll( '.jp-connect-button, #jp-connect-button--alt' );

connectButtons.forEach( function ( connectButton ) {
	connectButton.addEventListener( 'click', function ( event ) {
		event.preventDefault();
		startConnectionFlow( connectButton );
	} );
} );

function startConnectionFlow( connectButton ) {
	connectButton.classList.add( 'button-disabled' );

	const searchParams = new URLSearchParams(
		connectButton.getAttribute( 'href' ).split( '?' )[ 1 ]
	);
	window.location =
		searchParams && searchParams.get( 'from' )
			? jpConnect.connectUrl
					.split( '?page=jetpack' )
					.join( '?page=jetpack&from=' + searchParams.get( 'from' ) )
			: jpConnect.connectUrl;
}
