/* global brightcove, brightcoveData */
( function ( $ ) {
	var script = document.createElement( 'script' ),
		tld = 'co.jp' === brightcoveData.tld ? 'co.jp' : 'com',
		timer = false;

	// Load Brightcove script
	script.src = 'https://sadmin.brightcove.' + tld + '/js/BrightcoveExperiences.js';
	script.type = 'text/javascript';
	script.language = 'JavaScript';
	document.head.appendChild( script );

	// Start detection for Brightcove script loading in its object
	try_brightcove();

	// Detect if Brightcove script has loaded and bind some events once loaded
	function try_brightcove() {
		clearTimeout( timer );

		if ( 'object' === typeof brightcove ) {
			$( document ).ready( brightcove.createExperiences );
			$( 'body' ).on( 'post-load', brightcove.createExperiences );

			brightcove.createExperiences();
		} else {
			timer = setTimeout( try_brightcove, 100 );
		}
	}
} )( jQuery );
