/* global FB, jpfbembed */
( function ( window ) {
	var facebookEmbed = function () {
		var fbroot, src, newScript, firstScript;

		if ( 'undefined' !== typeof FB && FB.XFBML ) {
			FB.XFBML.parse();
		} else {
			fbroot = document.createElement( 'div' );
			fbroot.id = 'fb-root';
			document.getElementsByTagName( 'body' )[ 0 ].appendChild( fbroot );

			src = '//connect.facebook.net/' + jpfbembed.locale + '/sdk.js#xfbml=1';
			if ( jpfbembed.appid ) {
				src += '&appId=' + jpfbembed.appid;
			}
			src += '&version=v2.3';

			newScript = document.createElement( 'script' );
			newScript.setAttribute( 'src', src );
			firstScript = document.querySelector( 'script' );
			firstScript.parentNode.insertBefore( newScript, firstScript );
		}
	};

	window.fbAsyncInit = function () {
		FB.init( {
			appId: jpfbembed.appid,
			version: 'v2.3',
		} );

		FB.XFBML.parse();
	};

	if ( 'undefined' !== typeof infiniteScroll ) {
		document.body.addEventListener( 'post-load', facebookEmbed );
	}

	facebookEmbed();
} )( window );
