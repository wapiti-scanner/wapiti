/**
 * File: Cdnfsd_TransparentCDN_Page_View.js
 *
 * @since 0.15.0
 */
jQuery( document ).ready( function( $ ) {
	box = document.getElementById( 'tcdn_test_status' );

	if ( box ){
		box.innerHTML = transparent_configuration_strings.test_string;

		$( '#transparentcdn_test' ).on( 'click', function( e ) {
			var url = 'https://api.transparentcdn.com/v1/oauth2/access_token/',
				p = document.getElementById( 'tcdn_test_text' ),
				client_id = 'client_id' +
					'=' +
					document.getElementById( 'cdnfsd_transparentcdn_clientid' ).value,
				client_secret = 'client_secret' +
					'=' +
					document.getElementById( 'cdnfsd_transparentcdn_clientsecret' ).value,
				grant_type = 'grant_type=client_credentials',
				params = grant_type +
					'&' +
					client_id +
					'&' +
					client_secret,
				req = new XMLHttpRequest();

			e.preventDefault();

			req.open( 'POST', url, true );
			req.setRequestHeader( 'Content-type', 'application/x-www-form-urlencoded' );
			req.onreadystatechange = function(e) {
				if ( 4 == req.readyState ) {
					if ( 200 == req.status ) {
						box.innerHTML = transparent_configuration_strings.test_success;
						box.className = 'w3tc-status w3tc-success';
					} else {
						box.innerHTML = transparent_configuration_strings.test_failure;
						box.className = 'w3tc-status w3tc-error';
					}
				}
			};
			req.send( params );
		});
	}
});
