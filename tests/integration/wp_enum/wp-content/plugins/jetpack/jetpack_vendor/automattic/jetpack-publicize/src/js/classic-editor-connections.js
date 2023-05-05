import { _n } from '@wordpress/i18n';
import jQuery from 'jquery';

const { ajaxUrl, connectionsUrl } = window.jetpackSocialClassicEditorConnections;

jQuery( function ( $ ) {
	let fetchingConnTest = false;
	const publicizeConnTestStart = function () {
		if ( ! fetchingConnTest ) {
			$.post( ajaxUrl, { action: 'test_publicize_conns' }, publicizeConnTestComplete );
			fetchingConnTest = true;
		}
	};

	let timer;
	window.addEventListener( 'focus', () => {
		if ( timer ) {
			clearTimeout( timer );
		}
		timer = setTimeout( publicizeConnTestStart, 2000 );
	} );

	const publicizeConnTestComplete = function ( response ) {
		fetchingConnTest = false;
		const testsSelector = $( '#pub-connection-tests' );
		testsSelector
			.removeClass( 'test-in-progress' )
			.removeClass( 'below-h2' )
			.removeClass( 'error' )
			.removeClass( 'publicize-token-refresh-message' )
			.html( '' );

		const brokenConnections = ! response.data
			? 0
			: response.data.reduce( ( brokenCount, testResult ) => {
					if ( ! testResult.connectionTestPassed ) {
						$( '#wpas-submit-' + testResult.unique_id )
							.prop( 'checked', false )
							.prop( 'disabled', true );
						return brokenCount + 1;
					}
					return brokenCount;
			  }, 0 );
		if ( brokenConnections ) {
			/* translators: %s is the link to the connections page in Calypso */
			const msg = _n(
				'One of your social connections is broken. Reconnect it on the <a href="%s" rel="noopener noreferrer" target="_blank">connection management</a> page.',
				'Some of your social connections are broken. Reconnect them on the <a href="%s" rel="noopener noreferrer" target="_blank">connection management</a> page.',
				brokenConnections,
				'jetpack-publicize-pkg'
			);

			testsSelector
				.addClass( 'below-h2' )
				.addClass( 'error' )
				.addClass( 'publicize-token-refresh-message' )
				.append( msg.replace( '%s', connectionsUrl ) );
		}
	};

	// If we have the #pub-connection-tests div present, kick off the connection test
	if ( $( '#pub-connection-tests' ).length ) {
		publicizeConnTestStart();
	}
} );
