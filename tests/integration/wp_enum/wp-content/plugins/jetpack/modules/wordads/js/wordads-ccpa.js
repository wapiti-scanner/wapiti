/**
 * Outputs Javascript to handle California IP detection, consent modal, and setting of default cookies.
 */
( function () {
	/* global ccpaSettings */

	// Minimal Mozilla Cookie library.
	// https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie/Simple_document.cookie_framework
	var cookieLib = {
		getItem: function ( e ) {
			return (
				( e &&
					decodeURIComponent(
						document.cookie.replace(
							new RegExp(
								'(?:(?:^|.*;)\\s*' +
									encodeURIComponent( e ).replace( /[\-\.\+\*]/g, '\\$&' ) +
									'\\s*\\=\\s*([^;]*).*$)|^.*$'
							),
							'$1'
						)
					) ) ||
				null
			);
		},
		setItem: function ( e, o, n, t, r, i ) {
			if ( ! e || /^(?:expires|max\-age|path|domain|secure)$/i.test( e ) ) {
				return ! 1;
			}
			var c = '';
			if ( n ) {
				switch ( n.constructor ) {
					case Number:
						c = n === 1 / 0 ? '; expires=Fri, 31 Dec 9999 23:59:59 GMT' : '; max-age=' + n;
						break;
					case String:
						c = '; expires=' + n;
						break;
					case Date:
						c = '; expires=' + n.toUTCString();
				}
			}
			return (
				( 'rootDomain' !== r && '.rootDomain' !== r ) ||
					( r =
						( '.rootDomain' === r ? '.' : '' ) +
						document.location.hostname.split( '.' ).slice( -2 ).join( '.' ) ),
				( document.cookie =
					encodeURIComponent( e ) +
					'=' +
					encodeURIComponent( o ) +
					c +
					( r ? '; domain=' + r : '' ) +
					( t ? '; path=' + t : '' ) +
					( i ? '; secure' : '' ) ),
				! 0
			);
		},
	};

	// Implement IAB USP API.
	window.__uspapi = function ( command, version, callback ) {
		// Validate callback.
		if ( typeof callback !== 'function' ) {
			return;
		}

		// Validate the given command.
		if ( command !== 'getUSPData' || version !== 1 ) {
			callback( null, false );
			return;
		}

		// Check for GPC. If set, override any stored cookie.
		if ( navigator.globalPrivacyControl ) {
			callback( { version: 1, uspString: '1YYN' }, true );
			return;
		}

		// Check for cookie.
		var consent = cookieLib.getItem( 'usprivacy' );

		// Invalid cookie.
		if ( null === consent ) {
			callback( null, false );
			return;
		}

		// Everything checks out. Fire the provided callback with the consent data.
		callback( { version: 1, uspString: consent }, true );
	};

	var setDefaultOptInCookie = function () {
		var value = ccpaSettings.defaultOptInCookieString;
		var domain =
			'.wordpress.com' === location.hostname.slice( -14 ) ? '.rootDomain' : location.hostname;
		cookieLib.setItem( 'usprivacy', value, 365 * 24 * 60 * 60, '/', domain );
	};

	var setDefaultOptOutCookie = function () {
		var value = ccpaSettings.defaultOptOutCookieString;
		var domain =
			'.wordpress.com' === location.hostname.slice( -14 ) ? '.rootDomain' : location.hostname;
		cookieLib.setItem( 'usprivacy', value, 24 * 60 * 60, '/', domain );
	};

	var setDefaultNotApplicableCookie = function () {
		var value = '1---';
		var domain =
			'.wordpress.com' === location.hostname.slice( -14 ) ? '.rootDomain' : location.hostname;
		cookieLib.setItem( 'usprivacy', value, 24 * 60 * 60, '/', domain );
	};

	var setCcpaAppliesCookie = function ( value ) {
		var domain =
			'.wordpress.com' === location.hostname.slice( -14 ) ? '.rootDomain' : location.hostname;
		cookieLib.setItem( 'ccpa_applies', value, 24 * 60 * 60, '/', domain );
	};

	var injectLoadingMessage = function () {
		var wrapper = document.createElement( 'div' );
		document.body.insertBefore( wrapper, document.body.firstElementChild );
		wrapper.outerHTML =
			'<div id="ccpa-loading" class="cleanslate ccpa__loading-wrapper">' +
			'<div class="ccpa__loading-overlay">' +
			'<span class="ccpa__loading-message">' +
			ccpaSettings.strings.pleaseWait +
			'...</span>' +
			'</div>' +
			'</div>';
	};

	var destroyModal = function () {
		var node = document.querySelector( '#ccpa-modal' );

		if ( node ) {
			node.parentElement.removeChild( node );
		}
	};

	var injectModal = function () {
		destroyModal();

		injectLoadingMessage();

		var request = new XMLHttpRequest();
		request.open(
			'GET',
			ccpaSettings.ajaxUrl + '?action=privacy_optout_markup&security=' + ccpaSettings.ajaxNonce,
			true
		);
		request.onreadystatechange = function () {
			if ( 4 === this.readyState ) {
				if ( 200 === this.status ) {
					document.getElementById( 'ccpa-loading' ).remove();
					var wrapper = document.createElement( 'div' );
					document.body.insertBefore( wrapper, document.body.firstElementChild );
					wrapper.outerHTML = this.response;
					document.getElementById( 'ccpa-opt-out' ).focus();

					var optOut = document.querySelector( '#ccpa-modal .opt-out' );
					optOut.addEventListener( 'click', function ( e ) {
						var post = new XMLHttpRequest();
						post.open( 'POST', ccpaSettings.ajaxUrl, true );
						post.setRequestHeader(
							'Content-Type',
							'application/x-www-form-urlencoded; charset=UTF-8'
						);
						post.onreadystatechange = function () {
							if ( 4 === this.readyState ) {
								if ( 200 === this.status ) {
									var result = JSON.parse( this.response );

									if ( result && result.success ) {
										// Note: Cooke is set in HTTP response from POST, so only need to update the toggle switch state.
										if ( result.data ) {
											e.target.parentNode.classList.add( 'is-checked' );
											e.target.parentNode.parentNode.classList.add( 'is-checked' );
										} else {
											e.target.parentNode.classList.remove( 'is-checked' );
											e.target.parentNode.parentNode.classList.remove( 'is-checked' );
										}
									}
								}
							}
						};
						post.send(
							'action=privacy_optout&optout=' +
								e.target.checked +
								'&security=' +
								ccpaSettings.ajaxNonce
						);
					} );

					// Set initial toggle status based on cookie data.
					var usprivacyCookie = cookieLib.getItem( 'usprivacy' );
					var optout = usprivacyCookie && 'Y' === usprivacyCookie[ 2 ];
					var toggle = document.querySelector( '#ccpa-modal .opt-out' );

					toggle.checked = optout;

					if ( optout ) {
						toggle.parentNode.classList.add( 'is-checked' );
						toggle.parentNode.parentNode.classList.add( 'is-checked' );
					}

					var buttons = document.querySelectorAll( '#ccpa-modal .components-button' );
					Array.prototype.forEach.call( buttons, function ( el ) {
						el.addEventListener( 'click', function () {
							destroyModal();
						} );
					} );
				}
			}
		};

		request.send();
	};

	var dispatchInitializedEvent = function ( ccpaApplies ) {
		// Dispatches a custom event with data indicating if the CCPA applies or not once it has been determined.
		// Sites can listen for this event and do additional processing, e.g. showing or hiding additional elements.
		var event = document.createEvent( 'CustomEvent' );
		event.initCustomEvent( 'wordads-ccpa-initialized', true, false, { ccpaApplies: ccpaApplies } );
		document.dispatchEvent( event );
	};

	var initialize = function ( ccpaApplies, usprivacyCookie ) {
		// Get any Do Not Sell links on the page.
		var dnsLinks = document.querySelectorAll( '.ccpa-do-not-sell' );

		// No usprivacy cookie, so we need to set it.
		if ( null === usprivacyCookie ) {
			if ( ccpaApplies ) {
				if ( 0 === dnsLinks.length ) {
					// Could not find a Do Not Sell link as required, so default to opt-OUT just to be safe.
					setDefaultOptOutCookie();
				} else {
					// Found a Do Not Sell link, so set default opt-in.
					setDefaultOptInCookie();
				}
			} else {
				// CCPA does not apply.
				setDefaultNotApplicableCookie();
			}
		}

		// If CCPA does not apply, and we are not overriding it for admins, then we can stop here.
		if ( ! ccpaApplies && 'false' === ccpaSettings.forceApplies ) {
			dispatchInitializedEvent( false );
			return;
		}

		// Displays Do Not Sell links and adds handlers to display the modal when clicked.
		Array.prototype.forEach.call( dnsLinks, function ( dnsLink ) {
			dnsLink.addEventListener( 'click', function ( e ) {
				e.preventDefault();

				if ( ! ccpaSettings.stylesLoaded ) {
					// Load wordads-ccpa.min.css.
					var ccpaCss = document.createElement( 'link' );
					ccpaCss.rel = 'stylesheet';
					ccpaCss.type = 'text/css';
					ccpaCss.href = ccpaSettings.ccpaCssUrl;
					document.getElementsByTagName( 'HEAD' )[ 0 ].appendChild( ccpaCss );

					ccpaSettings.stylesLoaded = true;
				}

				injectModal();
			} );

			// Make the link visible.
			dnsLink.style.display = '';
		} );

		// CCPA applies (or we're forcing it to display for admins). Let any listeners know.
		dispatchInitializedEvent( true );
	};

	// Setup CCPA on DOM loaded.
	document.addEventListener( 'DOMContentLoaded', function () {
		// Look for usprivacy cookies first.
		var usprivacyCookie = cookieLib.getItem( 'usprivacy' );

		// Found a usprivacy cookie.
		if ( null !== usprivacyCookie ) {
			// CCPA does not apply.
			if ( '1---' === usprivacyCookie ) {
				initialize( false, usprivacyCookie );
			} else {
				// CCPA applies.
				initialize( true, usprivacyCookie );
			}

			// No more processing needed.
			return;
		}

		// We don't have a usprivacy cookie, so check to see if we have a CCPA applies cookie.
		var ccpaCookie = cookieLib.getItem( 'ccpa_applies' );

		// No CCPA applies cookie found, so we'll need to geolocate if this visitor is from applicable US state.
		// This needs to happen client side because we do not have region geo data in our $SERVER headers,
		// only country data -- therefore we can't vary cache on the region.
		if ( null === ccpaCookie ) {
			var request = new XMLHttpRequest();
			request.open( 'GET', 'https://public-api.wordpress.com/geo/', true );

			request.onreadystatechange = function () {
				if ( 4 === this.readyState ) {
					if ( 200 === this.status ) {
						// Got a geo response. Parse out the region data.
						var data = JSON.parse( this.response );
						var region = data.region ? data.region.toLowerCase() : '';
						var ccpaApplies =
							[ 'california', 'colorado', 'connecticut', 'utah', 'virginia' ].indexOf( region ) >
							-1;

						// Set CCPA applies cookie. This keeps us from having to make a geo request too frequently.
						setCcpaAppliesCookie( ccpaApplies );

						// Perform the rest of the initialization.
						initialize( ccpaApplies, null );
					} else {
						// Geolocation request failed, so default to CCPA applies just to be safe.
						setCcpaAppliesCookie( true );

						// Perform the rest of the initialization.
						initialize( true, null );
					}
				}
			};

			// Send the geo request.
			request.send();
		} else {
			// We found a CCPA applies cookie. Continue with initialization.
			initialize( 'true' === ccpaCookie, null );
		}
	} );
} )();
