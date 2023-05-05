/* global WPCOM_sharing_counts */

// NOTE: This file intentionally does not make use of polyfills or libraries,
// including jQuery. Please keep all code as IE11-compatible vanilla ES5, and
// ensure everything is inside an IIFE to avoid global namespace pollution.
// Code follows WordPress browser support guidelines. For an up to date list,
// see https://make.wordpress.org/core/handbook/best-practices/browser-support/

( function () {
	var currentScript = document.currentScript;

	// -------------------------- UTILITY FUNCTIONS -------------------------- //

	// Helper function to load an external script.
	function loadScript( url ) {
		var script = document.createElement( 'script' );
		var prev = currentScript || document.getElementsByTagName( 'script' )[ 0 ];
		script.setAttribute( 'async', true );
		script.setAttribute( 'src', url );
		prev.parentNode.insertBefore( script, prev );
	}

	// Helper matches function (not a polyfill), compatible with IE 11.
	function matches( el, sel ) {
		if ( Element.prototype.matches ) {
			return el.matches( sel );
		}

		if ( Element.prototype.msMatchesSelector ) {
			return el.msMatchesSelector( sel );
		}
	}

	// Helper closest parent node function (not a polyfill) based on
	// https://developer.mozilla.org/en-US/docs/Web/API/Element/closest#Polyfill
	function closest( el, sel ) {
		if ( el.closest ) {
			return el.closest( sel );
		}

		var current = el;

		do {
			if ( matches( current, sel ) ) {
				return current;
			}
			current = current.parentElement || current.parentNode;
		} while ( current !== null && current.nodeType === 1 );

		return null;
	}

	// Helper function to iterate over a NodeList
	// (since IE 11 doesn't have NodeList.prototype.forEach)
	function forEachNode( list, fn ) {
		for ( var i = 0; i < list.length; i++ ) {
			var node = list[ i ];
			fn( node, i, list );
		}
	}

	// Helper function to remove a node from the DOM.
	function removeNode( node ) {
		if ( node && node.parentNode ) {
			node.parentNode.removeChild( node );
		}
	}

	// Helper functions to show/hide a node, and check its status.
	function hideNode( node ) {
		if ( node ) {
			node.style.display = 'none';
		}
	}

	function showNode( node ) {
		if ( node ) {
			node.style.removeProperty( 'display' );
		}
	}

	function isNodeHidden( node ) {
		return ! node || node.style.display === 'none';
	}

	// ------------------------------- CLASSES ------------------------------- //

	var PANE_SELECTOR = '.sharing-hidden .inner';
	var PANE_DATA_ATTR = 'data-sharing-more-button-id';

	// Implements a MoreButton class, which controls the lifecycle and behavior
	// of a "more" button and its dialog.
	function MoreButton( buttonEl ) {
		this.button = buttonEl;
		this.pane = closest( buttonEl, 'div' ).querySelector( PANE_SELECTOR );
		this.openedBy = null;
		this.recentlyOpenedByHover = false;

		MoreButton.instances.push( this );
		this.pane.setAttribute( PANE_DATA_ATTR, MoreButton.instances.length - 1 );

		this.attachHandlers();
	}

	// Keep a reference to each instance, so we can get back to it from the DOM.
	MoreButton.instances = [];

	// Delay time configs.
	MoreButton.hoverOpenDelay = 200;
	MoreButton.recentOpenDelay = 400;
	MoreButton.hoverCloseDelay = 300;

	// Use this to avoid creating new instances for buttons which already have one.
	MoreButton.instantiateOrReuse = function ( buttonEl ) {
		var pane = closest( buttonEl, 'div' ).querySelector( PANE_SELECTOR );
		var paneId = pane && pane.getAttribute( PANE_DATA_ATTR );

		var existingInstance = MoreButton.instances[ paneId ];
		if ( existingInstance ) {
			return existingInstance;
		}

		return new MoreButton( buttonEl );
	};

	// Retrieve a button instance from the pane DOM element.
	MoreButton.getButtonInstanceFromPane = function ( paneEl ) {
		var paneId = paneEl && paneEl.getAttribute( PANE_DATA_ATTR );
		return MoreButton.instances[ paneId ];
	};

	// Close all open More Button dialogs.
	MoreButton.closeAll = function () {
		for ( var i = 0; i < MoreButton.instances.length; i++ ) {
			MoreButton.instances[ i ].close();
		}
	};

	MoreButton.prototype.open = function () {
		var offset;
		var offsetParent;
		var parentOffset = [ 0, 0 ];

		function getOffsets( el ) {
			var rect = el.getBoundingClientRect();
			return [
				rect.left + ( window.scrollX || window.pageXOffset || 0 ),
				rect.top + ( window.scrollY || window.pageYOffset || 0 ),
			];
		}

		function getStyleValue( el, prop ) {
			return parseInt( getComputedStyle( el ).getPropertyValue( prop ) || 0 );
		}

		offset = getOffsets( this.button );
		offsetParent = this.button.offsetParent || document.documentElement;

		while (
			offsetParent &&
			( offsetParent === document.body || offsetParent === document.documentElement ) &&
			getComputedStyle( offsetParent ).getPropertyValue( 'position' ) === 'static'
		) {
			offsetParent = offsetParent.parentNode;
		}

		if ( offsetParent && offsetParent !== this.button && offsetParent.nodeType === 1 ) {
			parentOffset = getOffsets( offsetParent );
			parentOffset = [
				parentOffset[ 0 ] + getStyleValue( offsetParent, 'border-left-width' ),
				parentOffset[ 1 ] + getStyleValue( offsetParent, 'border-top-width' ),
			];
		}

		var positionLeft =
			offset[ 0 ] - parentOffset[ 0 ] - getStyleValue( this.button, 'margin-left' );
		var positionTop = offset[ 1 ] - parentOffset[ 1 ] - getStyleValue( this.button, 'margin-top' );

		this.pane.style.left = positionLeft + 'px';
		this.pane.style.top = positionTop + this.button.offsetHeight + 3 + 'px';

		showNode( this.pane );
	};

	MoreButton.prototype.close = function () {
		hideNode( this.pane );
		this.openedBy = null;
	};

	MoreButton.prototype.toggle = function () {
		if ( isNodeHidden( this.pane ) ) {
			this.open();
		} else {
			this.close();
		}
	};

	MoreButton.prototype.nonHoverOpen = function () {
		clearTimeout( this.openTimer );
		clearTimeout( this.closeTimer );

		if ( this.recentlyOpenedByHover ) {
			this.recentlyOpenedByHover = false;
			clearTimeout( this.hoverOpenTimer );
			this.open();
		} else {
			this.toggle();
		}
	};

	MoreButton.prototype.resetCloseTimer = function () {
		clearTimeout( this.closeTimer );
		this.closeTimer = setTimeout( this.close.bind( this ), MoreButton.hoverCloseDelay );
	};

	MoreButton.prototype.attachHandlers = function () {
		this.buttonClick = function ( event ) {
			event.preventDefault();
			event.stopPropagation();

			this.openedBy = 'click';
			this.nonHoverOpen();
		}.bind( this );

		this.buttonKeydown = function ( event ) {
			if ( event.keyCode === 13 || event.keyCode === 32 ) {
				event.preventDefault();
				event.stopPropagation();

				this.openedBy = 'keydown';
				this.nonHoverOpen();
			}
		}.bind( this );

		this.buttonEnter = function () {
			if ( ! this.openedBy ) {
				this.openTimer = setTimeout(
					function () {
						this.open();
						this.openedBy = 'hover';
						this.recentlyOpenedByHover = true;
						this.hoverOpenTimer = setTimeout(
							function () {
								this.recentlyOpenedByHover = false;
							}.bind( this ),
							MoreButton.recentOpenDelay
						);
					}.bind( this ),
					MoreButton.hoverOpenDelay
				);
			}
			clearTimeout( this.closeTimer );
		}.bind( this );

		this.buttonLeave = function () {
			if ( this.openedBy === 'hover' ) {
				this.resetCloseTimer();
			}
			clearTimeout( this.openTimer );
		}.bind( this );

		this.paneEnter = function () {
			clearTimeout( this.closeTimer );
		}.bind( this );

		this.paneLeave = function () {
			if ( this.openedBy === 'hover' ) {
				this.resetCloseTimer();
			}
		}.bind( this );

		this.documentClick = function () {
			this.close();
		}.bind( this );

		this.button.addEventListener( 'click', this.buttonClick );
		this.button.addEventListener( 'keydown', this.buttonKeydown );
		document.addEventListener( 'click', this.documentClick );

		if ( document.ontouchstart === undefined ) {
			// Non-touchscreen device: use hover/mouseout with delay
			this.button.addEventListener( 'mouseenter', this.buttonEnter );
			this.button.addEventListener( 'mouseleave', this.buttonLeave );
			this.pane.addEventListener( 'mouseenter', this.paneEnter );
			this.pane.addEventListener( 'mouseleave', this.paneLeave );
		}
	};

	// ---------------------------- SHARE COUNTS ---------------------------- //

	if ( window.sharing_js_options && window.sharing_js_options.counts ) {
		var WPCOMSharing = {
			done_urls: [],
			get_counts: function () {
				var url, requests, id, service, service_request;

				if ( 'undefined' === typeof WPCOM_sharing_counts ) {
					return;
				}

				for ( url in WPCOM_sharing_counts ) {
					id = WPCOM_sharing_counts[ url ];

					if ( 'undefined' !== typeof WPCOMSharing.done_urls[ id ] ) {
						continue;
					}

					requests = {
						// Pinterest handles share counts for both http and https
						pinterest: [
							window.location.protocol +
								'//api.pinterest.com/v1/urls/count.json?callback=WPCOMSharing.update_pinterest_count&url=' +
								encodeURIComponent( url ),
						],
					};

					for ( service in requests ) {
						if ( ! document.querySelector( 'a[data-shared=sharing-' + service + '-' + id + ']' ) ) {
							continue;
						}

						while ( ( service_request = requests[ service ].pop() ) ) {
							loadScript( service_request );
						}

						if ( window.sharing_js_options.is_stats_active ) {
							WPCOMSharing.bump_sharing_count_stat( service );
						}
					}

					WPCOMSharing.done_urls[ id ] = true;
				}
			},
			update_pinterest_count: function ( data ) {
				if ( 'undefined' !== typeof data.count && data.count * 1 > 0 ) {
					WPCOMSharing.inject_share_count(
						'sharing-pinterest-' + WPCOM_sharing_counts[ data.url ],
						data.count
					);
				}
			},
			inject_share_count: function ( id, count ) {
				forEachNode(
					document.querySelectorAll( 'a[data-shared=' + id + '] > span' ),
					function ( span ) {
						var countNode = span.querySelector( '.share-count' );
						removeNode( countNode );
						var newNode = document.createElement( 'span' );
						newNode.className = 'share-count';
						newNode.textContent = WPCOMSharing.format_count( count );
						span.appendChild( newNode );
					}
				);
			},
			format_count: function ( count ) {
				if ( count < 1000 ) {
					return count;
				}
				if ( count >= 1000 && count < 10000 ) {
					return String( count ).substring( 0, 1 ) + 'K+';
				}
				return '10K+';
			},
			bump_sharing_count_stat: function ( service ) {
				new Image().src =
					document.location.protocol +
					'//pixel.wp.com/g.gif?v=wpcom-no-pv&x_sharing-count-request=' +
					service +
					'&r=' +
					Math.random();
			},
		};
		window.WPCOMSharing = WPCOMSharing;
	}

	// ------------------------ BUTTON FUNCTIONALITY ------------------------ //
	function isUrlForCurrentHost( url ) {
		var currentDomain = window.location.protocol + '//' + window.location.hostname + '/';

		return String( url ).indexOf( currentDomain ) === 0;
	}

	function getEncodedFormFieldForSubmit( name, value ) {
		// Encode the key and value into a URI-compatible string.
		var encoded = encodeURIComponent( name ) + '=' + encodeURIComponent( value );

		// In x-www-form-urlencoded, spaces should be `+`, not `%20`.
		return encoded.replace( /%20/g, '+' );
	}

	function trackButtonClick( button ) {
		var clickCount = getClickCountForButton( button );

		setClickCountForButton( button, clickCount + 1 );
	}

	function setClickCountForButton( button, clickCount ) {
		button.setAttribute( 'jetpack-share-click-count', clickCount );
	}

	function getClickCountForButton( button ) {
		var currentClickCount = button.getAttribute( 'jetpack-share-click-count' );
		if ( currentClickCount === null ) {
			return 0;
		}

		return parseInt( currentClickCount, 10 );
	}

	function showEmailShareError( emailShareButton, sdUlGroup ) {
		var sdContent = sdUlGroup.parentElement;
		if ( ! sdContent.classList.contains( 'sd-content' ) ) {
			return;
		}

		forEachNode( sdContent.querySelectorAll( '.share-email-error' ), function ( shareEmailError ) {
			shareEmailError.parentElement.removeChild( shareEmailError );
		} );

		var newShareEmailError = document.createElement( 'div' );
		newShareEmailError.className = 'share-email-error';

		var newShareEmailErrorTitle = document.createElement( 'h6' );
		newShareEmailErrorTitle.className = 'share-email-error-title';
		newShareEmailErrorTitle.innerText = emailShareButton.getAttribute(
			'data-email-share-error-title'
		);
		newShareEmailError.appendChild( newShareEmailErrorTitle );

		var newShareEmailErrorText = document.createElement( 'p' );
		newShareEmailErrorText.className = 'share-email-error-text';
		newShareEmailErrorText.innerText = emailShareButton.getAttribute(
			'data-email-share-error-text'
		);
		newShareEmailError.appendChild( newShareEmailErrorText );

		sdContent.appendChild( newShareEmailError );
	}

	function recordEmailShareClick( emailShareTrackerUrl, emailShareNonce ) {
		var request = new XMLHttpRequest();
		request.open( 'POST', emailShareTrackerUrl, true );
		request.setRequestHeader( 'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8' );
		request.setRequestHeader( 'x-requested-with', 'XMLHttpRequest' );

		request.send( getEncodedFormFieldForSubmit( 'email-share-nonce', emailShareNonce ) );
	}

	// Sharing initialization.
	// Will run immediately or on `DOMContentLoaded`, depending on current page status.
	function init() {
		WPCOMSharing_do();
	}
	if ( document.readyState !== 'loading' ) {
		init();
	} else {
		document.addEventListener( 'DOMContentLoaded', init );
	}

	// Set up sharing again whenever a new post loads, to pick up any new buttons.
	document.body.addEventListener( 'is.post-load', WPCOMSharing_do );

	// Set up sharing, updating counts and adding all button functionality.
	function WPCOMSharing_do() {
		if ( window.WPCOMSharing ) {
			window.WPCOMSharing.get_counts();
		}

		forEachNode( document.querySelectorAll( '.sharedaddy a' ), function ( anchor ) {
			var href = anchor.getAttribute( 'href' );
			if ( href && href.indexOf( 'share=' ) !== -1 && href.indexOf( '&nb=1' ) === -1 ) {
				anchor.setAttribute( 'href', href + '&nb=1' );
			}
		} );

		// Show hidden buttons

		// Touchscreen device: use click.
		// Non-touchscreen device: use click if not already appearing due to a hover event

		forEachNode(
			document.querySelectorAll( '.sharedaddy a.sharing-anchor' ),
			function ( buttonEl ) {
				MoreButton.instantiateOrReuse( buttonEl );
			}
		);

		if ( document.ontouchstart !== undefined ) {
			document.body.classList.add( 'jp-sharing-input-touch' );
		}

		// Add click functionality
		forEachNode( document.querySelectorAll( '.sharedaddy ul' ), function ( group ) {
			if ( group.getAttribute( 'data-sharing-events-added' ) === 'true' ) {
				return;
			}
			group.setAttribute( 'data-sharing-events-added', 'true' );

			var printUrl = function ( uniqueId, urlToPrint ) {
				var iframe = document.createElement( 'iframe' );
				iframe.setAttribute(
					'style',
					'position:fixed; top:100; left:100; height:1px; width:1px; border:none;'
				);
				iframe.setAttribute( 'id', 'printFrame-' + uniqueId );
				iframe.setAttribute( 'name', iframe.getAttribute( 'id' ) );
				iframe.setAttribute( 'src', urlToPrint );
				iframe.setAttribute(
					'onload',
					'frames["printFrame-' +
						uniqueId +
						'"].focus();frames["printFrame-' +
						uniqueId +
						'"].print();'
				);
				document.body.appendChild( iframe );
			};

			// Print button
			forEachNode( group.querySelectorAll( 'a.share-print' ), function ( printButton ) {
				printButton.addEventListener( 'click', function ( event ) {
					event.preventDefault();
					event.stopPropagation();

					var ref = printButton.getAttribute( 'href' ) || '';
					var doPrint = function () {
						if ( ref.indexOf( '#print' ) === -1 ) {
							var uid = new Date().getTime();
							printUrl( uid, ref );
						} else {
							window.print();
						}
					};

					// Is the button in a dropdown?
					var pane = closest( printButton, PANE_SELECTOR );
					if ( pane ) {
						var moreButton = MoreButton.getButtonInstanceFromPane( pane );
						if ( moreButton ) {
							moreButton.close();
							doPrint();
						}
					} else {
						doPrint();
					}
				} );
			} );

			// Press This button
			forEachNode( group.querySelectorAll( 'a.share-press-this' ), function ( pressThisButton ) {
				pressThisButton.addEventListener( 'click', function ( event ) {
					event.preventDefault();
					event.stopPropagation();

					var s = '';

					if ( window.getSelection ) {
						s = window.getSelection();
					} else if ( document.getSelection ) {
						s = document.getSelection();
					} else if ( document.selection ) {
						s = document.selection.createRange().text;
					}

					if ( s ) {
						var href = pressThisButton.getAttribute( 'href' );
						pressThisButton.setAttribute( 'href', href + '&sel=' + encodeURI( s ) );
					}

					if (
						! window.open(
							pressThisButton.getAttribute( 'href' ),
							't',
							'toolbar=0,resizable=1,scrollbars=1,status=1,width=720,height=570'
						)
					) {
						document.location.href = pressThisButton.getAttribute( 'href' );
					}
				} );
			} );

			// Email button
			forEachNode( group.querySelectorAll( 'a.share-email' ), function ( emailButton ) {
				setClickCountForButton( emailButton, 0 );

				var emailShareNonce = emailButton.getAttribute( 'data-email-share-nonce' );
				var emailShareTrackerUrl = emailButton.getAttribute( 'data-email-share-track-url' );

				if (
					emailShareNonce &&
					emailShareTrackerUrl &&
					isUrlForCurrentHost( emailShareTrackerUrl )
				) {
					emailButton.addEventListener( 'click', function () {
						trackButtonClick( emailButton );

						if ( getClickCountForButton( emailButton ) > 2 ) {
							showEmailShareError( emailButton, group );
						}

						recordEmailShareClick( emailShareTrackerUrl, emailShareNonce );
					} );
				}
			} );
		} );

		forEachNode(
			document.querySelectorAll( 'li.share-email, li.share-custom a.sharing-anchor' ),
			function ( node ) {
				node.classList.add( 'share-service-visible' );
			}
		);
	}
} )();
