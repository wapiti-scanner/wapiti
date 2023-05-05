/* global WPGroHo:true, Gravatar */
( function () {
	var extend = function ( out ) {
		out = out || {};

		for ( var i = 1; i < arguments.length; i++ ) {
			if ( ! arguments[ i ] ) continue;

			for ( var key in arguments[ i ] ) {
				if ( arguments[ i ].hasOwnProperty( key ) ) out[ key ] = arguments[ i ][ key ];
			}
		}

		return out;
	};

	WPGroHo = extend(
		{
			my_hash: '',
			data: {},
			renderers: {},
			syncProfileData: function ( hash, id ) {
				var hashElements;

				if ( ! WPGroHo.data[ hash ] ) {
					WPGroHo.data[ hash ] = {};
					hashElements = document.querySelectorAll( 'div.grofile-hash-map-' + hash + ' span' );
					for ( var i = 0; i < hashElements.length; i++ ) {
						WPGroHo.data[ hash ][ hashElements[ i ].className ] = hashElements[ i ].innerText;
					}
				}

				WPGroHo.appendProfileData( WPGroHo.data[ hash ], hash, id );
			},
			appendProfileData: function ( data, hash, id ) {
				for ( var key in data ) {
					if ( 'function' === typeof WPGroHo.renderers[ key ] ) {
						return WPGroHo.renderers[ key ]( data[ key ], hash, id, key );
					}

					var card = document.getElementById( id );
					if ( card ) {
						var heading = card.querySelector( 'h4' );
						if ( heading ) {
							var extra = document.createElement( 'p' );
							extra.className = 'grav-extra ' + key;
							extra.innerHTML = data[ key ];

							heading.insertAdjacentElement( 'afterend', extra );
						}
					}
				}
			},
		},
		WPGroHo || {}
	);

	var jetpackHovercardsInit = function () {
		if ( 'undefined' === typeof Gravatar ) {
			return;
		}

		Gravatar.profile_cb = function ( h, d ) {
			WPGroHo.syncProfileData( h, d );
		};

		Gravatar.my_hash = WPGroHo.my_hash;
		Gravatar.init( 'body', '#wpadminbar' );
	};

	if ( document.readyState === 'interactive' || document.readyState === 'complete' ) {
		jetpackHovercardsInit();
	} else {
		document.addEventListener( 'DOMContentLoaded', jetpackHovercardsInit );
	}
} )();
