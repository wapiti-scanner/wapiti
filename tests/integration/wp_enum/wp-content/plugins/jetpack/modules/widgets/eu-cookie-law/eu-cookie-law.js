( function () {
	var cookieValue = document.cookie.replace(
			/(?:(?:^|.*;\s*)eucookielaw\s*\=\s*([^;]*).*$)|^.*$/,
			'$1'
		),
		overlay = document.getElementById( 'eu-cookie-law' ),
		widget = document.querySelector( '.widget_eu_cookie_law_widget' ),
		inCustomizer = widget && widget.hasAttribute( 'data-customize-widget-id' ),
		getScrollTop,
		initialScrollPosition,
		scrollFunction;

	if ( null === widget || null === overlay ) {
		return;
	}

	/**
	 * Gets the amount that the window is scrolled.
	 *
	 * @return int The distance from the top of the document.
	 */
	getScrollTop = function () {
		return Math.abs( document.body.getBoundingClientRect().y );
	};

	if ( overlay.classList.contains( 'top' ) ) {
		widget.classList.add( 'top' );
	}

	if ( overlay.classList.contains( 'ads-active' ) ) {
		var adsCookieValue = document.cookie.replace(
			/(?:(?:^|.*;\s*)personalized-ads-consent\s*\=\s*([^;]*).*$)|^.*$/,
			'$1'
		);
		if ( '' !== cookieValue && '' !== adsCookieValue && ! inCustomizer ) {
			overlay.parentNode.removeChild( overlay );
		}
	} else if ( '' !== cookieValue && ! inCustomizer ) {
		overlay.parentNode.removeChild( overlay );
	}

	document.body.appendChild( widget );
	overlay.querySelector( 'form' ).addEventListener( 'submit', accept );

	if ( overlay.classList.contains( 'hide-on-scroll' ) ) {
		initialScrollPosition = getScrollTop();
		scrollFunction = function () {
			if ( Math.abs( getScrollTop() - initialScrollPosition ) > 50 ) {
				accept();
			}
		};
		window.addEventListener( 'scroll', scrollFunction );
	} else if ( overlay.classList.contains( 'hide-on-time' ) ) {
		setTimeout( accept, overlay.getAttribute( 'data-hide-timeout' ) * 1000 );
	}

	var accepted = false;
	function accept( event ) {
		if ( accepted ) {
			return;
		}
		accepted = true;

		if ( event && event.preventDefault ) {
			event.preventDefault();
		}

		if ( overlay.classList.contains( 'hide-on-scroll' ) ) {
			window.removeEventListener( 'scroll', scrollFunction );
		}

		var expireTime = new Date();
		expireTime.setTime(
			expireTime.getTime() + overlay.getAttribute( 'data-consent-expiration' ) * 24 * 60 * 60 * 1000
		);

		document.cookie =
			'eucookielaw=' + expireTime.getTime() + ';path=/;expires=' + expireTime.toGMTString();
		if (
			overlay.classList.contains( 'ads-active' ) &&
			overlay.classList.contains( 'hide-on-button' )
		) {
			document.cookie =
				'personalized-ads-consent=' +
				expireTime.getTime() +
				';path=/;expires=' +
				expireTime.toGMTString();
		}

		overlay.classList.add( 'hide' );
		setTimeout( function () {
			overlay.parentNode.removeChild( overlay );
			var widgetSection = document.querySelector( '.widget.widget_eu_cookie_law_widget' );
			widgetSection.parentNode.removeChild( widgetSection );
		}, 400 );
	}
} )();
