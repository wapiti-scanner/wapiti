/* globals infiniteScroll, _wpmejsSettings, ga, _gaq, WPCOM_sharing_counts, MediaElementPlayer */
( function () {
	// Open closure.
	// Local vars.
	var Scroller, ajaxurl, stats, type, text, totop, loading_text;

	// IE requires special handling
	var isIE = -1 != navigator.userAgent.search( 'MSIE' );
	if ( isIE ) {
		var IEVersion = navigator.userAgent.match( /MSIE\s?(\d+)\.?\d*;/ );
		IEVersion = parseInt( IEVersion[ 1 ] );
	}

	// HTTP ajaxurl when site is HTTPS causes Access-Control-Allow-Origin failure in Desktop and iOS Safari
	if ( 'https:' == document.location.protocol ) {
		infiniteScroll.settings.ajaxurl = infiniteScroll.settings.ajaxurl.replace(
			'http://',
			'https://'
		);
	}

	/**
	 * Loads new posts when users scroll near the bottom of the page.
	 */
	Scroller = function ( settings ) {
		var self = this;

		// Initialize our variables
		this.id = settings.id;
		this.body = document.body;
		this.window = window;
		this.element = document.getElementById( settings.id );
		this.wrapperClass = settings.wrapper_class;
		this.ready = true;
		this.disabled = false;
		this.page = 1;
		this.offset = settings.offset;
		this.currentday = settings.currentday;
		this.order = settings.order;
		this.throttle = false;
		this.click_handle = settings.click_handle;
		this.google_analytics = settings.google_analytics;
		this.history = settings.history;
		this.origURL = window.location.href;

		// Handle element
		this.handle = document.createElement( 'div' );
		this.handle.setAttribute( 'id', 'infinite-handle' );
		this.handle.innerHTML = '<span><button>' + text.replace( '\\', '' ) + '</button></span>';

		// Footer settings
		this.footer = {
			el: document.getElementById( 'infinite-footer' ),
			wrap: settings.footer,
		};

		// Bind methods used as callbacks
		this.checkViewportOnLoadBound = self.checkViewportOnLoad.bind( this );

		// Core's native MediaElement.js implementation needs special handling
		this.wpMediaelement = null;

		// We have two type of infinite scroll
		// cases 'scroll' and 'click'

		if ( type == 'scroll' ) {
			// Bind refresh to the scroll event
			// Throttle to check for such case every 300ms

			// On event the case becomes a fact
			this.window.addEventListener( 'scroll', function () {
				self.throttle = true;
			} );

			// Go back top method
			self.gotop();

			setInterval( function () {
				if ( self.throttle ) {
					// Once the case is the case, the action occurs and the fact is no more
					self.throttle = false;
					// Reveal or hide footer
					self.thefooter();
					// Fire the refresh
					self.refresh();
					self.determineURL(); // determine the url
				}
			}, 250 );

			// Ensure that enough posts are loaded to fill the initial viewport, to compensate for short posts and large displays.
			self.ensureFilledViewport();
			this.body.addEventListener( 'is.post-load', self.checkViewportOnLoadBound );
		} else if ( type == 'click' ) {
			if ( this.click_handle ) {
				this.element.appendChild( this.handle );
			}

			this.handle.addEventListener( 'click', function () {
				// Handle the handle
				if ( self.click_handle ) {
					self.handle.parentNode.removeChild( self.handle );
				}

				// Fire the refresh
				self.refresh();
			} );
		}

		// Initialize any Core audio or video players loaded via IS
		this.body.addEventListener( 'is.post-load', self.initializeMejs );
	};

	/**
	 * Normalize the access to the document scrollTop value.
	 */
	Scroller.prototype.getScrollTop = function () {
		return window.pageYOffset || document.documentElement.scrollTop || document.body.scrollTop || 0;
	};

	/**
	 * Polyfill jQuery.extend.
	 */
	Scroller.prototype.extend = function ( out ) {
		out = out || {};

		for ( var i = 1; i < arguments.length; i++ ) {
			if ( ! arguments[ i ] ) {
				continue;
			}

			for ( var key in arguments[ i ] ) {
				if ( arguments[ i ].hasOwnProperty( key ) ) {
					out[ key ] = arguments[ i ][ key ];
				}
			}
		}
		return out;
	};

	/**
	 * Check whether we should fetch any additional posts.
	 */
	Scroller.prototype.check = function () {
		var wrapperMeasurements = this.measure( this.element, [ this.wrapperClass ] );

		// Fetch more posts when we're less than 2 screens away from the bottom.
		return wrapperMeasurements.bottom < 2 * this.window.innerHeight;
	};

	/**
	 * Renders the results from a successful response.
	 */
	Scroller.prototype.render = function ( response ) {
		var childrenToAppend = Array.prototype.slice.call( response.fragment.childNodes );
		this.body.classList.add( 'infinity-success' );

		// Render the retrieved nodes.
		while ( childrenToAppend.length > 0 ) {
			var currentNode = childrenToAppend.shift();
			this.element.appendChild( currentNode );
		}

		this.trigger( this.body, 'is.post-load', {
			jqueryEventName: 'post-load',
			data: response,
		} );

		this.ready = true;
	};

	/**
	 * Returns the object used to query for new posts.
	 */
	Scroller.prototype.query = function () {
		return {
			page: this.page + this.offset, // Load the next page.
			currentday: this.currentday,
			order: this.order,
			scripts: window.infiniteScroll.settings.scripts,
			styles: window.infiniteScroll.settings.styles,
			query_args: window.infiniteScroll.settings.query_args,
			query_before: window.infiniteScroll.settings.query_before,
			last_post_date: window.infiniteScroll.settings.last_post_date,
		};
	};

	Scroller.prototype.animate = function ( cb, duration ) {
		var start = performance.now();

		requestAnimationFrame( function animate( time ) {
			var timeFraction = Math.min( 1, ( time - start ) / duration );
			cb( timeFraction );

			if ( timeFraction < 1 ) {
				requestAnimationFrame( animate );
			}
		} );
	};

	/**
	 * Scroll back to top.
	 */
	Scroller.prototype.gotop = function () {
		var blog = document.getElementById( 'infinity-blog-title' );
		var self = this;

		if ( ! blog ) {
			return;
		}

		blog.setAttribute( 'title', totop );
		blog.addEventListener( 'click', function ( e ) {
			var sourceScroll = self.window.pageYOffset;
			e.preventDefault();

			self.animate( function ( progress ) {
				var currentScroll = sourceScroll - sourceScroll * progress;
				document.documentElement.scrollTop = document.body.scrollTop = currentScroll;
			}, 200 );
		} );
	};

	/**
	 * The infinite footer.
	 */
	Scroller.prototype.thefooter = function () {
		var self = this,
			pageWrapper,
			footerContainer,
			width,
			sourceBottom,
			targetBottom,
			footerEnabled = this.footer && this.footer.el;

		if ( ! footerEnabled ) {
			return;
		}

		// Check if we have an id for the page wrapper
		if ( 'string' === typeof this.footer.wrap ) {
			try {
				pageWrapper = document.getElementById( this.footer.wrap );
				width = pageWrapper.getBoundingClientRect();
				width = width.width;
			} catch ( err ) {
				width = 0;
			}

			// Make the footer match the width of the page
			if ( width > 479 ) {
				footerContainer = this.footer.el.querySelector( '.container' );
				if ( footerContainer ) {
					footerContainer.style.width = width + 'px';
				}
			}
		}

		// Reveal footer
		sourceBottom = parseInt( self.footer.el.style.bottom || -50, 10 );
		targetBottom = this.window.pageYOffset >= 350 ? 0 : -50;

		if ( sourceBottom !== targetBottom ) {
			self.animate( function ( progress ) {
				var currentBottom = sourceBottom + ( targetBottom - sourceBottom ) * progress;
				self.footer.el.style.bottom = currentBottom + 'px';

				if ( 1 === progress ) {
					sourceBottom = targetBottom;
				}
			}, 200 );
		}
	};

	/**
	 * Recursively convert a JS object into URL encoded data.
	 */
	Scroller.prototype.urlEncodeJSON = function ( obj, prefix ) {
		var params = [],
			encodedKey,
			newPrefix;

		for ( var key in obj ) {
			encodedKey = encodeURIComponent( key );
			newPrefix = prefix ? prefix + '[' + encodedKey + ']' : encodedKey;

			if ( 'object' === typeof obj[ key ] ) {
				if ( ! Array.isArray( obj[ key ] ) || obj[ key ].length > 0 ) {
					params.push( this.urlEncodeJSON( obj[ key ], newPrefix ) );
				} else {
					// Explicitly expose empty arrays with no values
					params.push( newPrefix + '[]=' );
				}
			} else {
				params.push( newPrefix + '=' + encodeURIComponent( obj[ key ] ) );
			}
		}
		return params.join( '&' );
	};

	/**
	 * Controls the flow of the refresh. Don't mess.
	 */
	Scroller.prototype.refresh = function () {
		var self = this,
			query,
			xhr,
			loader,
			customized;

		// If we're disabled, ready, or don't pass the check, bail.
		if ( this.disabled || ! this.ready || ! this.check() ) {
			return;
		}

		// Let's get going -- set ready to false to prevent
		// multiple refreshes from occurring at once.
		this.ready = false;

		// Create a loader element to show it's working.
		if ( this.click_handle ) {
			if ( ! loader ) {
				document.getElementById( 'infinite-aria' ).textContent = loading_text;
				loader = document.createElement( 'div' );
				loader.classList.add( 'infinite-loader' );
				loader.setAttribute( 'role', 'progress' );
				loader.innerHTML =
					'<div class="spinner"><div class="spinner-inner"><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div></div></div>';
			}
			this.element.appendChild( loader );
		}

		// Generate our query vars.
		query = self.extend(
			{
				action: 'infinite_scroll',
			},
			this.query()
		);

		// Inject Customizer state.
		if ( 'undefined' !== typeof wp && wp.customize && wp.customize.settings.theme ) {
			customized = {};
			query.wp_customize = 'on';
			query.theme = wp.customize.settings.theme.stylesheet;
			wp.customize.each( function ( setting ) {
				if ( setting._dirty ) {
					customized[ setting.id ] = setting();
				}
			} );
			query.customized = JSON.stringify( customized );
			query.nonce = wp.customize.settings.nonce.preview;
		}

		// Fire the ajax request.
		xhr = new XMLHttpRequest();
		xhr.open( 'POST', infiniteScroll.settings.ajaxurl, true );
		xhr.setRequestHeader( 'X-Requested-With', 'XMLHttpRequest' );
		xhr.setRequestHeader( 'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8' );
		xhr.send( self.urlEncodeJSON( query ) );

		// Allow refreshes to occur again if an error is triggered.
		xhr.onerror = function () {
			if ( self.click_handle && loader.parentNode ) {
				loader.parentNode.removeChild( loader );
			}

			self.ready = true;
		};

		// Success handler
		xhr.onload = function () {
			var response = JSON.parse( xhr.responseText ),
				httpCheck = xhr.status >= 200 && xhr.status < 300,
				responseCheck = 'undefined' !== typeof response.html;

			if ( ! response || ! httpCheck || ! responseCheck ) {
				if ( self.click_handle && loader.parentNode ) {
					loader.parentNode.removeChild( loader );
				}
				return;
			}

			// On success, let's hide the loader circle.
			if ( self.click_handle && loader.parentNode ) {
				loader.parentNode.removeChild( loader );
			}

			// If additional scripts are required by the incoming set of posts, parse them
			if ( response.scripts && Array.isArray( response.scripts ) ) {
				response.scripts.forEach( function ( item ) {
					var elementToAppendTo = item.footer ? 'body' : 'head';

					// Add script handle to list of those already parsed
					window.infiniteScroll.settings.scripts.push( item.handle );

					// Output extra data, if present
					if ( item.extra_data ) {
						self.appendInlineScript( item.extra_data, elementToAppendTo );
					}

					if ( item.before_handle ) {
						self.appendInlineScript( item.before_handle, elementToAppendTo );
					}

					// Build script tag and append to DOM in requested location
					var script = document.createElement( 'script' );
					script.type = 'text/javascript';
					script.src = item.src;
					script.id = item.handle;

					// Dynamically loaded scripts are async by default.
					// We don't want that, it breaks stuff, e.g. wp-mediaelement init.
					script.async = false;

					if ( item.after_handle ) {
						script.onload = function () {
							self.appendInlineScript( item.after_handle, elementToAppendTo );
						};
					}

					// If MediaElement.js is loaded in by item set of posts, don't initialize the players a second time as it breaks them all
					if ( 'wp-mediaelement' === item.handle ) {
						self.body.removeEventListener( 'is.post-load', self.initializeMejs );
					}

					if ( 'wp-mediaelement' === item.handle && 'undefined' === typeof mejs ) {
						self.wpMediaelement = {};
						self.wpMediaelement.tag = script;
						self.wpMediaelement.element = elementToAppendTo;
						setTimeout( self.maybeLoadMejs.bind( self ), 250 );
					} else {
						document.getElementsByTagName( elementToAppendTo )[ 0 ].appendChild( script );
					}
				} );
			}

			// If additional stylesheets are required by the incoming set of posts, parse them
			if ( response.styles && Array.isArray( response.styles ) ) {
				response.styles.forEach( function ( item ) {
					// Add stylesheet handle to list of those already parsed
					window.infiniteScroll.settings.styles.push( item.handle );

					// Build link tag
					var style = document.createElement( 'link' );
					style.rel = 'stylesheet';
					style.href = item.src;
					style.id = item.handle + '-css';

					// Destroy link tag if a conditional statement is present and either the browser isn't IE, or the conditional doesn't evaluate true
					if (
						item.conditional &&
						( ! isIE || ! eval( item.conditional.replace( /%ver/g, IEVersion ) ) )
					) {
						style = false;
					}

					// Append link tag if necessary
					if ( style ) {
						document.getElementsByTagName( 'head' )[ 0 ].appendChild( style );
					}
				} );
			}

			// Convert the response.html to a fragment element.
			// Using a div instead of DocumentFragment, because the latter doesn't support innerHTML.
			response.fragment = document.createElement( 'div' );
			response.fragment.innerHTML = response.html;

			// Increment the page number
			self.page++;

			// Record pageview in WP Stats, if available.
			if ( stats ) {
				new Image().src =
					document.location.protocol +
					'//pixel.wp.com/g.gif?' +
					stats +
					'&post=0&baba=' +
					Math.random();
			}

			// Add new posts to the postflair object
			if ( 'object' === typeof response.postflair && 'object' === typeof WPCOM_sharing_counts ) {
				WPCOM_sharing_counts = self.extend( WPCOM_sharing_counts, response.postflair ); // eslint-disable-line no-global-assign
			}

			// Render the results
			self.render.call( self, response );

			// If 'click' type and there are still posts to fetch, add back the handle
			if ( type == 'click' ) {
				// add focus to new posts, only in button mode as we know where page focus currently is and only if we have a wrapper
				if ( infiniteScroll.settings.wrapper ) {
					document
						.querySelector(
							'#infinite-view-' + ( self.page + self.offset - 1 ) + ' a:first-of-type'
						)
						.focus( {
							preventScroll: true,
						} );
				}

				if ( response.lastbatch ) {
					if ( self.click_handle ) {
						// Update body classes
						self.body.classList.add( 'infinity-end' );
						self.body.classList.remove( 'infinity-success' );
					} else {
						self.trigger( this.body, 'infinite-scroll-posts-end' );
					}
				} else {
					if ( self.click_handle ) {
						self.element.appendChild( self.handle );
					} else {
						self.trigger( this.body, 'infinite-scroll-posts-more' );
					}
				}
			} else if ( response.lastbatch ) {
				self.disabled = true;

				self.body.classList.add( 'infinity-end' );
				self.body.classList.remove( 'infinity-success' );
			}

			// Update currentday to the latest value returned from the server
			if ( response.currentday ) {
				self.currentday = response.currentday;
			}

			// Fire Google Analytics pageview
			if ( self.google_analytics ) {
				var ga_url = self.history.path.replace( /%d/, self.page );
				if ( 'object' === typeof _gaq ) {
					_gaq.push( [ '_trackPageview', ga_url ] );
				}
				if ( 'function' === typeof ga ) {
					ga( 'send', 'pageview', ga_url );
				}
			}
		};

		return xhr;
	};

	/**
	 * Given JavaScript blob and the name of a parent tag, this helper function will
	 * generate a script tag, insert the JavaScript blob, and append it to the parent.
	 *
	 * It's important to note that the JavaScript blob will be evaluated immediately. If
	 * you need a parent script to load first, use that script element's onload handler.
	 *
	 * @param {string} script    The blob of JavaScript to run.
	 * @param {string} parentTag The tag name of the parent element.
	 */
	Scroller.prototype.appendInlineScript = function ( script, parentTag ) {
		var element = document.createElement( 'script' ),
			scriptContent = document.createTextNode( '//<![CDATA[ \n' + script + '\n//]]>' );

		element.type = 'text/javascript';
		element.appendChild( scriptContent );

		document.getElementsByTagName( parentTag )[ 0 ].appendChild( element );
	};

	/**
	 * Core's native media player uses MediaElement.js
	 * The library's size is sufficient that it may not be loaded in time for Core's helper to invoke it, so we need to delay until `mejs` exists.
	 */
	Scroller.prototype.maybeLoadMejs = function () {
		if ( null === this.wpMediaelement ) {
			return;
		}

		if ( 'undefined' === typeof mejs ) {
			setTimeout( this.maybeLoadMejs.bind( this ), 250 );
		} else {
			document
				.getElementsByTagName( this.wpMediaelement.element )[ 0 ]
				.appendChild( this.wpMediaelement.tag );
			this.wpMediaelement = null;

			// Ensure any subsequent IS loads initialize the players
			this.body.addEventListener( 'is.post-load', this.initializeMejs );
		}
	};

	/**
	 * Initialize the MediaElement.js player for any posts not previously initialized
	 */
	Scroller.prototype.initializeMejs = function ( e ) {
		// Are there media players in the incoming set of posts?
		if (
			! e.detail ||
			! e.detail.html ||
			( -1 === e.detail.html.indexOf( 'wp-audio-shortcode' ) &&
				-1 === e.detail.html.indexOf( 'wp-video-shortcode' ) )
		) {
			return;
		}

		// Don't bother if mejs isn't loaded for some reason
		if ( 'undefined' === typeof mejs ) {
			return;
		}

		// Adapted from wp-includes/js/mediaelement/wp-mediaelement.js
		// Modified to not initialize already-initialized players, as Mejs doesn't handle that well
		var settings = {};
		var audioVideoElements;

		if ( typeof _wpmejsSettings !== 'undefined' ) {
			settings.pluginPath = _wpmejsSettings.pluginPath;
		}

		settings.success = function ( mejs ) {
			var autoplay = mejs.attributes.autoplay && 'false' !== mejs.attributes.autoplay;
			if ( 'flash' === mejs.pluginType && autoplay ) {
				mejs.addEventListener(
					'canplay',
					function () {
						mejs.play();
					},
					false
				);
			}
		};

		audioVideoElements = document.querySelectorAll( '.wp-audio-shortcode, .wp-video-shortcode' );
		audioVideoElements = Array.prototype.slice.call( audioVideoElements );

		// Only process already unprocessed shortcodes.
		audioVideoElements = audioVideoElements.filter( function ( el ) {
			while ( el.parentNode ) {
				if ( el.classList.contains( 'mejs-container' ) ) {
					return false;
				}
				el = el.parentNode;
			}
			return true;
		} );

		for ( var i = 0; i < audioVideoElements.length; i++ ) {
			new MediaElementPlayer( audioVideoElements[ i ], settings );
		}
	};

	/**
	 * Get element measurements relative to the viewport.
	 *
	 * @returns {object}
	 */
	Scroller.prototype.measure = function ( element, expandClasses ) {
		expandClasses = expandClasses || [];

		var childrenToTest = Array.prototype.slice.call( element.children );
		var currentChild,
			minTop = Number.MAX_VALUE,
			maxBottom = 0,
			currentChildRect,
			i;

		while ( childrenToTest.length > 0 ) {
			currentChild = childrenToTest.shift();

			for ( i = 0; i < expandClasses.length; i++ ) {
				// Expand (= measure) child elements of nodes with class names from expandClasses.
				if ( currentChild.classList.contains( expandClasses[ i ] ) ) {
					childrenToTest = childrenToTest.concat(
						Array.prototype.slice.call( currentChild.children )
					);
					break;
				}
			}
			currentChildRect = currentChild.getBoundingClientRect();

			minTop = Math.min( minTop, currentChildRect.top );
			maxBottom = Math.max( maxBottom, currentChildRect.bottom );
		}

		var viewportMiddle = Math.round( window.innerHeight / 2 );

		// isActive = does the middle of the viewport cross the element?
		var isActive = minTop <= viewportMiddle && maxBottom >= viewportMiddle;

		/**
		 * Factor = percentage of viewport above the middle line occupied by the element.
		 *
		 * Negative factors are assigned for elements below the middle line. That's on purpose
		 * to only allow "page 2" to change the URL once it's in the middle of the viewport.
		 */
		var factor = ( Math.min( maxBottom, viewportMiddle ) - Math.max( minTop, 0 ) ) / viewportMiddle;

		return {
			top: minTop,
			bottom: maxBottom,
			height: maxBottom - minTop,
			factor: factor,
			isActive: isActive,
		};
	};

	/**
	 * Trigger IS to load additional posts if the initial posts don't fill the window.
	 *
	 * On large displays, or when posts are very short, the viewport may not be filled with posts,
	 * so we overcome this by loading additional posts when IS initializes.
	 */
	Scroller.prototype.ensureFilledViewport = function () {
		var self = this,
			windowHeight = self.window.innerHeight,
			wrapperMeasurements = self.measure( self.element, [ self.wrapperClass ] );

		// Only load more posts once. This prevents infinite loops when there are no more posts.
		self.body.removeEventListener( 'is.post-load', self.checkViewportOnLoadBound );

		// Load more posts if space permits, otherwise stop checking for a full viewport.
		if ( wrapperMeasurements.bottom !== 0 && wrapperMeasurements.bottom < windowHeight ) {
			self.ready = true;
			self.refresh();
		}
	};

	/**
	 * Event handler for ensureFilledViewport(), tied to the post-load trigger.
	 * Necessary to ensure that the variable `this` contains the scroller when used in ensureFilledViewport(). Since this function is tied to an event, `this` becomes the DOM element the event is tied to.
	 */
	Scroller.prototype.checkViewportOnLoad = function () {
		this.ensureFilledViewport();
	};

	function fullscreenState() {
		return document.fullscreenElement ||
			document.mozFullScreenElement ||
			document.webkitFullscreenElement ||
			document.msFullscreenElement
			? 1
			: 0;
	}

	var previousFullScrenState = fullscreenState();

	/**
	 * Identify archive page that corresponds to majority of posts shown in the current browser window.
	 */
	Scroller.prototype.determineURL = function () {
		var self = this,
			pageNum = -1,
			currentFullScreenState = fullscreenState(),
			wrapperEls,
			maxFactor = 0;

		// xor - check if the state has changed
		if ( previousFullScrenState ^ currentFullScreenState ) {
			// If we just switched to/from fullscreen,
			// don't do the div clearing/caching or the
			// URL setting. Doing so can break video playback
			// if the video goes to fullscreen.

			previousFullScrenState = currentFullScreenState;
			return;
		}
		previousFullScrenState = currentFullScreenState;
		wrapperEls = document.querySelectorAll( '.' + self.wrapperClass );

		for ( var i = 0; i < wrapperEls.length; i++ ) {
			var setMeasurements = self.measure( wrapperEls[ i ] );

			// If it exists, pick a set that is crossed by the middle of the viewport.
			if ( setMeasurements.isActive ) {
				pageNum = parseInt( wrapperEls[ i ].dataset.pageNum, 10 );
				break;
			}

			// If there is such a set, pick the one that occupies the most space
			// above the middle of the viewport.
			if ( setMeasurements.factor > maxFactor ) {
				pageNum = parseInt( wrapperEls[ i ].dataset.pageNum, 10 );
				maxFactor = setMeasurements.factor;
			}

			// Otherwise default to -1
		}

		self.updateURL( pageNum );
	};

	/**
	 * Update address bar to reflect archive page URL for a given page number.
	 * Checks if URL is different to prevent pollution of browser history.
	 */
	Scroller.prototype.updateURL = function ( page ) {
		// IE only supports pushState() in v10 and above, so don't bother if those conditions aren't met.
		if ( ! window.history.pushState ) {
			return;
		}
		var self = this,
			pageSlug = self.origURL;

		if ( -1 !== page ) {
			pageSlug =
				window.location.protocol +
				'//' +
				self.history.host +
				self.history.path.replace( /%d/, page ) +
				self.history.parameters;
		}

		if ( window.location.href != pageSlug ) {
			history.pushState( null, null, pageSlug );
		}
	};

	/**
	 * Pause scrolling.
	 */
	Scroller.prototype.pause = function () {
		this.disabled = true;
	};

	/**
	 * Resume scrolling.
	 */
	Scroller.prototype.resume = function () {
		this.disabled = false;
	};

	/**
	 * Emits custom JS events.
	 *
	 * @param {Node}   el
	 * @param {string} eventName
	 * @param {*}      data
	 */
	Scroller.prototype.trigger = function ( el, eventName, opts ) {
		opts = opts || {};

		/**
		 * Emit the event in a jQuery way for backwards compatibility where necessary.
		 */
		if ( opts.jqueryEventName && 'undefined' !== typeof jQuery ) {
			jQuery( el ).trigger( opts.jqueryEventName, opts.data || null );
		}

		/**
		 * Emit the event in a standard way.
		 */
		var e;
		try {
			e = new CustomEvent( eventName, {
				bubbles: true,
				cancelable: true,
				detail: opts.data || null,
			} );
		} catch ( err ) {
			e = document.createEvent( 'CustomEvent' );
			e.initCustomEvent( eventName, true, true, opts.data || null );
		}
		el.dispatchEvent( e );
	};

	/**
	 * Ready, set, go!
	 */
	var jetpackInfinityModule = function () {
		var bodyClasses = infiniteScroll.settings.body_class.split( ' ' );

		// Check for our variables
		if ( 'object' !== typeof infiniteScroll ) {
			return;
		}

		bodyClasses.forEach( function ( className ) {
			if ( className ) {
				document.body.classList.add( className );
			}
		} );

		// Set ajaxurl (for brevity)
		ajaxurl = infiniteScroll.settings.ajaxurl;

		// Set stats, used for tracking stats
		stats = infiniteScroll.settings.stats;

		// Define what type of infinity we have, grab text for click-handle
		type = infiniteScroll.settings.type;
		text = infiniteScroll.settings.text;
		totop = infiniteScroll.settings.totop;

		// aria text
		loading_text = infiniteScroll.settings.loading_text;

		// Initialize the scroller (with the ID of the element from the theme)
		infiniteScroll.scroller = new Scroller( infiniteScroll.settings );

		/**
		 * Monitor user scroll activity to update URL to correspond to archive page for current set of IS posts
		 */
		if ( type == 'click' ) {
			var timer = null;
			window.addEventListener( 'scroll', function () {
				// run the real scroll handler once every 250 ms.
				if ( timer ) {
					return;
				}
				timer = setTimeout( function () {
					infiniteScroll.scroller.determineURL();
					timer = null;
				}, 250 );
			} );
		}
	};

	/**
	 * Ready, set, go!
	 */
	if ( document.readyState === 'interactive' || document.readyState === 'complete' ) {
		jetpackInfinityModule();
	} else {
		document.addEventListener( 'DOMContentLoaded', jetpackInfinityModule );
	}
} )(); // Close closure
