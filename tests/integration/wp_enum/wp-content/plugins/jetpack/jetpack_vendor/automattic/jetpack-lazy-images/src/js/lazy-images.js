/* global jetpackLazyImagesL10n */

const jetpackLazyImagesModule = function () {
	const config = {
		// If the image gets within 200px in the Y axis, start the download.
		rootMargin: '200px 0px',
		threshold: 0.01,
	};
	const loadingImages = [];
	let lazyImages, loadingWarning, observer;

	lazy_load_init();

	const bodyEl = document.querySelector( 'body' );
	if ( bodyEl ) {
		// Lazy load images that are brought in from Infinite Scroll
		bodyEl.addEventListener( 'is.post-load', lazy_load_init );

		// Add event to provide optional compatibility for other code.
		bodyEl.addEventListener( 'jetpack-lazy-images-load', lazy_load_init );
	}

	/**
	 * Initialize the module.
	 */
	function lazy_load_init() {
		lazyImages = Array.from(
			document.querySelectorAll( 'img.jetpack-lazy-image:not(.jetpack-lazy-image--handled)' )
		);

		// If initialized, then disconnect the observer
		if ( observer ) {
			observer.disconnect();
		}

		// If we don't have support for intersection observer, loads the images immediately
		if ( ! ( 'IntersectionObserver' in window ) ) {
			loadAllImages();
		} else {
			// It is supported, load the images
			observer = new IntersectionObserver( onIntersection, config );

			lazyImages.forEach( function ( image ) {
				if ( ! image.getAttribute( 'data-lazy-loaded' ) ) {
					observer.observe( image );
				}
			} );

			// Watch for attempts to print, and load all images. Most browsers
			// support beforeprint, Safari needs a media listener. Doesn't hurt
			// to double-fire if a browser supports both.
			window.addEventListener( 'beforeprint', onPrint );
			if ( window.matchMedia ) {
				window.matchMedia( 'print' ).addListener( function ( mql ) {
					if ( mql.matches ) {
						onPrint();
					}
				} );
			}
		}
	}

	/**
	 * Load all of the images immediately
	 */
	function loadAllImages() {
		if ( observer ) {
			observer.disconnect();
		}

		while ( lazyImages.length > 0 ) {
			applyImage( lazyImages[ 0 ] );
		}
	}

	/**
	 * On intersection
	 *
	 * @param {Array} entries - List of elements being observed.
	 */
	function onIntersection( entries ) {
		// Loop through the entries
		for ( let i = 0; i < entries.length; i++ ) {
			const entry = entries[ i ];

			// Are we in viewport?
			if ( entry.intersectionRatio > 0 ) {
				// Stop watching and load the image
				observer.unobserve( entry.target );
				applyImage( entry.target );
			}
		}

		// Disconnect if we've already loaded all of the images
		if ( lazyImages.length === 0 ) {
			observer.disconnect();
		}
	}

	/**
	 * On print
	 */
	function onPrint() {
		if ( ! loadingWarning && ( lazyImages.length > 0 || loadingImages.length > 0 ) ) {
			// Replace the printed page with a notice that images are still loading.
			// Hopefully the user won't actually print this, but if they do at least it'll not
			// waste too much ink.
			loadingWarning = document.createElement( 'div' );
			loadingWarning.id = 'loadingWarning';
			loadingWarning.style.fontWeight = 'bold';
			loadingWarning.innerText = jetpackLazyImagesL10n.loading_warning;

			const s = document.createElement( 'style' );
			s.innerHTML =
				'#loadingWarning { display: none; }\n@media print {\n#loadingWarning { display: block; }\nbody > #loadingWarning ~ * { display: none !important; }\n}';
			loadingWarning.appendChild( s );

			bodyEl.insertBefore( loadingWarning, bodyEl.firstChild );
		}

		if ( lazyImages.length > 0 ) {
			loadAllImages();
		}

		// May as well try an alert() too. The browser may block it, but if not
		// it could save them some trouble.
		if ( loadingWarning ) {
			alert( jetpackLazyImagesL10n.loading_warning );
		}
	}

	/**
	 * Apply the image
	 *
	 * @param {Element} image - The image object.
	 */
	function applyImage( image ) {
		let lazyLoadedImageEvent;

		if ( ! ( image instanceof HTMLImageElement ) ) {
			return;
		}

		const srcset = image.getAttribute( 'data-lazy-srcset' );
		const sizes = image.getAttribute( 'data-lazy-sizes' );

		// Remove lazy attributes.
		image.removeAttribute( 'data-lazy-srcset' );
		image.removeAttribute( 'data-lazy-sizes' );
		image.removeAttribute( 'data-lazy-src' );

		// Add the attributes we want.
		image.classList.add( 'jetpack-lazy-image--handled' );
		image.setAttribute( 'data-lazy-loaded', 1 );

		if ( sizes ) {
			image.setAttribute( 'sizes', sizes );
		}

		if ( ! srcset ) {
			image.removeAttribute( 'srcset' );
		} else {
			image.setAttribute( 'srcset', srcset );
		}

		// Force eager loading, otherwise the browser-native loading=lazy support will still
		// prevent the loading.
		image.setAttribute( 'loading', 'eager' );

		loadingImages.push( image );
		const idx = lazyImages.indexOf( image );
		if ( idx >= 0 ) {
			lazyImages.splice( idx, 1 );
		}

		if ( image.complete ) {
			loadedImage.call( image, null );
		} else {
			image.addEventListener( 'load', loadedImage, { once: true } );
			image.addEventListener( 'error', loadedImage, { once: true } );
		}

		// Hack for Safari: it does not respect srcset changes for img tags outside
		// of <figure> tags. So, we need to force Safari to re-parse that bit of HTML.
		if ( 'undefined' !== typeof safari ) {
			// eslint-disable-next-line no-self-assign
			image.outerHTML = image.outerHTML;
		}

		// Fire an event so that third-party code can perform actions after an image is loaded.
		try {
			lazyLoadedImageEvent = new Event( 'jetpack-lazy-loaded-image', {
				bubbles: true,
				cancelable: true,
			} );
		} catch ( e ) {
			lazyLoadedImageEvent = document.createEvent( 'Event' );
			lazyLoadedImageEvent.initEvent( 'jetpack-lazy-loaded-image', true, true );
		}

		image.dispatchEvent( lazyLoadedImageEvent );
	}

	/**
	 * An image from applyImage() finished loading.
	 */
	function loadedImage() {
		const idx = loadingImages.indexOf( this );
		if ( idx >= 0 ) {
			loadingImages.splice( idx, 1 );
		}

		if ( loadingWarning && lazyImages.length === 0 && loadingImages.length === 0 ) {
			loadingWarning.parentNode.removeChild( loadingWarning );
			loadingWarning = null;
		}
	}
};

// Let's kick things off now
if ( document.readyState === 'interactive' || document.readyState === 'complete' ) {
	jetpackLazyImagesModule();
} else {
	document.addEventListener( 'DOMContentLoaded', jetpackLazyImagesModule );
}
