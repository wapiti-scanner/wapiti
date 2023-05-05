( function () {
	function TiledGalleryCollection() {
		this.galleries = [];
		this.findAndSetupNewGalleries();
	}

	TiledGalleryCollection.prototype.findAndSetupNewGalleries = function () {
		var self = this;
		var unresizedGalleries = document.querySelectorAll( '.tiled-gallery.tiled-gallery-unresized' );

		Array.prototype.forEach.call( unresizedGalleries, function ( el ) {
			self.galleries.push( new TiledGallery( el ) );
		} );
	};

	TiledGalleryCollection.prototype.resizeAll = function () {
		Array.prototype.forEach.call( this.galleries, function ( gallery ) {
			gallery.resize();
		} );
	};

	function TiledGallery( galleryElem ) {
		this.gallery = galleryElem;

		this.addCaptionEvents();

		// Resize when initialized to fit the gallery to window dimensions
		this.resize();

		// Displays the gallery and prevents it from being initialized again
		this.gallery.classList.remove( 'tiled-gallery-unresized' );
	}

	/**
	 * Selector for all resizeable elements inside a Tiled Gallery
	 */

	TiledGallery.prototype.resizeableElementsSelector =
		'.gallery-row, .gallery-group, .tiled-gallery-item img';

	/**
	 * Story
	 */

	TiledGallery.prototype.addCaptionEvents = function () {
		// Hide captions
		var galleryCaptions = this.gallery.querySelectorAll( '.tiled-gallery-caption' );
		Array.prototype.forEach.call( galleryCaptions, function ( el ) {
			el.style.display = 'none';
		} );

		var mouseHoverHandler = function ( e ) {
			var itemEl = e.target.closest( '.tiled-gallery-item' );
			var displayValue = 'mouseover' === e.type ? 'block' : 'none';

			if ( itemEl ) {
				var itemCaption = itemEl.querySelector( '.tiled-gallery-caption' );
				if ( itemCaption ) {
					itemCaption.style.display = displayValue;
				}
			}
		};

		// Add hover effects to bring the caption up and down for each item
		this.gallery.addEventListener( 'mouseover', mouseHoverHandler );
		this.gallery.addEventListener( 'mouseout', mouseHoverHandler );
	};

	TiledGallery.prototype.getExtraDimension = function ( el, attribute, mode ) {
		if ( mode === 'horizontal' ) {
			var left = attribute === 'border' ? 'borderLeftWidth' : attribute + 'Left';
			var right = attribute === 'border' ? 'borderRightWidth' : attribute + 'Right';
			return ( parseInt( el.style[ left ], 10 ) || 0 ) + ( parseInt( el.style[ right ], 10 ) || 0 );
		} else if ( mode === 'vertical' ) {
			var top = attribute === 'border' ? 'borderTopWidth' : attribute + 'Top';
			var bottom = attribute === 'border' ? 'borderBottomWidth' : attribute + 'Bottom';
			return ( parseInt( el.style[ top ], 10 ) || 0 ) + ( parseInt( el.style[ bottom ], 10 ) || 0 );
		} else {
			return 0;
		}
	};

	TiledGallery.prototype.resize = function () {
		// Resize everything in the gallery based on the ratio of the current content width
		// to the original content width;
		var originalWidth = parseInt( this.gallery.dataset.originalWidth, 10 );
		var currentWidth = parseFloat(
			getComputedStyle( this.gallery.parentNode, null ).width.replace( 'px', '' )
		);
		var resizeRatio = Math.min( 1, currentWidth / originalWidth );

		var self = this;
		var resizableElements = this.gallery.querySelectorAll( this.resizeableElementsSelector );
		Array.prototype.forEach.call( resizableElements, function ( el ) {
			var marginWidth = self.getExtraDimension( el, 'margin', 'horizontal' );
			var marginHeight = self.getExtraDimension( el, 'margin', 'vertical' );

			var paddingWidth = self.getExtraDimension( el, 'padding', 'horizontal' );
			var paddingHeight = self.getExtraDimension( el, 'padding', 'vertical' );

			var borderWidth = self.getExtraDimension( el, 'border', 'horizontal' );
			var borderHeight = self.getExtraDimension( el, 'border', 'vertical' );

			// Take all outer dimensions into account when resizing so that images
			// scale with constant empty space between them
			var outerWidth =
				parseInt( el.dataset.originalWidth, 10 ) + paddingWidth + borderWidth + marginWidth;
			var outerHeight =
				parseInt( el.dataset.originalHeight, 10 ) + paddingHeight + borderHeight + marginHeight;

			// Subtract margins so that images don't overflow on small browser windows
			el.style.width = Math.floor( resizeRatio * outerWidth ) - marginWidth + 'px';
			el.style.height = Math.floor( resizeRatio * outerHeight ) - marginHeight + 'px';
		} );
	};

	/**
	 * Resizing logic
	 */

	var requestAnimationFrame =
		window.requestAnimationFrame ||
		window.mozRequestAnimationFrame ||
		window.webkitRequestAnimationFrame ||
		window.msRequestAnimationFrame;

	function attachResizeInAnimationFrames( tiledGalleries ) {
		var resizing = false;
		var resizeTimeout = null;

		function handleFrame() {
			tiledGalleries.resizeAll();
			if ( resizing ) {
				requestAnimationFrame( handleFrame );
			}
		}

		window.addEventListener( 'resize', function () {
			clearTimeout( resizeTimeout );

			if ( ! resizing ) {
				requestAnimationFrame( handleFrame );
			}
			resizing = true;
			resizeTimeout = setTimeout( function () {
				resizing = false;
			}, 15 );
		} );
	}

	function attachPlainResize( tiledGalleries ) {
		window.addEventListener( 'resize', function () {
			tiledGalleries.resizeAll();
		} );
	}

	/**
	 * Ready, set...
	 */
	function ready( fn ) {
		if ( document.readyState !== 'loading' ) {
			fn();
		} else {
			document.addEventListener( 'DOMContentLoaded', fn );
		}
	}
	ready( function () {
		var tiledGalleries = new TiledGalleryCollection();

		document.body.addEventListener( 'is.post-load', function () {
			tiledGalleries.findAndSetupNewGalleries();
		} );

		// Chrome is a unique snow flake and will start lagging on occasion
		// It helps if we only resize on animation frames
		//
		// For other browsers it seems like there is no lag even if we resize every
		// time there is an event
		if ( window.chrome && requestAnimationFrame ) {
			attachResizeInAnimationFrames( tiledGalleries );
		} else {
			attachPlainResize( tiledGalleries );
		}

		if ( 'undefined' !== typeof wp && wp.customize && wp.customize.selectiveRefresh ) {
			wp.customize.selectiveRefresh.bind( 'partial-content-rendered', function ( placement ) {
				if ( wp.isJetpackWidgetPlaced( placement, 'gallery' ) ) {
					tiledGalleries.findAndSetupNewGalleries();
				}
			} );
		}
	} );
} )();
