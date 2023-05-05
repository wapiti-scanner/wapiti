/* global wpcom, jetpackCarouselStrings, DocumentTouch */

( function () {
	'use strict';
	var swiper;
	/////////////////////////////////////
	// Utility functions
	/////////////////////////////////////
	var util = ( function () {
		var noop = function () {};

		function texturize( text ) {
			// Ensure we get a string.
			text = text + '';
			text = text.replace( /'/g, '&#8217;' ).replace( /&#039;/g, '&#8217;' );
			text = text
				.replace( /"/g, '&#8221;' )
				.replace( /&#034;/g, '&#8221;' )
				.replace( /&quot;/g, '&#8221;' )
				.replace( /[\u201D]/g, '&#8221;' );
			// Untexturize allowed HTML tags params double-quotes.
			text = text.replace( /([\w]+)=&#[\d]+;(.+?)&#[\d]+;/g, '$1="$2"' );
			return text.trim();
		}

		function applyReplacements( text, replacements ) {
			if ( ! text ) {
				return;
			}
			if ( ! replacements ) {
				return text;
			}
			return text.replace( /{(\d+)}/g, function ( match, number ) {
				return typeof replacements[ number ] !== 'undefined' ? replacements[ number ] : match;
			} );
		}

		function getBackgroundImage( imgEl ) {
			var canvas = document.createElement( 'canvas' ),
				context = canvas.getContext && canvas.getContext( '2d' );

			if ( ! imgEl ) {
				return;
			}

			context.filter = 'blur(20px) ';
			context.drawImage( imgEl, 0, 0 );
			var url = canvas.toDataURL( 'image/png' );
			canvas = null;

			return url;
		}

		return {
			noop: noop,
			texturize: texturize,
			applyReplacements: applyReplacements,
			getBackgroundImage: getBackgroundImage,
		};
	} )();

	/////////////////////////////////////
	// DOM-related utility functions
	/////////////////////////////////////
	var domUtil = ( function () {
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

		function hide( el ) {
			if ( el ) {
				el.style.display = 'none';
			}
		}

		function show( el ) {
			if ( el ) {
				// Everything we show and hide in Carousel is currently a block,
				// so we can make this really straightforward.
				el.style.display = 'block';
			}
		}

		function fade( el, start, end, callback ) {
			if ( ! el ) {
				return callback();
			}

			// Prepare for transition.
			// Ensure the item is in the render tree, in its initial state.
			el.style.removeProperty( 'display' );
			el.style.opacity = start;
			el.style.transition = 'opacity 0.2s';
			el.style.pointerEvents = 'none';

			var finished = function ( e ) {
				if ( e.target === el && e.propertyName === 'opacity' ) {
					el.style.removeProperty( 'transition' );
					el.style.removeProperty( 'opacity' );
					el.style.removeProperty( 'pointer-events' );
					el.removeEventListener( 'transitionend', finished );
					el.removeEventListener( 'transitioncancel', finished );
					callback();
				}
			};

			requestAnimationFrame( function () {
				// Double rAF for browser compatibility.
				requestAnimationFrame( function () {
					el.addEventListener( 'transitionend', finished );
					el.addEventListener( 'transitioncancel', finished );
					// Trigger transition.
					el.style.opacity = end;
				} );
			} );
		}

		function fadeIn( el, callback ) {
			callback = callback || util.noop;
			fade( el, '0', '1', callback );
		}

		function fadeOut( el, callback ) {
			callback = callback || util.noop;
			fade( el, '1', '0', function () {
				if ( el ) {
					el.style.display = 'none';
				}
				callback();
			} );
		}

		function emitEvent( el, type, detail ) {
			var e;
			try {
				e = new CustomEvent( type, {
					bubbles: true,
					cancelable: true,
					detail: detail || null,
				} );
			} catch ( err ) {
				e = document.createEvent( 'CustomEvent' );
				e.initCustomEvent( type, true, true, detail || null );
			}
			el.dispatchEvent( e );
		}

		// From: https://easings.net/#easeInOutQuad
		function easeInOutQuad( num ) {
			return num < 0.5 ? 2 * num * num : 1 - Math.pow( -2 * num + 2, 2 ) / 2;
		}

		function getFooterClearance( container ) {
			var footer = container.querySelector( '.jp-carousel-info-footer' );
			var infoArea = container.querySelector( '.jp-carousel-info-extra' );
			var contentArea = container.querySelector( '.jp-carousel-info-content-wrapper' );

			if ( footer && infoArea && contentArea ) {
				var styles = window.getComputedStyle( infoArea );
				var padding = parseInt( styles.paddingTop, 10 ) + parseInt( styles.paddingBottom, 10 );
				padding = isNaN( padding ) ? 0 : padding;
				return contentArea.offsetHeight + footer.offsetHeight + padding;
			}
			return 0;
		}

		function isTouch() {
			return (
				'ontouchstart' in window || ( window.DocumentTouch && document instanceof DocumentTouch )
			);
		}

		function scrollToElement( el, container, callback ) {
			if ( ! el || ! container ) {
				if ( callback ) {
					return callback();
				}
				return;
			}

			// For iOS Safari compatibility, use JS to set the minimum height.
			var infoArea = container.querySelector( '.jp-carousel-info-extra' );
			if ( infoArea ) {
				// 64px is the same height as `.jp-carousel-info-footer` in the CSS.
				infoArea.style.minHeight = window.innerHeight - 64 + 'px';
			}

			var isScrolling = true;
			var startTime = Date.now();
			var duration = 300;
			var originalPosition = container.scrollTop;
			var targetPosition = Math.max(
				0,
				el.offsetTop - Math.max( 0, window.innerHeight - getFooterClearance( container ) )
			);
			var distance = targetPosition - container.scrollTop;
			distance = Math.min( distance, container.scrollHeight - window.innerHeight );

			function stopScroll() {
				isScrolling = false;
			}

			function runScroll() {
				var now = Date.now();
				var progress = easeInOutQuad( ( now - startTime ) / duration );

				progress = progress > 1 ? 1 : progress;
				var newVal = progress * distance;
				container.scrollTop = originalPosition + newVal;

				if ( now <= startTime + duration && isScrolling ) {
					return requestAnimationFrame( runScroll );
				}
				if ( callback ) {
					callback();
				}
				if ( infoArea ) {
					infoArea.style.minHeight = '';
				}
				isScrolling = false;
				container.removeEventListener( 'wheel', stopScroll );
			}

			// Allow scroll to be cancelled by user interaction.
			container.addEventListener( 'wheel', stopScroll );
			runScroll();
		}

		function getJSONAttribute( el, attr ) {
			if ( ! el || ! el.hasAttribute( attr ) ) {
				return undefined;
			}

			try {
				return JSON.parse( el.getAttribute( attr ) );
			} catch ( e ) {
				return undefined;
			}
		}

		function convertToPlainText( html ) {
			var dummy = document.createElement( 'div' );
			dummy.textContent = html;
			return dummy.innerHTML;
		}

		function stripHTML( text ) {
			return text.replace( /<[^>]*>?/gm, '' );
		}

		return {
			closest: closest,
			matches: matches,
			hide: hide,
			show: show,
			fadeIn: fadeIn,
			fadeOut: fadeOut,
			scrollToElement: scrollToElement,
			getJSONAttribute: getJSONAttribute,
			convertToPlainText: convertToPlainText,
			stripHTML: stripHTML,
			emitEvent: emitEvent,
			isTouch: isTouch,
		};
	} )();

	/////////////////////////////////////
	// Carousel implementation
	/////////////////////////////////////
	function init() {
		var commentInterval;
		var screenPadding;
		var originalOverflow;
		var originalHOverflow;
		var scrollPos;

		var lastKnownLocationHash = '';
		var isUserTyping = false;

		var gallerySelector =
			'div.gallery, div.tiled-gallery, ul.wp-block-gallery, ul.blocks-gallery-grid, ' +
			'figure.wp-block-gallery.has-nested-images, div.wp-block-jetpack-tiled-gallery, a.single-image-gallery';

		// Selector for items within a gallery or tiled gallery.
		var galleryItemSelector =
			'.gallery-item, .tiled-gallery-item, .blocks-gallery-item, ' + ' .tiled-gallery__item';

		// Selector for all items including single images.
		var itemSelector = galleryItemSelector + ', .wp-block-image';

		var carousel = {};

		var stat =
			typeof wpcom !== 'undefined' && wpcom.carousel && wpcom.carousel.stat
				? wpcom.carousel.stat
				: util.noop;

		var pageview =
			typeof wpcom !== 'undefined' && wpcom.carousel && wpcom.carousel.pageview
				? wpcom.carousel.pageview
				: util.noop;

		function handleKeyboardEvent( e ) {
			if ( ! isUserTyping ) {
				switch ( e.which ) {
					case 38: // up
						e.preventDefault();
						carousel.overlay.scrollTop -= 100;
						break;
					case 40: // down
						e.preventDefault();
						carousel.overlay.scrollTop += 100;
						break;
					case 39: // right
						e.preventDefault();
						swiper.slideNext();
						break;
					case 37: // left
					case 8: // backspace
						e.preventDefault();
						swiper.slidePrev();
						break;
					case 27: // escape
						e.preventDefault();
						closeCarousel();
						break;
					default:
						break;
				}
			}
		}

		function disableKeyboardNavigation() {
			isUserTyping = true;
		}

		function enableKeyboardNavigation() {
			isUserTyping = false;
		}

		function calculatePadding() {
			var baseScreenPadding = 110;
			screenPadding = baseScreenPadding;

			if ( window.innerWidth <= 760 ) {
				screenPadding = Math.round( ( window.innerWidth / 760 ) * baseScreenPadding );

				if ( screenPadding < 40 && domUtil.isTouch() ) {
					screenPadding = 0;
				}
			}
		}

		function initializeCarousel() {
			if ( ! carousel.overlay ) {
				carousel.overlay = document.querySelector( '.jp-carousel-overlay' );
				carousel.container = carousel.overlay.querySelector( '.jp-carousel-wrap' );
				carousel.gallery = carousel.container.querySelector( '.jp-carousel' );
				carousel.info = carousel.overlay.querySelector( '.jp-carousel-info' );
				carousel.caption = carousel.info.querySelector( '.jp-carousel-caption' );
				carousel.commentField = carousel.overlay.querySelector(
					'#jp-carousel-comment-form-comment-field'
				);
				carousel.emailField = carousel.overlay.querySelector(
					'#jp-carousel-comment-form-email-field'
				);
				carousel.authorField = carousel.overlay.querySelector(
					'#jp-carousel-comment-form-author-field'
				);
				carousel.urlField = carousel.overlay.querySelector( '#jp-carousel-comment-form-url-field' );

				calculatePadding();

				[
					carousel.commentField,
					carousel.emailField,
					carousel.authorField,
					carousel.urlField,
				].forEach( function ( field ) {
					if ( field ) {
						field.addEventListener( 'focus', disableKeyboardNavigation );
						field.addEventListener( 'blur', enableKeyboardNavigation );
					}
				} );

				carousel.overlay.addEventListener( 'click', function ( e ) {
					var target = e.target;
					var isTargetCloseHint = !! domUtil.closest( target, '.jp-carousel-close-hint' );
					var isSmallScreen = !! window.matchMedia( '(max-device-width: 760px)' ).matches;
					if ( target === carousel.overlay ) {
						if ( isSmallScreen ) {
							return;
						} else {
							closeCarousel();
						}
					} else if ( isTargetCloseHint ) {
						closeCarousel();
					} else if ( target.classList.contains( 'jp-carousel-image-download' ) ) {
						stat( 'download_original_click' );
					} else if ( target.classList.contains( 'jp-carousel-comment-login' ) ) {
						handleCommentLoginClick( e );
					} else if ( domUtil.closest( target, '#jp-carousel-comment-form-container' ) ) {
						handleCommentFormClick( e );
					} else if (
						domUtil.closest( target, '.jp-carousel-photo-icons-container' ) ||
						target.classList.contains( 'jp-carousel-photo-title' )
					) {
						handleFooterElementClick( e );
					} else if ( ! domUtil.closest( target, '.jp-carousel-info' ) ) {
						return;
					}
				} );

				window.addEventListener( 'keydown', handleKeyboardEvent );

				carousel.overlay.addEventListener( 'jp_carousel.afterOpen', function () {
					enableKeyboardNavigation();

					// Don't show navigation if there's only one image.
					if ( carousel.slides.length <= 1 ) {
						return;
					}
					// Show dot pagination if slide count is <= 5, otherwise show n/total.
					if ( carousel.slides.length <= 5 ) {
						domUtil.show( carousel.info.querySelector( '.jp-swiper-pagination' ) );
					} else {
						domUtil.show( carousel.info.querySelector( '.jp-carousel-pagination' ) );
					}
				} );

				carousel.overlay.addEventListener( 'jp_carousel.beforeClose', function () {
					disableKeyboardNavigation();

					// Fixes some themes where closing carousel brings view back to top.
					document.documentElement.style.removeProperty( 'height' );

					// If we disable the swiper (because there's only one image)
					// we have to re-enable it here again as Swiper doesn't, for some reason,
					// show the navigation buttons again after reinitialization.
					if ( swiper ) {
						swiper.enable();
					}

					// Hide pagination.
					domUtil.hide( carousel.info.querySelector( '.jp-swiper-pagination' ) );
					domUtil.hide( carousel.info.querySelector( '.jp-carousel-pagination' ) );
				} );

				carousel.overlay.addEventListener( 'jp_carousel.afterClose', function () {
					// don't force the browser back when the carousel closes.
					if ( window.history.pushState ) {
						history.pushState(
							'',
							document.title,
							window.location.pathname + window.location.search
						);
					} else {
						window.location.href = '';
					}
					lastKnownLocationHash = '';
					carousel.isOpen = false;
				} );

				// Prevent native browser zooming
				carousel.overlay.addEventListener( 'touchstart', function ( e ) {
					if ( e.touches.length > 1 ) {
						e.preventDefault();
					}
				} );
			}
		}

		function handleCommentLoginClick() {
			var slide = carousel.currentSlide;
			var attachmentId = slide ? slide.attrs.attachmentId : '0';

			window.location.href = jetpackCarouselStrings.login_url + '%23jp-carousel-' + attachmentId;
		}

		function updatePostResults( msg, isSuccess ) {
			var results = carousel.overlay.querySelector( '#jp-carousel-comment-post-results' );
			var elClass = 'jp-carousel-comment-post-' + ( isSuccess ? 'success' : 'error' );
			results.innerHTML = '<span class="' + elClass + '">' + msg + '</span>';
			domUtil.hide( carousel.overlay.querySelector( '#jp-carousel-comment-form-spinner' ) );
			carousel.overlay
				.querySelector( '#jp-carousel-comment-form' )
				.classList.remove( 'jp-carousel-is-disabled' );
			domUtil.show( results );
		}

		function handleCommentFormClick( e ) {
			var target = e.target;
			var data = domUtil.getJSONAttribute( carousel.container, 'data-carousel-extra' ) || {};
			var attachmentId = carousel.currentSlide.attrs.attachmentId;

			var wrapper = document.querySelector( '#jp-carousel-comment-form-submit-and-info-wrapper' );
			var spinner = document.querySelector( '#jp-carousel-comment-form-spinner' );
			var submit = document.querySelector( '#jp-carousel-comment-form-button-submit' );
			var form = document.querySelector( '#jp-carousel-comment-form' );

			if (
				carousel.commentField &&
				carousel.commentField.getAttribute( 'id' ) === target.getAttribute( 'id' )
			) {
				// For first page load
				disableKeyboardNavigation();
				domUtil.show( wrapper );
			} else if ( domUtil.matches( target, 'input[type="submit"]' ) ) {
				e.preventDefault();
				e.stopPropagation();

				domUtil.show( spinner );
				form.classList.add( 'jp-carousel-is-disabled' );

				var ajaxData = {
					action: 'post_attachment_comment',
					nonce: jetpackCarouselStrings.nonce,
					blog_id: data.blog_id,
					id: attachmentId,
					comment: carousel.commentField.value,
				};

				if ( ! ajaxData.comment.length ) {
					updatePostResults( jetpackCarouselStrings.no_comment_text, false );
					return;
				}

				if ( Number( jetpackCarouselStrings.is_logged_in ) !== 1 ) {
					ajaxData.email = carousel.emailField.value;
					ajaxData.author = carousel.authorField.value;
					ajaxData.url = carousel.urlField.value;

					if ( Number( jetpackCarouselStrings.require_name_email ) === 1 ) {
						if ( ! ajaxData.email.length || ! ajaxData.email.match( '@' ) ) {
							updatePostResults( jetpackCarouselStrings.no_comment_email, false );
							return;
						} else if ( ! ajaxData.author.length ) {
							updatePostResults( jetpackCarouselStrings.no_comment_author, false );
							return;
						}
					}
				}

				var xhr = new XMLHttpRequest();
				xhr.open( 'POST', jetpackCarouselStrings.ajaxurl, true );
				xhr.setRequestHeader( 'X-Requested-With', 'XMLHttpRequest' );
				xhr.setRequestHeader( 'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8' );

				xhr.onreadystatechange = function () {
					if (
						this.readyState === XMLHttpRequest.DONE &&
						this.status >= 200 &&
						this.status < 300
					) {
						var response;
						try {
							response = JSON.parse( this.response );
						} catch ( error ) {
							updatePostResults( jetpackCarouselStrings.comment_post_error, false );
							return;
						}
						if ( response.comment_status === 'approved' ) {
							updatePostResults( jetpackCarouselStrings.comment_approved, true );
						} else if ( response.comment_status === 'unapproved' ) {
							updatePostResults( jetpackCarouselStrings.comment_unapproved, true );
						} else {
							// 'deleted', 'spam', false
							updatePostResults( jetpackCarouselStrings.comment_post_error, false );
						}
						clearCommentTextAreaValue();
						fetchComments( attachmentId );
						submit.value = jetpackCarouselStrings.post_comment;
						domUtil.hide( spinner );
						form.classList.remove( 'jp-carousel-is-disabled' );
					} else {
						// TODO: Add error handling and display here
						updatePostResults( jetpackCarouselStrings.comment_post_error, false );
					}
				};

				var params = [];
				for ( var item in ajaxData ) {
					if ( item ) {
						// Encode each form element into a URI-compatible string.
						var encoded = encodeURIComponent( item ) + '=' + encodeURIComponent( ajaxData[ item ] );
						// In x-www-form-urlencoded, spaces should be `+`, not `%20`.
						params.push( encoded.replace( /%20/g, '+' ) );
					}
				}
				var encodedData = params.join( '&' );

				xhr.send( encodedData );
			}
		}

		/**
		 * Handles clicks to icons and other action elements in the icon container.
		 * @param {MouseEvent|TouchEvent|KeyBoardEvent} Event object.
		 */
		function handleFooterElementClick( e ) {
			e.preventDefault();

			var target = e.target;
			var extraInfoContainer = carousel.info.querySelector( '.jp-carousel-info-extra' );
			var photoMetaContainer = carousel.info.querySelector( '.jp-carousel-image-meta' );
			var commentsContainer = carousel.info.querySelector( '.jp-carousel-comments-wrapper' );
			var infoIcon = carousel.info.querySelector( '.jp-carousel-icon-info' );
			var commentsIcon = carousel.info.querySelector( '.jp-carousel-icon-comments' );

			function handleInfoToggle() {
				if ( commentsIcon ) {
					commentsIcon.classList.remove( 'jp-carousel-selected' );
				}
				infoIcon.classList.toggle( 'jp-carousel-selected' );

				if ( commentsContainer ) {
					commentsContainer.classList.remove( 'jp-carousel-show' );
				}
				if ( photoMetaContainer ) {
					photoMetaContainer.classList.toggle( 'jp-carousel-show' );
					if ( photoMetaContainer.classList.contains( 'jp-carousel-show' ) ) {
						extraInfoContainer.classList.add( 'jp-carousel-show' );
					} else {
						extraInfoContainer.classList.remove( 'jp-carousel-show' );
					}
				}
			}

			function handleCommentToggle() {
				if ( infoIcon ) {
					infoIcon.classList.remove( 'jp-carousel-selected' );
				}
				commentsIcon.classList.toggle( 'jp-carousel-selected' );

				if ( photoMetaContainer ) {
					photoMetaContainer.classList.remove( 'jp-carousel-show' );
				}
				if ( commentsContainer ) {
					commentsContainer.classList.toggle( 'jp-carousel-show' );
					if ( commentsContainer.classList.contains( 'jp-carousel-show' ) ) {
						extraInfoContainer.classList.add( 'jp-carousel-show' );
					} else {
						extraInfoContainer.classList.remove( 'jp-carousel-show' );
					}
				}
			}

			if (
				domUtil.closest( target, '.jp-carousel-icon-info' ) ||
				target.classList.contains( 'jp-carousel-photo-title' )
			) {
				if ( photoMetaContainer && photoMetaContainer.classList.contains( 'jp-carousel-show' ) ) {
					domUtil.scrollToElement( carousel.overlay, carousel.overlay, handleInfoToggle );
				} else {
					handleInfoToggle();
					domUtil.scrollToElement( carousel.info, carousel.overlay );
				}
			}

			if ( domUtil.closest( target, '.jp-carousel-icon-comments' ) ) {
				if ( commentsContainer && commentsContainer.classList.contains( 'jp-carousel-show' ) ) {
					domUtil.scrollToElement( carousel.overlay, carousel.overlay, handleCommentToggle );
				} else {
					handleCommentToggle();
					domUtil.scrollToElement( carousel.info, carousel.overlay );
				}
			}
		}

		function processSingleImageGallery() {
			var images = document.querySelectorAll( 'a img[data-attachment-id]' );
			Array.prototype.forEach.call( images, function ( image ) {
				var link = image.parentElement;
				var container = link.parentElement;

				// Skip if image was already added to gallery by shortcode.
				if ( container.classList.contains( 'gallery-icon' ) ) {
					return;
				}

				// Skip if image is part of a gallery.
				if ( domUtil.closest( container, galleryItemSelector ) ) {
					return;
				}

				// Skip if the parent is not actually a link.
				if ( ! link.hasAttribute( 'href' ) ) {
					return;
				}

				var valid = false;

				// If link points to 'Media File' (ignoring GET parameters) and flag is set, allow it.
				if (
					link.getAttribute( 'href' ).split( '?' )[ 0 ] ===
						image.getAttribute( 'data-orig-file' ).split( '?' )[ 0 ] &&
					Number( jetpackCarouselStrings.single_image_gallery_media_file ) === 1
				) {
					valid = true;
				}

				// If link points to 'Attachment Page', allow it.
				if ( link.getAttribute( 'href' ) === image.getAttribute( 'data-permalink' ) ) {
					valid = true;
				}

				// Links to 'Custom URL' or 'Media File' when flag is not set are not valid.
				if ( ! valid ) {
					return;
				}

				// Make this node a gallery recognizable by event listener above.
				link.classList.add( 'single-image-gallery' );
				// blog_id is needed to allow posting comments to correct blog.
				link.setAttribute(
					'data-carousel-extra',
					JSON.stringify( {
						blog_id: Number( jetpackCarouselStrings.blog_id ),
					} )
				);
			} );
		}

		function testForData( el ) {
			return !! ( el && el.getAttribute( 'data-carousel-extra' ) );
		}

		function openOrSelectSlide( gal, index ) {
			if ( ! carousel.isOpen ) {
				// The `open` method selects the correct slide during the initialization.
				loadSwiper( gal, { startIndex: index } );
			} else {
				selectSlideAtIndex( index );
				// We have to force swiper to slide to the index onHasChange.
				swiper.slideTo( index + 1 );
			}
		}

		function selectSlideAtIndex( index ) {
			if ( ! index || index < 0 || index > carousel.slides.length ) {
				index = 0;
			}
			carousel.currentSlide = carousel.slides[ index ];

			var current = carousel.currentSlide;
			var attachmentId = current.attrs.attachmentId;
			var infoIcon = carousel.info.querySelector( '.jp-carousel-icon-info' );
			var commentsIcon = carousel.info.querySelector( '.jp-carousel-icon-comments' );

			// If the comment/info section is toggled open, it's kept open, but scroll to top of the next slide.
			if (
				( infoIcon && infoIcon.classList.contains( 'jp-carousel-selected' ) ) ||
				( commentsIcon && commentsIcon.classList.contains( 'jp-carousel-selected' ) )
			) {
				if ( carousel.overlay.scrollTop !== 0 ) {
					domUtil.scrollToElement( carousel.overlay, carousel.overlay );
				}
			}

			loadFullImage( carousel.slides[ index ] );

			if (
				Number( jetpackCarouselStrings.display_background_image ) === 1 &&
				! carousel.slides[ index ].backgroundImage
			) {
				loadBackgroundImage( carousel.slides[ index ] );
			}

			domUtil.hide( carousel.caption );
			updateTitleCaptionAndDesc( {
				caption: current.attrs.caption,
				title: current.attrs.title,
				desc: current.attrs.desc,
			} );

			var imageMeta = carousel.slides[ index ].attrs.imageMeta;
			updateExif( imageMeta );
			updateFullSizeLink( current );

			if ( Number( jetpackCarouselStrings.display_comments ) === 1 ) {
				testCommentsOpened( carousel.slides[ index ].attrs.commentsOpened );
				fetchComments( attachmentId );
				domUtil.hide( carousel.info.querySelector( '#jp-carousel-comment-post-results' ) );
			}

			// Update pagination in footer.
			var pagination = carousel.info.querySelector( '.jp-carousel-pagination' );
			if ( pagination && carousel.slides.length > 5 ) {
				var currentPage = index + 1;
				pagination.innerHTML = '<span>' + currentPage + ' / ' + carousel.slides.length + '</span>';
			}

			// Record pageview in WP Stats, for each new image loaded full-screen.
			if ( jetpackCarouselStrings.stats ) {
				new Image().src =
					document.location.protocol +
					'//pixel.wp.com/g.gif?' +
					jetpackCarouselStrings.stats +
					'&post=' +
					encodeURIComponent( attachmentId ) +
					'&rand=' +
					Math.random();
			}

			pageview( attachmentId );

			window.location.hash = lastKnownLocationHash = '#jp-carousel-' + attachmentId;
		}

		function restoreScroll() {
			window.scrollTo( window.scrollX || window.pageXOffset || 0, scrollPos || 0 );
		}

		function closeCarousel() {
			// Make sure to let the page scroll again.
			document.body.style.overflow = originalOverflow;
			document.documentElement.style.overflow = originalHOverflow;
			clearCommentTextAreaValue();

			disableKeyboardNavigation();

			domUtil.emitEvent( carousel.overlay, 'jp_carousel.beforeClose' );
			restoreScroll();
			swiper.destroy();
			carousel.isOpen = false;
			// Clear slide data for DOM garbage collection.
			carousel.slides = [];
			carousel.currentSlide = undefined;
			carousel.gallery.innerHTML = '';

			domUtil.fadeOut( carousel.overlay, function () {
				domUtil.emitEvent( carousel.overlay, 'jp_carousel.afterClose' );
			} );
		}

		function calculateMaxSlideDimensions() {
			return {
				width: window.innerWidth,
				height: window.innerHeight - 64, //subtract height of bottom info bar,
			};
		}

		function selectBestImageUrl( args ) {
			if ( typeof args !== 'object' ) {
				args = {};
			}

			if ( typeof args.origFile === 'undefined' ) {
				return '';
			}

			if ( typeof args.origWidth === 'undefined' || typeof args.maxWidth === 'undefined' ) {
				return args.origFile;
			}

			if ( typeof args.mediumFile === 'undefined' || typeof args.largeFile === 'undefined' ) {
				return args.origFile;
			}

			// Check if the image is being served by Photon (using a regular expression on the hostname).

			var imageLinkParser = document.createElement( 'a' );
			imageLinkParser.href = args.largeFile;

			var isPhotonUrl = /^i[0-2]\.wp\.com$/i.test( imageLinkParser.hostname );

			var mediumSizeParts = getImageSizeParts( args.mediumFile, args.origWidth, isPhotonUrl );
			var largeSizeParts = getImageSizeParts( args.largeFile, args.origWidth, isPhotonUrl );

			var largeWidth = parseInt( largeSizeParts[ 0 ], 10 );
			var largeHeight = parseInt( largeSizeParts[ 1 ], 10 );
			var mediumWidth = parseInt( mediumSizeParts[ 0 ], 10 );
			var mediumHeight = parseInt( mediumSizeParts[ 1 ], 10 );

			args.origMaxWidth = args.maxWidth;
			args.origMaxHeight = args.maxHeight;

			// Give devices with a higher devicePixelRatio higher-res images (Retina display = 2, Android phones = 1.5, etc)
			if ( typeof window.devicePixelRatio !== 'undefined' && window.devicePixelRatio > 1 ) {
				args.maxWidth = args.maxWidth * window.devicePixelRatio;
				args.maxHeight = args.maxHeight * window.devicePixelRatio;
			}

			if ( largeWidth >= args.maxWidth || largeHeight >= args.maxHeight ) {
				return args.largeFile;
			}

			if ( mediumWidth >= args.maxWidth || mediumHeight >= args.maxHeight ) {
				return args.mediumFile;
			}

			if ( isPhotonUrl ) {
				// args.origFile doesn't point to a Photon url, so in this case we use args.largeFile
				// to return the photon url of the original image.
				var largeFileIndex = args.largeFile.lastIndexOf( '?' );
				var origPhotonUrl = args.largeFile;
				if ( largeFileIndex !== -1 ) {
					origPhotonUrl = args.largeFile.substring( 0, largeFileIndex );
					// If we have a really large image load a smaller version
					// that is closer to the viewable size
					if ( args.origWidth > args.maxWidth || args.origHeight > args.maxHeight ) {
						// @2x the max sizes so we get a high enough resolution for zooming.
						args.origMaxWidth = args.maxWidth * 2;
						args.origMaxHeight = args.maxHeight * 2;
						origPhotonUrl += '?fit=' + args.origMaxWidth + '%2C' + args.origMaxHeight;
					}
				}
				return origPhotonUrl;
			}

			return args.origFile;
		}

		function getImageSizeParts( file, origWidth, isPhotonUrl ) {
			var size = isPhotonUrl
				? file.replace( /.*=([\d]+%2C[\d]+).*$/, '$1' )
				: file.replace( /.*-([\d]+x[\d]+)\..+$/, '$1' );

			var sizeParts =
				size !== file
					? isPhotonUrl
						? size.split( '%2C' )
						: size.split( 'x' )
					: [ origWidth, 0 ];

			// If one of the dimensions is set to 9999, then the actual value of that dimension can't be retrieved from the url.
			// In that case, we set the value to 0.
			if ( sizeParts[ 0 ] === '9999' ) {
				sizeParts[ 0 ] = '0';
			}

			if ( sizeParts[ 1 ] === '9999' ) {
				sizeParts[ 1 ] = '0';
			}

			return sizeParts;
		}

		/**
		 * Returns a number in a fraction format that represents the shutter speed.
		 * @param Number speed
		 * @return String
		 */
		function formatShutterSpeed( speed ) {
			var denominator;

			// round to one decimal if value > 1s by multiplying it by 10, rounding, then dividing by 10 again
			if ( speed >= 1 ) {
				return Math.round( speed * 10 ) / 10 + 's';
			}

			// If the speed is less than one, we find the denominator by inverting
			// the number. Since cameras usually use rational numbers as shutter
			// speeds, we should get a nice round number. Or close to one in cases
			// like 1/30. So we round it.
			denominator = Math.round( 1 / speed );

			return '1/' + denominator + 's';
		}

		function parseTitleOrDesc( value ) {
			if ( ! value.match( ' ' ) && value.match( '_' ) ) {
				return '';
			}

			return value;
		}

		function updateTitleCaptionAndDesc( data ) {
			var caption = '';
			var title = '';
			var desc = '';
			var captionMainElement;
			var captionInfoExtraElement;
			var titleElement;
			var descriptionElement;

			captionMainElement = carousel.overlay.querySelector( '.jp-carousel-photo-caption' );
			captionInfoExtraElement = carousel.overlay.querySelector( '.jp-carousel-caption' );

			titleElement = carousel.overlay.querySelector( '.jp-carousel-photo-title' );
			descriptionElement = carousel.overlay.querySelector( '.jp-carousel-photo-description' );

			domUtil.hide( captionMainElement );
			domUtil.hide( captionInfoExtraElement );
			domUtil.hide( titleElement );
			domUtil.hide( descriptionElement );

			caption = parseTitleOrDesc( data.caption ) || '';
			title = parseTitleOrDesc( data.title ) || '';
			desc = parseTitleOrDesc( data.desc ) || '';

			if ( caption || title || desc ) {
				if ( caption ) {
					captionMainElement.innerHTML = caption;
					captionInfoExtraElement.innerHTML = caption;

					domUtil.show( captionMainElement );
					domUtil.show( captionInfoExtraElement );
				}

				if ( domUtil.stripHTML( caption ) === domUtil.stripHTML( title ) ) {
					title = '';
				}

				if ( domUtil.stripHTML( caption ) === domUtil.stripHTML( desc ) ) {
					desc = '';
				}

				if ( domUtil.stripHTML( title ) === domUtil.stripHTML( desc ) ) {
					desc = '';
				}

				if ( desc ) {
					descriptionElement.innerHTML = desc;
					domUtil.show( descriptionElement );

					if ( ! title && ! caption ) {
						captionMainElement.innerHTML = domUtil.stripHTML( desc );
						domUtil.show( captionMainElement );
					}
				}

				if ( title ) {
					var plainTitle = domUtil.stripHTML( title );
					titleElement.innerHTML = plainTitle;

					if ( ! caption ) {
						captionMainElement.innerHTML = plainTitle;
						captionInfoExtraElement.innerHTML = plainTitle;

						domUtil.show( captionMainElement );
					}

					domUtil.show( titleElement );
				}
			}
		}

		// updateExif updates the contents of the exif UL (.jp-carousel-image-exif)
		function updateExif( meta ) {
			if ( ! meta || Number( jetpackCarouselStrings.display_exif ) !== 1 ) {
				return false;
			}

			var ul = carousel.info.querySelector( '.jp-carousel-image-meta ul.jp-carousel-image-exif' );
			var html = '';

			for ( var key in meta ) {
				var val = meta[ key ];
				var metaKeys = jetpackCarouselStrings.meta_data || [];

				if ( parseFloat( val ) === 0 || ! val.length || metaKeys.indexOf( key ) === -1 ) {
					continue;
				}

				switch ( key ) {
					case 'focal_length':
						val = val + 'mm';
						break;
					case 'shutter_speed':
						val = formatShutterSpeed( val );
						break;
					case 'aperture':
						val = 'f/' + val;
						break;
				}

				html += '<li><h5>' + jetpackCarouselStrings[ key ] + '</h5>' + val + '</li>';
			}

			ul.innerHTML = html;
			ul.style.removeProperty( 'display' );
		}

		// Update the contents of the jp-carousel-image-download link
		function updateFullSizeLink( currentSlide ) {
			if ( ! currentSlide ) {
				return false;
			}
			var original;
			var origSize = [ currentSlide.attrs.origWidth, currentSlide.attrs.origHeight ];
			var imageLinkParser = document.createElement( 'a' );

			imageLinkParser.href = currentSlide.attrs.src.replace( /\?.+$/, '' );

			// Is this a Photon URL?
			if ( imageLinkParser.hostname.match( /^i[\d]{1}\.wp\.com$/i ) !== null ) {
				original = imageLinkParser.href;
			} else {
				original = currentSlide.attrs.origFile.replace( /\?.+$/, '' );
			}

			var downloadText = carousel.info.querySelector( '.jp-carousel-download-text' );
			var permalink = carousel.info.querySelector( '.jp-carousel-image-download' );

			downloadText.innerHTML = util.applyReplacements(
				jetpackCarouselStrings.download_original,
				origSize
			);
			permalink.setAttribute( 'href', original );
			permalink.style.removeProperty( 'display' );
		}

		function testCommentsOpened( opened ) {
			var commentForm = carousel.container.querySelector( '.jp-carousel-comment-form-container' );
			var isOpened = parseInt( opened, 10 ) === 1;

			if ( isOpened ) {
				domUtil.fadeIn( commentForm );
			} else {
				domUtil.fadeOut( commentForm );
			}
		}

		function fetchComments( attachmentId, offset ) {
			var shouldClear = offset === undefined;
			var commentsIndicator = carousel.info.querySelector(
				'.jp-carousel-icon-comments .jp-carousel-has-comments-indicator'
			);

			commentsIndicator.classList.remove( 'jp-carousel-show' );

			clearInterval( commentInterval );

			if ( ! attachmentId ) {
				return;
			}

			if ( ! offset || offset < 1 ) {
				offset = 0;
			}

			var comments = carousel.info.querySelector( '.jp-carousel-comments' );
			var commentsLoading = carousel.info.querySelector( '#jp-carousel-comments-loading' );
			domUtil.show( commentsLoading );

			if ( shouldClear ) {
				domUtil.hide( comments );
				comments.innerHTML = '';
			}

			var xhr = new XMLHttpRequest();
			var url =
				jetpackCarouselStrings.ajaxurl +
				'?action=get_attachment_comments' +
				'&nonce=' +
				jetpackCarouselStrings.nonce +
				'&id=' +
				attachmentId +
				'&offset=' +
				offset;
			xhr.open( 'GET', url );
			xhr.setRequestHeader( 'X-Requested-With', 'XMLHttpRequest' );

			var onError = function () {
				domUtil.fadeIn( comments );
				domUtil.fadeOut( commentsLoading );
			};

			xhr.onload = function () {
				// Ignore the results if they arrive late and we're now on a different slide.
				if (
					! carousel.currentSlide ||
					carousel.currentSlide.attrs.attachmentId !== attachmentId
				) {
					return;
				}

				var isSuccess = xhr.status >= 200 && xhr.status < 300;
				var data;
				try {
					data = JSON.parse( xhr.responseText );
				} catch ( e ) {
					// Do nothing.
				}

				if ( ! isSuccess || ! data || ! Array.isArray( data ) ) {
					return onError();
				}

				if ( shouldClear ) {
					comments.innerHTML = '';
				}

				for ( var i = 0; i < data.length; i++ ) {
					var entry = data[ i ];
					var comment = document.createElement( 'div' );
					comment.classList.add( 'jp-carousel-comment' );
					comment.setAttribute( 'id', 'jp-carousel-comment-' + entry.id );
					comment.innerHTML =
						'<div class="comment-gravatar">' +
						entry.gravatar_markup +
						'</div>' +
						'<div class="comment-content">' +
						'<div class="comment-author">' +
						entry.author_markup +
						'</div>' +
						'<div class="comment-date">' +
						entry.date_gmt +
						'</div>' +
						entry.content +
						'</div>';
					comments.appendChild( comment );

					// Set the interval to check for a new page of comments.
					clearInterval( commentInterval );
					commentInterval = setInterval( function () {
						if ( carousel.container.scrollTop + 150 > window.innerHeight ) {
							fetchComments( attachmentId, offset + 10 );
							clearInterval( commentInterval );
						}
					}, 300 );
				}

				if ( data.length > 0 ) {
					domUtil.show( comments );
					commentsIndicator.innerText = data.length;
					commentsIndicator.classList.add( 'jp-carousel-show' );
				}

				domUtil.hide( commentsLoading );
			};

			xhr.onerror = onError;

			xhr.send();
		}

		function loadFullImage( slide ) {
			var el = slide.el;
			var attrs = slide.attrs;
			var image = el.querySelector( 'img' );

			if ( ! image.hasAttribute( 'data-loaded' ) ) {
				var hasPreview = !! attrs.previewImage;
				var thumbSize = attrs.thumbSize;

				if ( ! hasPreview || ( thumbSize && el.offsetWidth > thumbSize.width ) ) {
					image.src = attrs.src;
				} else {
					image.src = attrs.previewImage;
				}

				image.setAttribute( 'itemprop', 'image' );
				image.setAttribute( 'data-loaded', 1 );
			}
		}

		function loadBackgroundImage( slide ) {
			var currentSlide = slide.el;

			if ( swiper && swiper.slides ) {
				currentSlide = swiper.slides[ swiper.activeIndex ];
			}

			var image = slide.attrs.originalElement;
			var isLoaded = image.complete && image.naturalHeight !== 0;

			if ( isLoaded ) {
				applyBackgroundImage( slide, currentSlide, image );
				return;
			}

			image.onload = function () {
				applyBackgroundImage( slide, currentSlide, image );
			};
		}

		function applyBackgroundImage( slide, currentSlide, image ) {
			var url = util.getBackgroundImage( image );
			slide.backgroundImage = url;
			currentSlide.style.backgroundImage = 'url(' + url + ')';
			currentSlide.style.backgroundSize = 'cover';
		}

		function clearCommentTextAreaValue() {
			if ( carousel.commentField ) {
				carousel.commentField.value = '';
			}
		}

		function getOriginalDimensions( el ) {
			var size = el.getAttribute( 'data-orig-size' ) || '';

			if ( size ) {
				var parts = size.split( ',' );
				return { width: parseInt( parts[ 0 ], 10 ), height: parseInt( parts[ 1 ], 10 ) };
			} else {
				return {
					width:
						el.getAttribute( 'data-original-width' ) || el.getAttribute( 'width' ) || undefined,
					height:
						el.getAttribute( 'data-original-height' ) || el.getAttribute( 'height' ) || undefined,
				};
			}
		}

		function initCarouselSlides( items, startIndex ) {
			carousel.slides = [];

			var max = calculateMaxSlideDimensions();

			// If the startIndex is not 0 then preload the clicked image first.
			if ( startIndex !== 0 ) {
				var img = new Image();
				img.src = items[ startIndex ].getAttribute( 'data-gallery-src' );
			}

			var useInPageThumbnails = !! domUtil.closest( items[ 0 ], '.tiled-gallery.type-rectangular' );

			// create the 'slide'
			Array.prototype.forEach.call( items, function ( item, i ) {
				var permalinkEl = domUtil.closest( item, 'a' );
				var origFile = item.getAttribute( 'data-orig-file' ) || item.getAttribute( 'src-orig' );
				var attrID =
					item.getAttribute( 'data-attachment-id' ) || item.getAttribute( 'data-id' ) || '0';
				var caption = document.querySelector(
					'img[data-attachment-id="' + attrID + '"] + figcaption'
				);

				if ( caption ) {
					caption = caption.innerHTML;
				} else {
					caption = item.getAttribute( 'data-image-caption' );
				}

				var attrs = {
					originalElement: item,
					attachmentId: attrID,
					commentsOpened: item.getAttribute( 'data-comments-opened' ) || '0',
					imageMeta: domUtil.getJSONAttribute( item, 'data-image-meta' ) || {},
					title: item.getAttribute( 'data-image-title' ) || '',
					desc: item.getAttribute( 'data-image-description' ) || '',
					mediumFile: item.getAttribute( 'data-medium-file' ) || '',
					largeFile: item.getAttribute( 'data-large-file' ) || '',
					origFile: origFile || '',
					thumbSize: { width: item.naturalWidth, height: item.naturalHeight },
					caption: caption || '',
					permalink: permalinkEl && permalinkEl.getAttribute( 'href' ),
					src: origFile || item.getAttribute( 'src' ) || '',
				};

				var tiledGalleryItem = domUtil.closest( item, '.tiled-gallery-item' );
				var tiledCaptionEl =
					tiledGalleryItem && tiledGalleryItem.querySelector( '.tiled-gallery-caption' );
				var tiledCaption = tiledCaptionEl && tiledCaptionEl.innerHTML;
				if ( tiledCaption ) {
					attrs.caption = tiledCaption;
				}

				var origDimensions = getOriginalDimensions( item );

				attrs.origWidth = origDimensions.width || attrs.thumbSize.width;
				attrs.origHeight = origDimensions.height || attrs.thumbSize.height;

				if ( typeof wpcom !== 'undefined' && wpcom.carousel && wpcom.carousel.generateImgSrc ) {
					attrs.src = wpcom.carousel.generateImgSrc( item, max );
				} else {
					attrs.src = selectBestImageUrl( {
						origFile: attrs.src,
						origWidth: attrs.origWidth,
						origHeight: attrs.origHeight,
						maxWidth: max.width,
						maxHeight: max.height,
						mediumFile: attrs.mediumFile,
						largeFile: attrs.largeFile,
					} );
				}

				// Set the final src.
				item.setAttribute( 'data-gallery-src', attrs.src );

				if ( attrs.attachmentId !== '0' ) {
					attrs.title = util.texturize( attrs.title );
					attrs.desc = util.texturize( attrs.desc );
					attrs.caption = util.texturize( attrs.caption );

					// Initially, the image is a 1x1 transparent gif.
					// The preview is shown as a background image on the slide itself.
					var image = new Image();
					image.src = attrs.src;

					var slideEl = document.createElement( 'div' );
					slideEl.classList.add( 'swiper-slide' );
					slideEl.setAttribute( 'itemprop', 'associatedMedia' );
					slideEl.setAttribute( 'itemscope', '' );
					slideEl.setAttribute( 'itemtype', 'https://schema.org/ImageObject' );
					var zoomEl = document.createElement( 'div' );
					zoomEl.classList.add( 'swiper-zoom-container' );

					carousel.gallery.appendChild( slideEl );

					slideEl.appendChild( zoomEl );
					zoomEl.appendChild( image );
					slideEl.setAttribute( 'data-attachment-id', attrs.attachmentId );
					slideEl.setAttribute( 'data-permalink', attrs.permalink );
					slideEl.setAttribute( 'data-orig-file', attrs.origFile );

					if ( useInPageThumbnails ) {
						// Use the image already loaded in the gallery as a preview.
						attrs.previewImage = attrs.src;
					}

					var slide = { el: slideEl, attrs: attrs, index: i };
					carousel.slides.push( slide );
				}
			} );
		}

		function loadSwiper( gallery, options ) {
			if ( ! window.Swiper670 ) {
				var loader = document.querySelector( '#jp-carousel-loading-overlay' );
				domUtil.show( loader );
				var jsScript = document.createElement( 'script' );
				jsScript.id = 'jetpack-carousel-swiper-js';
				jsScript.src = window.jetpackSwiperLibraryPath.url;
				jsScript.async = true;
				jsScript.onload = function () {
					domUtil.hide( loader );
					openCarousel( gallery, options );
				};
				jsScript.onerror = function () {
					domUtil.hide( loader );
				};
				document.head.appendChild( jsScript );
				return;
			}
			openCarousel( gallery, options );
		}

		function openCarousel( gallery, options ) {
			var settings = {
				imgSelector:
					'.gallery-item [data-attachment-id], .tiled-gallery-item [data-attachment-id], img[data-attachment-id], img[data-id]',
				startIndex: 0,
			};

			var data = domUtil.getJSONAttribute( gallery, 'data-carousel-extra' );
			var tapTimeout;

			if ( ! data ) {
				return; // don't run if the default gallery functions weren't used
			}

			initializeCarousel();

			if ( carousel.isOpen ) {
				return; // don't open if already opened
			}
			carousel.isOpen = true;

			// make sure to stop the page from scrolling behind the carousel overlay, so we don't trigger
			// infiniscroll for it when enabled (Reader, theme infiniscroll, etc).
			originalOverflow = getComputedStyle( document.body ).overflow;
			document.body.style.overflow = 'hidden';
			// prevent html from overflowing on some of the new themes.
			originalHOverflow = getComputedStyle( document.documentElement ).overflow;
			document.documentElement.style.overflow = 'hidden';
			scrollPos = window.scrollY || window.pageYOffset || 0;

			carousel.container.setAttribute( 'data-carousel-extra', JSON.stringify( data ) );
			stat( [ 'open', 'view_image' ] );

			// If options exist, lets merge them
			// with our default settings
			for ( var option in options || {} ) {
				settings[ option ] = options[ option ];
			}

			if ( settings.startIndex === -1 ) {
				settings.startIndex = 0; // -1 returned if can't find index, so start from beginning
			}

			domUtil.emitEvent( carousel.overlay, 'jp_carousel.beforeOpen' );
			carousel.gallery.innerHTML = '';

			// Need to set the overlay manually to block or swiper does't initialise properly.
			carousel.overlay.style.opacity = 1;
			carousel.overlay.style.display = 'block';

			initCarouselSlides( gallery.querySelectorAll( settings.imgSelector ), settings.startIndex );

			swiper = new window.Swiper670( '.jp-carousel-swiper-container', {
				centeredSlides: true,
				zoom: true,
				loop: carousel.slides.length > 1,
				// Turn off interactions and hide navigation arrows if there is only one slide.
				enabled: carousel.slides.length > 1,
				pagination: {
					el: '.jp-swiper-pagination',
					clickable: true,
				},
				navigation: {
					nextEl: '.jp-swiper-button-next',
					prevEl: '.jp-swiper-button-prev',
				},
				initialSlide: settings.startIndex,
				on: {
					init: function () {
						selectSlideAtIndex( settings.startIndex );
					},
				},
				preventClicks: false,
				preventClicksPropagation: false,
				preventInteractionOnTransition: ! domUtil.isTouch(),
				threshold: 5,
			} );

			swiper.on( 'slideChange', function ( swiper ) {
				var index;
				// Swiper indexes slides from 1, plus when looping to left last slide ends up
				// as 0 and looping to right first slide as total slides + 1. These are adjusted
				// here to match index of carousel.slides.
				if ( swiper.activeIndex === 0 ) {
					index = carousel.slides.length - 1;
				} else if ( swiper.activeIndex === carousel.slides.length + 1 ) {
					index = 0;
				} else {
					index = swiper.activeIndex - 1;
				}
				selectSlideAtIndex( index );

				carousel.overlay.classList.remove( 'jp-carousel-hide-controls' );
			} );

			swiper.on( 'zoomChange', function ( swiper, scale ) {
				if ( scale > 1 ) {
					carousel.overlay.classList.add( 'jp-carousel-hide-controls' );
				}

				if ( scale === 1 ) {
					carousel.overlay.classList.remove( 'jp-carousel-hide-controls' );
				}
			} );

			swiper.on( 'doubleTap', function ( swiper ) {
				clearTimeout( tapTimeout );
				if ( swiper.zoom.scale === 1 ) {
					var zoomTimeout = setTimeout( function () {
						carousel.overlay.classList.remove( 'jp-carousel-hide-controls' );
						clearTimeout( zoomTimeout );
					}, 150 );
				}
			} );

			swiper.on( 'tap', function () {
				if ( swiper.zoom.scale > 1 ) {
					tapTimeout = setTimeout( function () {
						carousel.overlay.classList.toggle( 'jp-carousel-hide-controls' );
					}, 150 );
				}
			} );

			domUtil.fadeIn( carousel.overlay, function () {
				domUtil.emitEvent( carousel.overlay, 'jp_carousel.afterOpen' );
			} );
		}

		// Register the event listener for starting the gallery
		document.body.addEventListener( 'click', function ( e ) {
			var isCompatible =
				window.CSS && window.CSS.supports && window.CSS.supports( 'display', 'grid' );

			// IE11 support is being dropped in August 2021. The new swiper.js libray is not IE11 compat
			// so just default to opening individual image attachment/media pages for IE.
			if ( ! isCompatible ) {
				return;
			}

			var target = e.target;
			var gallery = domUtil.closest( target, gallerySelector );

			if ( gallery ) {
				if ( ! testForData( gallery ) ) {
					return;
				}

				var parent = target.parentElement;
				var grandparent = parent.parentElement;

				// If Gallery is made up of individual Image blocks check for custom link before
				// loading carousel. The custom link may be the parent or could be a descendant
				// of the parent if the image has rounded corners.
				var parentHref = null;
				if ( grandparent && grandparent.classList.contains( 'wp-block-image' ) ) {
					parentHref = parent.getAttribute( 'href' );
				} else if (
					parent &&
					parent.classList.contains( 'wp-block-image' ) &&
					parent.querySelector( ':scope > a' )
				) {
					parentHref = parent.querySelector( ':scope > a' ).getAttribute( 'href' );
				}

				// If the link does not point to the attachment or media file then assume Image has
				// a custom link so don't load the carousel.
				if (
					parentHref &&
					parentHref.split( '?' )[ 0 ] !==
						target.getAttribute( 'data-orig-file' ).split( '?' )[ 0 ] &&
					parentHref !== target.getAttribute( 'data-permalink' )
				) {
					return;
				}

				// Do not open the modal if we are looking at a gallery caption from before WP5, which may contain a link.
				if ( parent.classList.contains( 'gallery-caption' ) ) {
					return;
				}

				// Do not open the modal if we are looking at a caption of a gallery block, which may contain a link.
				if ( domUtil.matches( parent, 'figcaption' ) ) {
					return;
				}

				// Set height to auto.
				// Fix some themes where closing carousel brings view back to top.
				document.documentElement.style.height = 'auto';

				e.preventDefault();

				// Stopping propagation in case there are parent elements
				// with .gallery or .tiled-gallery class
				e.stopPropagation();

				var item = domUtil.closest( target, itemSelector );
				var index = Array.prototype.indexOf.call( gallery.querySelectorAll( itemSelector ), item );
				loadSwiper( gallery, { startIndex: index } );
			}
		} );

		// Handle lightbox (single image gallery) for images linking to 'Attachment Page'.
		if ( Number( jetpackCarouselStrings.single_image_gallery ) === 1 ) {
			processSingleImageGallery();
			document.body.addEventListener( 'is.post-load', function () {
				processSingleImageGallery();
			} );
		}

		// Makes carousel work on page load and when back button leads to same URL with carousel hash
		// (i.e. no actual document.ready trigger).
		window.addEventListener( 'hashchange', function () {
			var hashRegExp = /jp-carousel-(\d+)/;

			if ( ! window.location.hash || ! hashRegExp.test( window.location.hash ) ) {
				if ( carousel.isOpen ) {
					closeCarousel();
				}

				return;
			}

			if ( window.location.hash === lastKnownLocationHash && carousel.isOpen ) {
				return;
			}

			if ( window.location.hash && carousel.gallery && ! carousel.isOpen && history.back ) {
				history.back();
				return;
			}

			lastKnownLocationHash = window.location.hash;
			var matchList = window.location.hash.match( hashRegExp );
			var attachmentId = parseInt( matchList[ 1 ], 10 );
			var galleries = document.querySelectorAll( gallerySelector );

			// Find the first thumbnail that matches the attachment ID in the location
			// hash, then open the gallery that contains it.
			for ( var i = 0; i < galleries.length; i++ ) {
				var gallery = galleries[ i ];
				var selected;

				var images = gallery.querySelectorAll( 'img' );
				for ( var j = 0; j < images.length; j++ ) {
					if (
						parseInt( images[ j ].getAttribute( 'data-attachment-id' ), 10 ) === attachmentId ||
						parseInt( images[ j ].getAttribute( 'data-id' ), 10 ) === attachmentId
					) {
						selected = j;
						break;
					}
				}

				if ( selected !== undefined ) {
					openOrSelectSlide( gallery, selected );
					break;
				}
			}
		} );

		if ( window.location.hash ) {
			domUtil.emitEvent( window, 'hashchange' );
		}
	}

	if ( document.readyState !== 'loading' ) {
		init();
	} else {
		document.addEventListener( 'DOMContentLoaded', init );
	}
} )();
