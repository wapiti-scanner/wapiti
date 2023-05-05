/* global blogDisplay, postDetails */

/**
 * customizer.js
 *
 * Theme Customizer enhancements for a better user experience.
 *
 * Contains handlers to make Theme Customizer preview reload changes asynchronously.
 */

( function ( $ ) {
	// Blog Display
	wp.customize( 'jetpack_content_blog_display', function ( value ) {
		if ( 'content' === blogDisplay.display ) {
			$( '.jetpack-blog-display.jetpack-the-excerpt' ).css( {
				clip: 'rect(1px, 1px, 1px, 1px)',
				position: 'absolute',
			} );
			$( '.jetpack-blog-display.jetpack-the-content' ).css( {
				clip: 'auto',
				position: 'relative',
			} );
		} else if ( 'excerpt' === blogDisplay.display ) {
			$( '.jetpack-blog-display.jetpack-the-content' ).css( {
				clip: 'rect(1px, 1px, 1px, 1px)',
				position: 'absolute',
			} );
			$( '.jetpack-blog-display.jetpack-the-excerpt' ).css( {
				clip: 'auto',
				position: 'relative',
			} );
		} else if ( 'mixed' === blogDisplay.display ) {
			$( '.jetpack-blog-display.jetpack-the-content.output-the-content' ).css( {
				clip: 'auto',
				position: 'relative',
			} );
			$( '.jetpack-blog-display.jetpack-the-excerpt.output-the-content' ).css( {
				clip: 'rect(1px, 1px, 1px, 1px)',
				position: 'absolute',
			} );
			$( '.jetpack-blog-display.jetpack-the-content.output-the-excerpt' ).css( {
				clip: 'rect(1px, 1px, 1px, 1px)',
				position: 'absolute',
			} );
			$( '.jetpack-blog-display.jetpack-the-excerpt.output-the-excerpt' ).css( {
				clip: 'auto',
				position: 'relative',
			} );
		}
		value.bind( function ( to ) {
			if ( 'content' === to ) {
				$( '.jetpack-blog-display.jetpack-the-excerpt' ).css( {
					clip: 'rect(1px, 1px, 1px, 1px)',
					position: 'absolute',
				} );
				$( '.jetpack-blog-display.jetpack-the-content' ).css( {
					clip: 'auto',
					position: 'relative',
				} );
			} else if ( 'excerpt' === to ) {
				$( '.jetpack-blog-display.jetpack-the-content' ).css( {
					clip: 'rect(1px, 1px, 1px, 1px)',
					position: 'absolute',
				} );
				$( '.jetpack-blog-display.jetpack-the-excerpt' ).css( {
					clip: 'auto',
					position: 'relative',
				} );
			} else if ( 'mixed' === to ) {
				$( '.jetpack-blog-display.jetpack-the-content.output-the-content' ).css( {
					clip: 'auto',
					position: 'relative',
				} );
				$( '.jetpack-blog-display.jetpack-the-excerpt.output-the-content' ).css( {
					clip: 'rect(1px, 1px, 1px, 1px)',
					position: 'absolute',
				} );
				$( '.jetpack-blog-display.jetpack-the-content.output-the-excerpt' ).css( {
					clip: 'rect(1px, 1px, 1px, 1px)',
					position: 'absolute',
				} );
				$( '.jetpack-blog-display.jetpack-the-excerpt.output-the-excerpt' ).css( {
					clip: 'auto',
					position: 'relative',
				} );
			}
			if ( blogDisplay.masonry ) {
				$( blogDisplay.masonry ).masonry();
			}
		} );
	} );

	// Post Details: Date.
	wp.customize( 'jetpack_content_post_details_date', function ( value ) {
		value.bind( function ( to ) {
			if ( false === to ) {
				$( postDetails.date ).css( {
					clip: 'rect(1px, 1px, 1px, 1px)',
					height: '1px',
					overflow: 'hidden',
					position: 'absolute',
					width: '1px',
				} );
				$( 'body' ).addClass( 'date-hidden' );
			} else {
				$( postDetails.date ).css( {
					clip: 'auto',
					height: 'auto',
					overflow: 'auto',
					position: 'relative',
					width: 'auto',
				} );
				$( 'body' ).removeClass( 'date-hidden' );
			}
		} );
	} );

	// Post Details: Categories.
	wp.customize( 'jetpack_content_post_details_categories', function ( value ) {
		value.bind( function ( to ) {
			if ( false === to ) {
				$( postDetails.categories ).css( {
					clip: 'rect(1px, 1px, 1px, 1px)',
					height: '1px',
					overflow: 'hidden',
					position: 'absolute',
					width: '1px',
				} );
				$( 'body' ).addClass( 'categories-hidden' );
			} else {
				$( postDetails.categories ).css( {
					clip: 'auto',
					height: 'auto',
					overflow: 'auto',
					position: 'relative',
					width: 'auto',
				} );
				$( 'body' ).removeClass( 'categories-hidden' );
			}
		} );
	} );

	// Post Details: Tags.
	wp.customize( 'jetpack_content_post_details_tags', function ( value ) {
		value.bind( function ( to ) {
			if ( false === to ) {
				$( postDetails.tags ).css( {
					clip: 'rect(1px, 1px, 1px, 1px)',
					height: '1px',
					overflow: 'hidden',
					position: 'absolute',
					width: '1px',
				} );
				$( 'body' ).addClass( 'tags-hidden' );
			} else {
				$( postDetails.tags ).css( {
					clip: 'auto',
					height: 'auto',
					overflow: 'auto',
					position: 'relative',
					width: 'auto',
				} );
				$( 'body' ).removeClass( 'tags-hidden' );
			}
		} );
	} );

	// Post Details: Author.
	wp.customize( 'jetpack_content_post_details_author', function ( value ) {
		value.bind( function ( to ) {
			if ( false === to ) {
				$( postDetails.author ).css( {
					clip: 'rect(1px, 1px, 1px, 1px)',
					height: '1px',
					overflow: 'hidden',
					position: 'absolute',
					width: '1px',
				} );
				$( 'body' ).addClass( 'author-hidden' );
			} else {
				$( postDetails.author ).css( {
					clip: 'auto',
					height: 'auto',
					overflow: 'auto',
					position: 'relative',
					width: 'auto',
				} );
				$( 'body' ).removeClass( 'author-hidden' );
			}
		} );
	} );

	// Post Details: Comment link.
	wp.customize( 'jetpack_content_post_details_comment', function ( value ) {
		value.bind( function ( to ) {
			if ( false === to ) {
				$( postDetails.comment ).css( {
					clip: 'rect(1px, 1px, 1px, 1px)',
					height: '1px',
					overflow: 'hidden',
					position: 'absolute',
					width: '1px',
				} );
				$( 'body' ).addClass( 'comment-hidden' );
			} else {
				$( postDetails.comment ).css( {
					clip: 'auto',
					height: 'auto',
					overflow: 'auto',
					position: 'relative',
					width: 'auto',
				} );
				$( 'body' ).removeClass( 'comment-hidden' );
			}
		} );
	} );
} )( jQuery );
