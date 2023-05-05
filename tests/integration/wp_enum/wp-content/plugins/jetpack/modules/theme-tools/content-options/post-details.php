<?php
/**
 * Theme Tools: functions for Post Details.
 *
 * @package automattic/jetpack
 */

/**
 * The function to include Post Details in a theme's stylesheet.
 */
function jetpack_post_details_enqueue_scripts() {
	// Make sure we can proceed.
	list( $should_run, $options, $definied, $post_details ) = jetpack_post_details_should_run();

	if ( ! $should_run ) {
		return;
	}

	list( $date_option, $categories_option, $tags_option, $author_option, $comment_option ) = $options;
	list( $date, $categories, $tags, $author, $comment )                                    = $definied;

	$elements = array();

	// If date option is unticked, add it to the list of classes.
	if ( 1 !== (int) $date_option && ! empty( $date ) ) {
		$elements[] = $date;
	}

	// If categories option is unticked, add it to the list of classes.
	if ( 1 !== (int) $categories_option && ! empty( $categories ) ) {
		$elements[] = $categories;
	}

	// If tags option is unticked, add it to the list of classes.
	if ( 1 !== (int) $tags_option && ! empty( $tags ) ) {
		$elements[] = $tags;
	}

	// If author option is unticked, add it to the list of classes.
	if ( 1 !== (int) $author_option && ! empty( $author ) ) {
		$elements[] = $author;
	}

	// If comment option is unticked, add it to the list of classes.
	if ( 1 !== (int) $comment_option && ! empty( $comment ) ) {
		$elements[] = $comment;
	}

	// If the Elements array is empty, return without setting custom CSS.
	if ( empty( $elements ) ) {
		return;
	}

	// Get the list of classes.
	$elements = implode( ', ', $elements );

	// Hide the classes with CSS.
	$css = $elements . ' { clip: rect(1px, 1px, 1px, 1px); height: 1px; position: absolute; overflow: hidden; width: 1px; }';

	// Add the CSS to the stylesheet.
	wp_add_inline_style( $post_details['stylesheet'], $css );
}
add_action( 'wp_enqueue_scripts', 'jetpack_post_details_enqueue_scripts' );

/**
 * Adds custom classes to the array of body classes.
 *
 * @param array $classes Classes for the body element.
 */
function jetpack_post_details_body_classes( $classes ) {
	// Make sure we can proceed.
	list( $should_run, $options, $definied ) = jetpack_post_details_should_run();

	if ( ! $should_run ) {
		return $classes;
	}

	list( $date_option, $categories_option, $tags_option, $author_option, $comment_option ) = $options;
	list( $date, $categories, $tags, $author, $comment )                                    = $definied;

	// If date option is unticked, add a class of 'date-hidden' to the body.
	if ( 1 !== (int) $date_option && ! empty( $date ) ) {
		$classes[] = 'date-hidden';
	}

	// If categories option is unticked, add a class of 'categories-hidden' to the body.
	if ( 1 !== (int) $categories_option && ! empty( $categories ) ) {
		$classes[] = 'categories-hidden';
	}

	// If tags option is unticked, add a class of 'tags-hidden' to the body.
	if ( 1 !== (int) $tags_option && ! empty( $tags ) ) {
		$classes[] = 'tags-hidden';
	}

	// If author option is unticked, add a class of 'author-hidden' to the body.
	if ( 1 !== (int) $author_option && ! empty( $author ) ) {
		$classes[] = 'author-hidden';
	}

	// If comment option is unticked, add a class of 'comment-hidden' to the body.
	if ( 1 !== (int) $comment_option && ! empty( $comment ) ) {
		$classes[] = 'comment-hidden';
	}

	return $classes;
}
add_filter( 'body_class', 'jetpack_post_details_body_classes' );

/**
 * Determines if Post Details should run.
 */
function jetpack_post_details_should_run() {
	// Empty value representing falsy return value.
	$void = array( false, null, null, null );

	// If the theme doesn't support 'jetpack-content-options', don't continue.
	if ( ! current_theme_supports( 'jetpack-content-options' ) ) {
		return $void;
	}

	$options      = get_theme_support( 'jetpack-content-options' );
	$post_details = ( ! empty( $options[0]['post-details'] ) ) ? $options[0]['post-details'] : null;

	// If the theme doesn't support 'jetpack-content-options[ 'post-details' ]', don't continue.
	if ( empty( $post_details ) ) {
		return $void;
	}

	$date       = ( ! empty( $post_details['date'] ) ) ? $post_details['date'] : null;
	$categories = ( ! empty( $post_details['categories'] ) ) ? $post_details['categories'] : null;
	$tags       = ( ! empty( $post_details['tags'] ) ) ? $post_details['tags'] : null;
	$author     = ( ! empty( $post_details['author'] ) ) ? $post_details['author'] : null;
	$comment    = ( ! empty( $post_details['comment'] ) ) ? $post_details['comment'] : null;

	// If there is no stylesheet and there are no date, categories, tags, author or comment declared, don't continue.
	if (
		empty( $post_details['stylesheet'] )
		&& ( empty( $date )
			|| empty( $categories )
			|| empty( $tags )
			|| empty( $author )
			|| empty( $comment ) )
	) {
		return $void;
	}

	$date_option       = Jetpack_Options::get_option_and_ensure_autoload( 'jetpack_content_post_details_date', 1 );
	$categories_option = Jetpack_Options::get_option_and_ensure_autoload( 'jetpack_content_post_details_categories', 1 );
	$tags_option       = Jetpack_Options::get_option_and_ensure_autoload( 'jetpack_content_post_details_tags', 1 );
	$author_option     = Jetpack_Options::get_option_and_ensure_autoload( 'jetpack_content_post_details_author', 1 );
	$comment_option    = Jetpack_Options::get_option_and_ensure_autoload( 'jetpack_content_post_details_comment', 1 );

	$options  = array( $date_option, $categories_option, $tags_option, $author_option, $comment_option );
	$definied = array( $date, $categories, $tags, $author, $comment );

	// If all the options are ticked, don't continue.
	if ( array( 1, 1, 1, 1, 1 ) === $options ) {
		return $void;
	}

	return array( true, $options, $definied, $post_details );
}
