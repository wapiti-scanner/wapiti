<?php
/**
 * Theme Tools: the functions to display Content or Excerpt in a theme.
 *
 * @package automattic/jetpack
 */

/**
 * If the theme doesn't support 'jetpack-content-options', don't continue.
 */
if ( ! current_theme_supports( 'jetpack-content-options' ) ) {
	return;
}

/**
 * Get the Blog Display setting.
 * If theme is using both 'Content' and 'Excerpt' then this setting will be called 'Mixed'.
 */
$options      = get_theme_support( 'jetpack-content-options' );
$blog_display = ( ! empty( $options[0]['blog-display'] ) ) ? $options[0]['blog-display'] : null;
$blog_display = preg_grep( '/^(content|excerpt)$/', (array) $blog_display );
sort( $blog_display );
$blog_display = implode( ', ', $blog_display );
$blog_display = ( 'content, excerpt' === $blog_display ) ? 'mixed' : $blog_display;

/**
 * If the theme doesn't support 'jetpack-content-options[ 'blog-display' ]', don't continue.
 */
if ( ! in_array( $blog_display, array( 'content', 'excerpt', 'mixed' ), true ) ) {
	return;
}

/**
 * Apply Content filters.
 *
 * @since 9.7.0 Deprecated $content parameter.
 *
 * @param string $content Post content. Deprecated.
 */
function jetpack_blog_display_custom_excerpt( $content = '' ) {
	if ( ! empty( $content ) ) {
		_doing_it_wrong(
			'jetpack_blog_display_custom_excerpt',
			esc_html__( 'You do not need to pass a $content parameter anymore.', 'jetpack' ),
			'jetpack-9.7.0'
		);
	}

	$post = get_post();
	if ( empty( $post ) ) {
		return '';
	}

	if ( empty( $post->post_excerpt ) ) {
		$text = strip_shortcodes( $post->post_content );
		$text = str_replace( ']]>', ']]&gt;', $text );
		$text = wp_strip_all_tags( $text );
		/** This filter is documented in wp-includes/formatting.php */
		$excerpt_length = apply_filters( 'excerpt_length', 55 );
		/** This filter is documented in wp-includes/formatting.php */
		$excerpt_more = apply_filters( 'excerpt_more', ' [...]' );

		/*
		 * translators: If your word count is based on single characters (e.g. East Asian characters),
		 * enter 'characters_excluding_spaces' or 'characters_including_spaces'. Otherwise, enter 'words'.
		 * Do not translate into your own language.
		 */
		if ( strpos( _x( 'words', 'Word count type. Do not translate!', 'jetpack' ), 'characters' ) === 0 && preg_match( '/^utf\-?8$/i', get_option( 'blog_charset' ) ) ) {
			$text = trim( preg_replace( "/[\n\r\t ]+/", ' ', $text ), ' ' );
			preg_match_all( '/./u', $text, $words );
			$words = array_slice( $words[0], 0, $excerpt_length + 1 );
			$sep   = '';
		} else {
			$words = preg_split( "/[\n\r\t ]+/", $text, $excerpt_length + 1, PREG_SPLIT_NO_EMPTY );
			$sep   = ' ';
		}

		if ( count( $words ) > $excerpt_length ) {
			array_pop( $words );
			$text = implode( $sep, $words );
			$text = $text . $excerpt_more;
		} else {
			$text = implode( $sep, $words );
		}
	} else {
		$text = wp_kses_post( $post->post_excerpt );
	}
	return sprintf( '<p>%s</p>', $text );
}

/**
 * Display Excerpt instead of Content.
 *
 * @param string $content Post content.
 */
function jetpack_the_content_to_the_excerpt( $content ) {
	if ( ( is_home() || is_archive() ) && ! is_post_type_archive( array( 'jetpack-testimonial', 'jetpack-portfolio', 'product' ) ) ) {
		if ( post_password_required() ) {
			$excerpt = sprintf( '<p>%s</p>', esc_html__( 'There is no excerpt because this is a protected post.', 'jetpack' ) );
		} else {
			$excerpt = jetpack_blog_display_custom_excerpt();
		}
	}
	if ( empty( $excerpt ) ) {
		return $content;
	} else {
		return $excerpt;
	}
}

/**
 * Display Content instead of Excerpt.
 *
 * @param string $content The post excerpt.
 */
function jetpack_the_excerpt_to_the_content( $content ) {
	if ( ( is_home() || is_archive() ) && ! is_post_type_archive( array( 'jetpack-testimonial', 'jetpack-portfolio', 'product' ) ) ) {
		ob_start();
		the_content(
			sprintf(
				wp_kses(
					/* translators: %s: Name of current post. Only visible to screen readers */
					__( 'Continue reading<span class="screen-reader-text"> "%s"</span>', 'jetpack' ),
					array(
						'span' => array(
							'class' => array(),
						),
					)
				),
				get_the_title()
			)
		);
		$content = ob_get_clean();
	}
	return $content;
}

/**
 * Display both Content and Excerpt instead of Content in the Customizer so live preview can switch between them.
 *
 * @param string $content The post content.
 */
function jetpack_the_content_customizer( $content ) {
	$class = jetpack_the_content_customizer_class();
	if ( ( is_home() || is_archive() ) && ! is_post_type_archive( array( 'jetpack-testimonial', 'jetpack-portfolio', 'product' ) ) ) {
		if ( post_password_required() ) {
			$excerpt = sprintf( '<p>%s</p>', esc_html__( 'There is no excerpt because this is a protected post.', 'jetpack' ) );
		} else {
			$excerpt = jetpack_blog_display_custom_excerpt();
		}
	}
	if ( empty( $excerpt ) ) {
		return $content;
	} else {
		return sprintf( '<div class="jetpack-blog-display %s jetpack-the-content">%s</div><div class="jetpack-blog-display %s jetpack-the-excerpt">%s</div>', $class, $content, $class, $excerpt );
	}
}

/**
 * Display both Content and Excerpt instead of Excerpt in the Customizer so live preview can switch between them.
 *
 * @param string $excerpt The post excerpt.
 */
function jetpack_the_excerpt_customizer( $excerpt ) {
	if ( ( is_home() || is_archive() ) && ! is_post_type_archive( array( 'jetpack-testimonial', 'jetpack-portfolio', 'product' ) ) ) {
		ob_start();
		the_content(
			sprintf(
				wp_kses(
					/* translators: %s: Name of current post. Only visible to screen readers */
					__( 'Continue reading<span class="screen-reader-text"> "%s"</span>', 'jetpack' ),
					array(
						'span' => array(
							'class' => array(),
						),
					)
				),
				get_the_title()
			)
		);
		$content = ob_get_clean();
	}
	if ( empty( $content ) ) {
		return $excerpt;
	} else {
		return sprintf( '<div class="jetpack-blog-display jetpack-the-content">%s</div><div class="jetpack-blog-display jetpack-the-excerpt">%s</div>', $content, $excerpt );
	}
}

/**
 * Display Content instead of Excerpt in the Customizer when theme uses a 'Mixed' display.
 *
 * @param string $content The post excerpt.
 */
function jetpack_the_excerpt_mixed_customizer( $content ) {
	if ( ( is_home() || is_archive() ) && ! is_post_type_archive( array( 'jetpack-testimonial', 'jetpack-portfolio', 'product' ) ) ) {
		jetpack_the_content_customizer_class( 'output-the-excerpt' );
		ob_start();
		the_content();
		$content = ob_get_clean();
	}
	return $content;
}

/**
 * Returns a class value, `output-the-content` by default.
 * Used for themes with a 'Mixed' Blog Display so we can tell which output is by default.
 *
 * @param string|null $new_class CSS class added to content container.
 */
function jetpack_the_content_customizer_class( $new_class = null ) {
	static $class;
	if ( isset( $new_class ) ) {
		// Assign a new class and return.
		$class = $new_class;
	} elseif ( isset( $class ) ) {
		// Reset the class after getting value.
		$prev_class = $class;
		$class      = null;
		return $prev_class;
	} else {
		// Return default class value.
		return 'output-the-content';
	}
}

if ( is_customize_preview() ) {
	/*
	 * Display Content and Excerpt if the default Blog Display is 'Content'
	 * and we are in the Customizer.
	 */
	if ( 'content' === $blog_display ) {
		add_filter( 'the_content', 'jetpack_the_content_customizer' );
	}

	/*
	 * Display Content and Excerpt if the default Blog Display is 'Excerpt'
	 * and we are in the Customizer.
	 */
	if ( 'excerpt' === $blog_display ) {
		add_filter( 'the_excerpt', 'jetpack_the_excerpt_customizer' );
	}

	/*
	 * Display Content and Excerpt if the default Blog Display is 'Mixed'
	 * and we are in the Customizer.
	 */
	if ( 'mixed' === $blog_display ) {
		add_filter( 'the_content', 'jetpack_the_content_customizer' );
		add_filter( 'the_excerpt', 'jetpack_the_excerpt_mixed_customizer' );
	}
} else {
	$display_option = get_option( 'jetpack_content_blog_display', $blog_display );

	/*
	 * Display Excerpt if the default Blog Display is 'Content'
	 * or default Blog Display is 'Mixed'
	 * and the Option picked is 'Post Excerpt'
	 * and we aren't in the Customizer.
	 */
	if ( ( 'content' === $blog_display || 'mixed' === $blog_display ) && 'excerpt' === $display_option ) {
		add_filter( 'the_content', 'jetpack_the_content_to_the_excerpt' );
	}

	/*
	 * Display Content if the default Blog Display is 'Excerpt'
	 * or default Blog Display is 'Mixed'
	 * and the Option picked is 'Full Post'
	 * and we aren't in the Customizer.
	 */
	if ( ( 'excerpt' === $blog_display || 'mixed' === $blog_display ) && 'content' === $display_option ) {
		add_filter( 'the_excerpt', 'jetpack_the_excerpt_to_the_content' );
	}
}
