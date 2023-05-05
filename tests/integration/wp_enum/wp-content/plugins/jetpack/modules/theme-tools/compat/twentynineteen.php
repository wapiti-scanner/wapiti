<?php
/**
 * Jetpack Compatibility File
 * See: https://jetpack.com/
 *
 * @package automattic/jetpack
 */

/**
 * Add Jetpack theme supports for Twenty Nineteen.
 */
function twentynineteen_jetpack_setup() {

	/**
	 * Add theme support for Infinite Scroll.
	 */
	add_theme_support(
		'infinite-scroll',
		array(
			'type'      => 'click',
			'container' => 'main',
			'render'    => 'twentynineteen_infinite_scroll_render',
			'footer'    => 'page',
		)
	);

	/**
	 * Add theme support for Responsive Videos.
	 */
	add_theme_support( 'jetpack-responsive-videos' );

	/**
	 * Add theme support for geo-location.
	 */
	add_theme_support( 'jetpack-geo-location' );

	/**
	 * Add theme support for Content Options.
	 */
	add_theme_support(
		'jetpack-content-options',
		array(
			'blog-display'    => array( 'content', 'excerpt' ),
			'post-details'    => array(
				'stylesheet' => 'twentynineteen-style',
				'date'       => '.posted-on',
				'categories' => '.cat-links',
				'tags'       => '.tags-links',
				'author'     => '.byline',
				'comment'    => '.comments-link',
			),
			'featured-images' => array(
				'archive' => true,
				'post'    => true,
				'page'    => true,
			),
		)
	);
}
add_action( 'after_setup_theme', 'twentynineteen_jetpack_setup' );

/**
 * Custom render function for Infinite Scroll.
 */
function twentynineteen_infinite_scroll_render() {
	while ( have_posts() ) {
		the_post();
		get_template_part( 'template-parts/content/content' );
	}
}

/**
 * Enqueue Jetpack compat styles for Twenty Nineteen.
 */
function twentynineteen_init_jetpack() {
	/**
	 * Add our compat CSS file for Infinite Scroll and custom widget stylings and such.
	 * Set the version equal to filemtime for development builds, and the JETPACK__VERSION for production
	 * or skip it entirely for wpcom.
	 */
	if ( ! is_admin() ) {
		$version = false;
		if ( method_exists( 'Jetpack', 'is_development_version' ) ) {
			$version = Jetpack::is_development_version() ? filemtime( plugin_dir_path( __FILE__ ) . 'twentynineteen.css' ) : JETPACK__VERSION;
		}
		wp_enqueue_style( 'twentynineteen-jetpack', plugins_url( 'twentynineteen.css', __FILE__ ), array(), $version );
		wp_style_add_data( 'twentynineteen-jetpack', 'rtl', 'replace' );
	}
}
add_action( 'init', 'twentynineteen_init_jetpack' );

/**
 * Alter gallery widget default width.
 */
function twentynineteen_gallery_widget_content_width() {
	return 390;
}
add_filter( 'gallery_widget_content_width', 'twentynineteen_gallery_widget_content_width' );

/**
 * Alter featured-image default visibility for content-options.
 */
function twentynineteen_override_post_thumbnail() {
	$options         = get_theme_support( 'jetpack-content-options' );
	$featured_images = ( ! empty( $options[0]['featured-images'] ) ) ? $options[0]['featured-images'] : null;

	$settings = array(
		'post-default' => ( isset( $featured_images['post-default'] ) && false === $featured_images['post-default'] ) ? '' : 1,
		'page-default' => ( isset( $featured_images['page-default'] ) && false === $featured_images['page-default'] ) ? '' : 1,
	);

	$settings = array_merge(
		$settings,
		array(
			'post-option' => get_option( 'jetpack_content_featured_images_post', $settings['post-default'] ),
			'page-option' => get_option( 'jetpack_content_featured_images_page', $settings['page-default'] ),
		)
	);

	if ( ( ! $settings['post-option'] && is_single() )
	|| ( ! $settings['page-option'] && is_singular() && is_page() ) ) {
		return false;
	} else {
		return ! post_password_required() && ! is_attachment() && has_post_thumbnail();
	}
}
add_filter( 'twentynineteen_can_show_post_thumbnail', 'twentynineteen_override_post_thumbnail', 10, 2 );

/**
 * Adds custom classes to the array of body classes.
 *
 * @param array $classes Classes for the body element.
 * @return array
 */
function twentynineteen_jetpack_body_classes( $classes ) {
	// Adds a class if we're in the Customizer.
	if ( is_customize_preview() ) :
		$classes[] = 'twentynineteen-customizer';
	endif;

	return $classes;
}
add_filter( 'body_class', 'twentynineteen_jetpack_body_classes' );

/**
 * Load AMP theme specific hooks for infinite scroll.
 *
 * @return void
 */
function amp_twentynineteen_infinite_scroll_render_hooks() {
	add_filter( 'jetpack_amp_infinite_footers', 'twentynineteen_amp_infinite_footers', 10, 2 );
	add_filter( 'jetpack_amp_infinite_output', 'twentynineteen_amp_infinite_output' );
	add_filter( 'jetpack_amp_infinite_older_posts', 'twentynineteen_amp_infinite_older_posts' );
}

/**
 * Get the theme specific footers.
 *
 * @param array  $footers The footers of the themes.
 * @param string $buffer  Contents of the output buffer.
 *
 * @return mixed
 */
function twentynineteen_amp_infinite_footers( $footers, $buffer ) {
	// Collect the footer wrapper.
	preg_match(
		'/<footer id="colophon".*<!-- #colophon -->/s',
		$buffer,
		$footer
	);
	$footers[] = reset( $footer );

	return $footers;
}

/**
 * Hide and remove various elements from next page load.
 *
 * @param string $buffer Contents of the output buffer.
 *
 * @return string
 */
function twentynineteen_amp_infinite_output( $buffer ) {
	// Hide site header on next page load.
	$buffer = preg_replace(
		'/id="masthead"/',
		'$0 next-page-hide',
		$buffer
	);

	// Hide pagination on next page load.
	$buffer = preg_replace(
		'/class=".*navigation pagination.*"/',
		'$0 next-page-hide hidden',
		$buffer
	);

	// Remove the footer as it will be added back to amp next page footer.
	$buffer = preg_replace(
		'/<footer id="colophon".*<!-- #colophon -->/s',
		'',
		$buffer
	);

	return $buffer;
}

/**
 * Filter the AMP infinite scroll older posts button
 *
 * @return string
 */
function twentynineteen_amp_infinite_older_posts() {
	ob_start();
	?>
<div id="infinite-handle" style="text-align: center;">
	<span>
		<a href="{{url}}">
			<button>
				<?php esc_html_e( 'Older posts', 'jetpack' ); ?>
			</button>
		</a>
	</span>
</div>
	<?php
	return ob_get_clean();
}
