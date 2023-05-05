<?php
/**
 * Jetpack Compatibility File
 * See: https://jetpack.com/
 *
 * @package automattic/jetpack
 */

/**
 * Add Jetpack theme supports for Twenty Sixteen.
 */
function twentysixteen_jetpack_setup() {
	/**
	 * Add theme support for Responsive Videos.
	 */
	add_theme_support( 'jetpack-responsive-videos' );

	/**
	 * Add theme support for geo-location.
	 */
	add_theme_support( 'jetpack-geo-location' );
}
add_action( 'after_setup_theme', 'twentysixteen_jetpack_setup' );

/**
 * Enqueue Jetpack compat styles for Twenty Sixteen.
 */
function twentysixteen_init_jetpack() {
	/**
	 * Add our compat CSS file for custom widget stylings and such.
	 * Set the version equal to filemtime for development builds, and the JETPACK__VERSION for production
	 * or skip it entirely for wpcom.
	 */
	if ( ! is_admin() ) {
		$version = false;
		if ( method_exists( 'Jetpack', 'is_development_version' ) ) {
			$version = Jetpack::is_development_version() ? filemtime( plugin_dir_path( __FILE__ ) . 'twentysixteen.css' ) : JETPACK__VERSION;
		}
		wp_enqueue_style( 'twentysixteen-jetpack', plugins_url( 'twentysixteen.css', __FILE__ ), array(), $version );
		wp_style_add_data( 'twentysixteen-jetpack', 'rtl', 'replace' );
	}
}
add_action( 'init', 'twentysixteen_init_jetpack' );

/**
 * Alter gallery widget default width.
 */
function twentysixteen_gallery_widget_content_width() {
	return 390;
}
add_filter( 'gallery_widget_content_width', 'twentysixteen_gallery_widget_content_width' );

/**
 * Remove ratings from excerpts that are used as intro on blog index, single, and archive pages.
 */
function twentysixteen_remove_share() {
	if ( is_single() || is_archive() || is_home() ) {
		remove_filter( 'the_excerpt', 'sharing_display', 19 );
		if ( class_exists( 'Jetpack_Likes' ) ) {
			remove_filter( 'the_excerpt', array( Jetpack_Likes::init(), 'post_likes' ), 30, 1 );
		}
	}
}
add_action( 'loop_start', 'twentysixteen_remove_share' );

/**
 * Add inline script for lazy load compat in Twenty Sixteen.
 */
function twentysixteen_jetpack_lazy_images_compat() {
	// Since TwentySixteen outdents when window is resized, let's trigger a window resize
	// every time we lazy load an image on the TwentySixteen theme.
	wp_add_inline_script(
		'jetpack-lazy-images',
		"jQuery( document.body ).on( 'jetpack-lazy-loaded-image', function () { jQuery( window ).trigger( 'resize' ); } );"
	);
}

// Priority needs to be 11 here so that we have already enqueued jetpack-lazy-images.
add_action( 'wp_enqueue_scripts', 'twentysixteen_jetpack_lazy_images_compat', 11 );
