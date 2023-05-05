<?php
/**
 * Jetpack Compatibility File
 * See: https://jetpack.com/
 *
 * @package automattic/jetpack
 */

/**
 * A last try to show posts, in case the Featured Content plugin returns no IDs.
 *
 * @param array $featured_ids Array of 'featured' post IDs.
 * @return array
 */
function twentyfourteen_featured_content_post_ids( $featured_ids ) {
	if ( empty( $featured_ids ) ) {
		$featured_ids = array_slice( get_option( 'sticky_posts', array() ), 0, 6 );
	}

	return $featured_ids;
}
add_action( 'featured_content_post_ids', 'twentyfourteen_featured_content_post_ids' );

/**
 * Set the default tag name for Featured Content.
 *
 * @param WP_Customize_Manager $wp_customize Theme Customizer object.
 * @return void
 */
function twentyfourteen_customizer_default( $wp_customize ) {
	$wp_customize->get_setting( 'featured-content[tag-name]' )->default = 'featured';
}
add_action( 'customize_register', 'twentyfourteen_customizer_default' );

/**
 * Sets a default tag of 'featured' for Featured Content.
 *
 * @param array $settings Featured content settings.
 * @return array
 */
function twentyfourteen_featured_content_default_settings( $settings ) {
	$settings['tag-name'] = 'featured';

	return $settings;
}
add_action( 'featured_content_default_settings', 'twentyfourteen_featured_content_default_settings' );

/**
 * Removes sharing markup from post content if we're not in the loop and it's a
 * formatted post.
 *
 * @param bool    $show Whether to show sharing options.
 * @param WP_Post $post The post to share.
 * @return bool
 */
function twentyfourteen_mute_content_filters( $show, $post ) {
	$formats = get_theme_support( 'post-formats' );
	if ( ! in_the_loop() && has_post_format( $formats[0], $post ) ) {
		$show = false;
	}
	return $show;
}
add_filter( 'sharing_show', 'twentyfourteen_mute_content_filters', 10, 2 );

/**
 * Enqueue Jetpack compat styles for Twenty Fourteen.
 */
function twentyfourteen_init_jetpack() {
	/**
	 * Add our compat CSS file for custom widget stylings and such.
	 * Set the version equal to filemtime for development builds, and the JETPACK__VERSION for production.
	 */
	if ( ! is_admin() ) {
		$version = false;
		if ( method_exists( 'Jetpack', 'is_development_version' ) ) {
			$version = Jetpack::is_development_version() ? filemtime( plugin_dir_path( __FILE__ ) . 'twentyfourteen.css' ) : JETPACK__VERSION;
		}
		wp_enqueue_style( 'twentyfourteen-jetpack', plugins_url( 'twentyfourteen.css', __FILE__ ), array(), $version );
		wp_style_add_data( 'twentyfourteen-jetpack', 'rtl', 'replace' );
	}
}
add_action( 'init', 'twentyfourteen_init_jetpack' );
