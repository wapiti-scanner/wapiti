<?php
/**
 * Functions and template tags for Site Logo theme tool.
 *
 * @package automattic/jetpack
 */

/**
 * Retrieve the site logo URL or ID (URL by default). Pass in the string 'id' for ID.
 *
 * @uses get_option()
 * @uses esc_url_raw()
 * @uses set_url_scheme()
 * @param string $show 'url' or 'id' for site logo.
 * @return mixed The URL or ID of our site logo, false if not set
 * @since 1.0
 */
function jetpack_get_site_logo( $show = 'url' ) {
	$logo_id = site_logo()->logo;

	// Return false if no logo is set
	if ( ! $logo_id ) {
		return false;
	}

	// Return the ID if specified, otherwise return the URL by default
	if ( 'id' === $show ) {
		return $logo_id;
	} else {
		$logo_url = wp_get_attachment_url( $logo_id );
		return esc_url_raw( set_url_scheme( $logo_url ) );
	}
}

/**
 * Retrieve an array of the dimensions of the Site Logo.
 *
 * @uses Site_Logo::theme_size()
 * @uses get_option( 'thumbnail_size_w' )
 * @uses get_option( 'thumbnail_size_h' )
 * @uses global $_wp_additional_image_sizes;
 *
 * @since 3.6.0
 *
 * @return array $dimensions {
 *      An array of dimensions of the Site Logo.
 *
 *      @type string $width Width of the logo in pixels.
 *      @type string $height Height of the logo in pixels.
 * }
 */
function jetpack_get_site_logo_dimensions() {
	// Get the image size to use with the logo.
	$size = site_logo()->theme_size();

	// If the size is the default `thumbnail`, get its dimensions. Otherwise, get them from $_wp_additional_image_sizes
	if ( empty( $size ) ) {
		return false;
	} elseif ( 'thumbnail' === $size ) {
		$dimensions = array(
			'width'  => get_option( 'thumbnail_size_w' ),
			'height' => get_option( 'thumbnail_size_h' ),
		);
	} else {
		global $_wp_additional_image_sizes;

		if ( ! isset( $_wp_additional_image_sizes[ $size ] ) ) {
			return false;
		}

		$dimensions = array(
			'width'  => $_wp_additional_image_sizes[ $size ]['width'],
			'height' => $_wp_additional_image_sizes[ $size ]['height'],
		);
	}

	return $dimensions;
}

/**
 * Determine if a site logo is assigned or not.
 *
 * @uses get_option
 * @return boolean True if there is an active logo, false otherwise
 */
function jetpack_has_site_logo() {
	return site_logo()->has_site_logo();
}

/**
 * Output an <img> tag of the site logo, at the size specified
 * in the theme's add_theme_support() declaration.
 *
 * @uses Site_Logo::logo
 * @uses Site_Logo::theme_size()
 * @uses jetpack_has_site_logo()
 * @uses jetpack_is_customize_preview()
 * @uses esc_url()
 * @uses home_url()
 * @uses esc_attr()
 * @uses wp_get_attachment_image()
 * @uses apply_filters()
 * @since 1.0
 */
function jetpack_the_site_logo() {
	$size = site_logo()->theme_size();

	// If no logo is set, but we're in the Customizer, leave a placeholder (needed for the live preview).
	if (
		! jetpack_has_site_logo()
		&& jetpack_is_customize_preview()
	) {
		/*
		 * Reason: the output is escaped in the sprintf.
		 * phpcs:disable WordPress.Security.EscapeOutput
		 */
		/** This filter is documented in modules/theme-tools/site-logo/inc/functions.php */
		echo apply_filters(
			'jetpack_the_site_logo',
			sprintf(
				'<a href="%1$s" class="site-logo-link" style="display:none;"><img class="site-logo" data-size="%2$s" /></a>',
				esc_url( home_url( '/' ) ),
				esc_attr( $size )
			),
			array(),
			$size
		);
		/* phpcs:enable WordPress.Security.EscapeOutput */
		return;
	}

	// Check for WP 4.5 Site Logo and Jetpack logo.
	$logo_id = get_theme_mod( 'custom_logo' );
	// Get the option directly so the updated logo can be injected into customizer previews.
	$jetpack_logo_id = get_option( 'site_logo' );

	// Use WP Core logo if present and is an id (of an attachment), otherwise use Jetpack's.
	if ( ! is_numeric( $logo_id ) && $jetpack_logo_id ) {
		$logo_id = $jetpack_logo_id;
	}

	/*
	 * Reason: the output is escaped in the sprintf.
	 * phpcs:disable WordPress.Security.EscapeOutput
	 */
	/**
	 * Filter the Site Logo output.
	 *
	 * @module theme-tools
	 *
	 * @since 3.2.0
	 *
	 * @param string $html Site Logo HTML output.
	 * @param array $jetpack_logo Array of Site Logo details.
	 * @param string $size Size specified in add_theme_support declaration, or 'thumbnail' default.
	 */
	echo apply_filters(
		'jetpack_the_site_logo',
		sprintf(
			'<a href="%1$s" class="site-logo-link" rel="home" itemprop="url">%2$s</a>',
			esc_url( home_url( '/' ) ),
			wp_get_attachment_image(
				$logo_id,
				$size,
				false,
				array(
					'class'     => "site-logo attachment-$size",
					'data-size' => $size,
					'itemprop'  => 'logo',
				)
			)
		),
		// Return array format in filter for back compatibility.
		array(
			'id'    => $jetpack_logo_id,
			'url'   => wp_get_attachment_url( $jetpack_logo_id ),
			'sizes' => array(),
		),
		$size
	);
	/* phpcs:enable WordPress.Security.EscapeOutput */
}

/**
 * Whether the site is being previewed in the Customizer.
 * Duplicate of core function until 4.0 is released.
 *
 * @global WP_Customize_Manager $wp_customize Customizer instance.
 * @return bool True if the site is being previewed in the Customizer, false otherwise.
 */
function jetpack_is_customize_preview() {
	global $wp_customize;

	return is_a( $wp_customize, 'WP_Customize_Manager' ) && $wp_customize->is_preview();
}

/**
 * Sanitize the string of classes used for header text.
 * Limit to A-Z,a-z,0-9,(space),(comma),_,-
 *
 * @param string $classes Unsanitized string of CSS classes.
 * @return string Sanitized string of CSS classes.
 */
function jetpack_sanitize_header_text_classes( $classes ) {
	$classes = preg_replace( '/[^A-Za-z0-9\,\ ._-]/', '', $classes );

	return $classes;
}
