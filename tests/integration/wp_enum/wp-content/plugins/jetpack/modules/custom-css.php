<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Module Name: Custom CSS
 * Module Description: Adds options for CSS preprocessor use, disabling the theme's CSS, or custom image width.
 * Sort Order: 2
 * First Introduced: 1.7
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Appearance
 * Feature: Appearance
 * Additional Search Queries: css, customize, custom, style, editor, less, sass, preprocessor, font, mobile, appearance, theme, stylesheet
 */

/**
 * Load custom CSS
 */
function jetpack_load_custom_css() {
		include_once __DIR__ . '/custom-css/custom-css/preprocessors.php';
		include_once __DIR__ . '/custom-css/custom-css.php';
}

add_action( 'jetpack_modules_loaded', 'custom_css_loaded' );

/**
 * Enable CSS module.
 */
function custom_css_loaded() {
	Jetpack::enable_module_configurable( __FILE__ );
	add_filter( 'jetpack_module_configuration_url_custom-css', 'jetpack_custom_css_configuration_url' );
}

/**
 * Overrides default configuration url
 *
 * @uses admin_url
 *
 * @param string $default_url - the default URL.
 * @return string module settings URL
 */
function jetpack_custom_css_configuration_url( $default_url ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
	return Jetpack_Custom_CSS_Enhancements::customizer_link(
		array( 'return_url' => wp_get_referer() )
	);
}

jetpack_load_custom_css();
