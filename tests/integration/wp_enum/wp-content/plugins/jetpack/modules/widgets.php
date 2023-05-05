<?php
/**
 * Module Name: Extra Sidebar Widgets
 * Module Description: Provides additional widgets for use on your site.
 * Sort Order: 4
 * First Introduced: 1.2
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Social, Appearance
 * Feature: Appearance
 * Additional Search Queries: widget, widgets, facebook, gallery, twitter, gravatar, image, rss
 *
 * @package automattic/jetpack
 */

/**
 * Load Jetpack widget files.
 */
function jetpack_load_widgets() {
	$widgets_include = array();

	foreach ( Jetpack::glob_php( __DIR__ . '/widgets' ) as $file ) {
		$widgets_include[] = $file;
	}
	/**
	 * Modify which Jetpack Widgets to register.
	 *
	 * @module widgets
	 *
	 * @since 2.2.1
	 *
	 * @param array $widgets_include An array of widgets to be registered.
	 */
	$widgets_include = apply_filters( 'jetpack_widgets_to_include', $widgets_include );

	foreach ( $widgets_include as $include ) {
		include_once $include;
	}

	include_once __DIR__ . '/widgets/migrate-to-core/image-widget.php';
	include_once __DIR__ . '/widgets/migrate-to-core/gallery-widget.php';
}

add_action( 'jetpack_modules_loaded', 'jetpack_widgets_loaded' );
/**
 * Actions to perform after Jetpack widgets are loaded.
 */
function jetpack_widgets_loaded() {
	Jetpack::enable_module_configurable( __FILE__ );
	add_filter( 'jetpack_module_configuration_url_widgets', 'jetpack_widgets_configuration_url' );
}

/**
 * Overrides default configuration url
 *
 * @uses admin_url
 * @return string module settings URL
 */
function jetpack_widgets_configuration_url() {
	return admin_url( 'customize.php?autofocus[panel]=widgets' );
}

jetpack_load_widgets();

/**
 * Enqueue utilities to work with widgets in Customizer.
 *
 * @since 4.4.0
 */
function jetpack_widgets_customizer_assets_preview() {
	wp_enqueue_script(
		'jetpack-customizer-widget-utils',
		plugins_url( '/widgets/customizer-utils.js', __FILE__ ),
		array( 'jquery', 'customize-base' ),
		JETPACK__VERSION,
		false
	);
}
add_action( 'customize_preview_init', 'jetpack_widgets_customizer_assets_preview' );

/**
 * Enqueue styles to stylize widgets in Customizer.
 *
 * @since 4.4.0
 */
function jetpack_widgets_customizer_assets_controls() {
	wp_enqueue_style(
		'jetpack-customizer-widget-controls',
		plugins_url( '/widgets/customizer-controls.css', __FILE__ ),
		array( 'customize-widgets' ),
		JETPACK__VERSION
	);
}
add_action( 'customize_controls_enqueue_scripts', 'jetpack_widgets_customizer_assets_controls' );

/**
 * Cleanup old Jetpack widgets data.
 */
function jetpack_widgets_remove_old_widgets() {
	$old_widgets = array(
		'googleplus-badge',
	);

	// Don't bother cleaning up the sidebars_widgets data.
	// That will get cleaned up the next time a widget is
	// added, removed, moved, etc.
	foreach ( $old_widgets as $old_widget ) {
		delete_option( "widget_{$old_widget}" );
	}
}

add_action( 'updating_jetpack_version', 'jetpack_widgets_remove_old_widgets' );
