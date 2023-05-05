<?php
/**
 * Module: Theme Tools
 *
 * Load code specific to themes or theme tools
 * This file is special, and is not an actual `module` as such.
 * It is included by ./module-extras.php
 *
 * @package automattic/jetpack
 */

/**
 * Conditionally require the Tonesque lib depending on theme support.
 */
function jetpack_load_theme_tools() {
	if ( current_theme_supports( 'tonesque' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/_inc/lib/tonesque.php';
	}
}
add_action( 'init', 'jetpack_load_theme_tools', 30 );

/**
 * Load theme compat file if it exists.
 */
function jetpack_load_theme_compat() {

	/**
	 * Filter theme compat files.
	 *
	 * Themes can add their own compat files here if they like. For example:
	 *
	 * add_filter( 'jetpack_theme_compat_files', 'mytheme_jetpack_compat_file' );
	 * function mytheme_jetpack_compat_file( $files ) {
	 *     $files['mytheme'] = locate_template( 'jetpack-compat.php' );
	 *     return $files;
	 * }
	 *
	 * @module theme-tools
	 *
	 * @since 2.8.0
	 *
	 * @param array Associative array of theme compat files to load.
	 */
	$compat_files = apply_filters(
		'jetpack_theme_compat_files',
		array(
			'twentyfourteen'  => JETPACK__PLUGIN_DIR . 'modules/theme-tools/compat/twentyfourteen.php',
			'twentyfifteen'   => JETPACK__PLUGIN_DIR . 'modules/theme-tools/compat/twentyfifteen.php',
			'twentysixteen'   => JETPACK__PLUGIN_DIR . 'modules/theme-tools/compat/twentysixteen.php',
			'twentyseventeen' => JETPACK__PLUGIN_DIR . 'modules/theme-tools/compat/twentyseventeen.php',
			'twentynineteen'  => JETPACK__PLUGIN_DIR . 'modules/theme-tools/compat/twentynineteen.php',
			'twentytwenty'    => JETPACK__PLUGIN_DIR . 'modules/theme-tools/compat/twentytwenty.php',
			'twentytwentyone' => JETPACK__PLUGIN_DIR . 'modules/theme-tools/compat/twentytwentyone.php',
		)
	);

	_jetpack_require_compat_file( get_stylesheet(), $compat_files );

	if ( is_child_theme() ) {
		_jetpack_require_compat_file( get_template(), $compat_files );
	}
}
add_action( 'after_setup_theme', 'jetpack_load_theme_compat', -1 );

/**
 * Requires a file once, if the passed key exists in the files array.
 *
 * @access private
 * @param string $key The key to check.
 * @param array  $files Array of files to check in.
 * @return void|WP_Error
 */
function _jetpack_require_compat_file( $key, $files ) {
	if ( ! is_string( $key ) ) {
		return new WP_Error( 'key_not_string', 'The specified key is not actually a string.', compact( 'key' ) );
	}

	if ( array_key_exists( $key, $files ) && is_readable( $files[ $key ] ) ) {
		require_once $files[ $key ];
	}
}
