<?php
/**
 * Provides VideoPress videos support when module is disabled.
 *
 * @since 2.4
 * @since 3.9.5 Added compatibility with refactored VideoPress module.
 *
 * @package automattic/jetpack
 */

if ( ! Jetpack::is_module_active( 'videopress' ) ) {

	\Automattic\Jetpack\Assets::add_resource_hint(
		'//v0.wordpress.com',
		'dns-prefetch'
	);

	include_once JETPACK__PLUGIN_DIR . 'modules/videopress/shortcode.php';

}
