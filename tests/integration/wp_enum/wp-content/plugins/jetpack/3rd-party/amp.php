<?php
/**
 * This file contains compatibility features for AMP to improve Jetpack feature support.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack;

/**
 * Load Jetpack_AMP_Support.
 */
function load_3rd_party_amp_support() {
	// Only load the support class when AMP actually initializes.
	// This avoids calls to some slow functions if the plugin is loaded but
	// 'amp_is_enabled' is used to prevent it from initializing.
	require_once JETPACK__PLUGIN_DIR . '/3rd-party/class.jetpack-amp-support.php';

	add_action( 'init', array( 'Jetpack_AMP_Support', 'init' ), 1 );
	add_action( 'admin_init', array( 'Jetpack_AMP_Support', 'admin_init' ), 1 );
}

add_action( 'amp_init', __NAMESPACE__ . '\load_3rd_party_amp_support' );
