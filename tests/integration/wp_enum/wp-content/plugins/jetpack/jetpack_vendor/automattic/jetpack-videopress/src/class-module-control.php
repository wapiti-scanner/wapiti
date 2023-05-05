<?php
/**
 * Jetpack VideoPress: Module_Control class
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

/**
 * To handle VideoPress module statuses
 */
class Module_Control {

	/**
	 * Initializer
	 *
	 * This method should onlybe called once by the Initializer class. Do not call this method again.
	 */
	public static function init() {
		add_filter( 'jetpack_get_available_standalone_modules', array( __CLASS__, 'add_videopress_to_array' ), 10, 1 );
		if ( Status::is_standalone_plugin_active() ) {
			// If the stand-alone plugin is active, videopress module will always be considered active
			add_filter( 'jetpack_active_modules', array( __CLASS__, 'add_videopress_to_array' ), 10, 2 );
		}
	}

	/**
	 * Adds videopress to the list of available/active modules
	 *
	 * @param array $modules Array with modules slugs.
	 * @return array
	 */
	public static function add_videopress_to_array( $modules ) {
		return array_merge( array( 'videopress' ), $modules );
	}
}
