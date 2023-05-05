<?php
/**
 * The class that provides information about VideoPress Status
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use Jetpack;

/**
 * The class that provides information about VideoPress Status
 */
class Status {

	/**
	 * Returns whether VideoPress is active
	 * either as a Jetpack module or as a stand alone plugin
	 *
	 * @return boolean
	 */
	public static function is_active() {
		return self::is_jetpack_plugin_and_videopress_module_active() || self::is_standalone_plugin_active();
	}

	/**
	 * Checks whether the Jetpack plugin is active
	 */
	public static function is_jetpack_plugin_active() {
		return class_exists( 'Jetpack' );
	}

	/**
	 * Checks whether the Jetpack plugin
	 * and its VideoPress module are active.
	 *
	 * @return boolean
	 */
	public static function is_jetpack_plugin_and_videopress_module_active() {
		return class_exists( 'Jetpack' ) && Jetpack::is_module_active( 'videopress' );
	}

	/**
	 * Checks whether the VideoPress stand alone plugin is active
	 *
	 * @return boolean
	 */
	public static function is_standalone_plugin_active() {
		return class_exists( 'Jetpack_VideoPress_Plugin' );
	}

	/**
	 * Checks whether the registrant plugin is active
	 * either as a Jetpack module (via Jetpack plugin)
	 * or as a stand-alone plugin.
	 *
	 * @return boolean True if the register plugin is active.
	 */
	public static function is_registrant_plugin_active() {
		return self::is_jetpack_plugin_active() || self::is_standalone_plugin_active();
	}
}
