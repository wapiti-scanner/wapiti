<?php
/**
 * Simple wrapper that allows enumerating cached static instances
 * of sync modules.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use Automattic\Jetpack\Sync\Modules\Module;

/**
 * A class to handle loading of sync modules.
 */
class Modules {

	/**
	 * Lists classnames of sync modules we load by default.
	 *
	 * @access public
	 *
	 * @var array
	 */
	const DEFAULT_SYNC_MODULES = array(
		'Automattic\\Jetpack\\Sync\\Modules\\Constants',
		'Automattic\\Jetpack\\Sync\\Modules\\Callables',
		'Automattic\\Jetpack\\Sync\\Modules\\Network_Options',
		'Automattic\\Jetpack\\Sync\\Modules\\Options',
		'Automattic\\Jetpack\\Sync\\Modules\\Terms',
		'Automattic\\Jetpack\\Sync\\Modules\\Menus',
		'Automattic\\Jetpack\\Sync\\Modules\\Themes',
		'Automattic\\Jetpack\\Sync\\Modules\\Users',
		'Automattic\\Jetpack\\Sync\\Modules\\Import',
		'Automattic\\Jetpack\\Sync\\Modules\\Posts',
		'Automattic\\Jetpack\\Sync\\Modules\\Protect',
		'Automattic\\Jetpack\\Sync\\Modules\\Comments',
		'Automattic\\Jetpack\\Sync\\Modules\\Updates',
		'Automattic\\Jetpack\\Sync\\Modules\\Attachments',
		'Automattic\\Jetpack\\Sync\\Modules\\Meta',
		'Automattic\\Jetpack\\Sync\\Modules\\Plugins',
		'Automattic\\Jetpack\\Sync\\Modules\\Stats',
		'Automattic\\Jetpack\\Sync\\Modules\\Full_Sync_Immediately',
		'Automattic\\Jetpack\\Sync\\Modules\\Term_Relationships',
	);

	/**
	 * Keeps track of initialized sync modules.
	 *
	 * @access private
	 * @static
	 *
	 * @var null|array
	 */
	private static $initialized_modules = null;

	/**
	 * Gets a list of initialized modules.
	 *
	 * @access public
	 * @static
	 *
	 * @return Module[]
	 */
	public static function get_modules() {
		if ( null === self::$initialized_modules ) {
			self::$initialized_modules = self::initialize_modules();
		}

		return self::$initialized_modules;
	}

	/**
	 * Sets defaults for all initialized modules.
	 *
	 * @access public
	 * @static
	 */
	public static function set_defaults() {
		foreach ( self::get_modules() as $module ) {
			$module->set_defaults();
		}
	}

	/**
	 * Gets the name of an initialized module. Returns false if given module has not been initialized.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $module_name A module name.
	 *
	 * @return bool|Automattic\Jetpack\Sync\Modules\Module
	 */
	public static function get_module( $module_name ) {
		foreach ( self::get_modules() as $module ) {
			if ( $module->name() === $module_name ) {
				return $module;
			}
		}

		return false;
	}

	/**
	 * Loads and sets defaults for all declared modules.
	 *
	 * @access public
	 * @static
	 *
	 * @return array
	 */
	public static function initialize_modules() {
		/**
		 * Filters the list of class names of sync modules.
		 * If you add to this list, make sure any classes implement the
		 * Jetpack_Sync_Module interface.
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 */
		$modules = apply_filters( 'jetpack_sync_modules', self::DEFAULT_SYNC_MODULES );

		$modules = array_map( array( __CLASS__, 'load_module' ), $modules );

		return array_map( array( __CLASS__, 'set_module_defaults' ), $modules );
	}

	/**
	 * Returns an instance of the given module class.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $module_class The classname of a Jetpack sync module.
	 *
	 * @return Automattic\Jetpack\Sync\Modules\Module
	 */
	public static function load_module( $module_class ) {
		return new $module_class();
	}

	/**
	 * Sets defaults for the given instance of a Jetpack sync module.
	 *
	 * @access public
	 * @static
	 *
	 * @param Automattic\Jetpack\Sync\Modules\Module $module Instance of a Jetpack sync module.
	 *
	 * @return Automattic\Jetpack\Sync\Modules\Module
	 */
	public static function set_module_defaults( $module ) {
		$module->set_defaults();
		if ( method_exists( $module, 'set_late_default' ) ) {
			add_action( 'init', array( $module, 'set_late_default' ), 90 );
		}
		return $module;
	}
}
