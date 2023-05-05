<?php
/**
 * A compatibility shim for the sync modules class.
 *
 * @package automattic/jetpack-compat
 */

use Automattic\Jetpack\Sync\Modules;

/**
 * Class Jetpack_Sync_Modules
 *
 * @deprecated Use Automattic\Jetpack\Sync\Modules
 */
class Jetpack_Sync_Modules {

	/**
	 * Returns the sync module object.
	 *
	 * @param String $module_name the module name.
	 * @return Automattic\Jetpack\Sync\Modules\Module the module object.
	 */
	public static function get_module( $module_name ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Modules' );

		return Modules::get_module( $module_name );
	}
}
