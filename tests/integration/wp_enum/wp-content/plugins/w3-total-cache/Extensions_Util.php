<?php
/**
 * File: Extensions_Util.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: Extensions_Util
 */
class Extensions_Util {
	/**
	 * Get registered extensions
	 *
	 * @static
	 *
	 * @param Config $config Configuration object.
	 * @return array
	 */
	public static function get_extensions( $config ) {
		return apply_filters( 'w3tc_extensions', __return_empty_array(), $config );
	}

	/**
	 * Get registered extension
	 *
	 * @static
	 *
	 * @param Config $config Configuration object.
	 * @param string $extension Extension.
	 * @return array
	 */
	public static function get_extension( $config, $extension ) {
		$exts = self::get_extensions( $config );

		if ( ! isset( $exts[ $extension ] ) ) {
			return null;
		}

		return $exts[ $extension ];
	}

	/**
	 * Returns the inactive extensions
	 *
	 * @static
	 *
	 * @param Config $config Configuration object.
	 * @return array
	 */
	public static function get_inactive_extensions( $config ) {
		$extensions        = self::get_extensions( $config );
		$config            = Dispatcher::config();
		$active_extensions = $config->get_array( 'extensions.active' );

		return array_diff_key( $extensions, $active_extensions );
	}

	/**
	 * Returns the active extensions.
	 *
	 * @static
	 *
	 * @param Config $config Configuration object.
	 * @return array
	 */
	public static function get_active_extensions( $config ) {
		$extensions        = self::get_extensions( $config );
		$extensions_keys   = array_keys( $extensions );
		$config            = Dispatcher::config();
		$active_extensions = $config->get_array( 'extensions.active' );

		return array_intersect_key( $extensions, $active_extensions );
	}

	/**
	 * Activate extension.
	 *
	 * @static
	 *
	 * @param string $extension        Extension.
	 * @param Config $w3_config        Configuration object.
	 * @param bool   $dont_save_config Whether or not to save configuration.  Default: false.
	 * @return bool
	 */
	public static function activate_extension( $extension, $w3_config, $dont_save_config = false ) {
		$all_extensions = self::get_extensions( $w3_config );
		$extensions     = $w3_config->get_array( 'extensions.active' );

		if ( ! $w3_config->is_extension_active( $extension ) ) {
			$meta = $all_extensions[ $extension ];

			$filename = W3TC_EXTENSION_DIR . '/' . trim( $meta['path'], '/' );

			if ( ! file_exists( $filename ) ) {
				return false;
			}

			include $filename;

			$extensions[ $extension ] = $meta['path'];

			ksort( $extensions, SORT_STRING );

			$w3_config->set( 'extensions.active', $extensions );

			// if extensions doesnt want to control frontend activity - activate it there too.
			if ( ! isset( $meta['active_frontend_own_control'] ) || ! $meta['active_frontend_own_control'] ) {
				$w3_config->set_extension_active_frontend( $extension, true );
			}

			try {
				if ( ! $dont_save_config ) {
					$w3_config->save();
				}

				// Set transient for displaying activation notice.
				set_transient( 'w3tc_activation_' . $extension, true, DAY_IN_SECONDS );

				return true;
			} catch ( \Exception $ex ) {
				return false;
			}
		}

		return false;
	}


	/**
	 * Deactivate extension.
	 *
	 * @static
	 *
	 * @param string $extension        Extension.
	 * @param Config $config           Configuration object.
	 * @param bool   $dont_save_config Whether or not to save configuration.  Default: false.
	 * @return bool
	 */
	public static function deactivate_extension( $extension, $config, $dont_save_config = false ) {
		$extensions = $config->get_array( 'extensions.active' );

		if ( array_key_exists( $extension, $extensions ) ) {
			unset( $extensions[ $extension ] );
			ksort( $extensions, SORT_STRING );
			$config->set( 'extensions.active', $extensions );
		}

		$config->set_extension_active_frontend( $extension, false );

		try {
			if ( ! $dont_save_config ) {
				$config->save();
			}

			// Delete transient for displaying activation notice.
			delete_transient( 'w3tc_activation_' . $extension );

			do_action( 'w3tc_deactivate_extension_' . $extension );

			return true;
		} catch ( \Exception $ex ) {
			return false;
		}

		return false;
	}
}
