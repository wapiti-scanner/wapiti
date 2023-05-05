<?php
/**
 * File: Util_Request.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * W3 Request object
 */

/**
 * Class: Util_Request
 */
class Util_Request {
	/**
	 * Returns request value
	 *
	 * @param string $key     Key.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	public static function get( $key, $default = null ) {
		$request = self::get_request();

		if ( isset( $request[ $key ] ) ) {
			$value = $request[ $key ];

			if ( defined( 'TEMPLATEPATH' ) ) {
				$value = Util_Environment::stripslashes( $value );
			}

			return $value;
		}

		return $default;
	}

	/**
	 * Returns string value
	 *
	 * @param string $key     Key.
	 * @param string $default Default value.
	 * @param bool   $trim    Trim.
	 * @return string
	 */
	public static function get_string( $key, $default = '', $trim = true ) {
		$value = (string) self::get( $key, $default );

		return ( $trim ) ? trim( $value ) : $value;
	}

	/**
	 * Get label.
	 *
	 * @param string $key     Key.
	 * @param string $default Default value.
	 * @return string
	 */
	public static function get_label( $key, $default = '' ) {
		$v = self::get_string( $key, $default );
		return preg_replace( '/[^A-Za-z0-9_\\-]/', '', $v );
	}

	/**
	 * Returns integer value.
	 *
	 * @param string $key     Key.
	 * @param int    $default Default value.
	 * @return int
	 */
	public static function get_integer( $key, $default = 0 ) {
		return (int) self::get( $key, $default );
	}

	/**
	 * Returns double value.
	 *
	 * @param string       $key     Key.
	 * @param double|float $default Default value.
	 * @return double
	 */
	public static function get_double( $key, $default = 0. ) {
		return (double) self::get( $key, $default ); // phpcs:ignore WordPress.PHP.TypeCasts.DoubleRealFound
	}

	/**
	 * Returns boolean value.
	 *
	 * @param string $key     Key.
	 * @param bool   $default Default value.
	 * @return bool
	 */
	public static function get_boolean( $key, $default = false ) {
		return Util_Environment::to_boolean( self::get( $key, $default ) );
	}

	/**
	 * Returns array value.
	 *
	 * @param string $key     Key.
	 * @param array  $default Default value.
	 * @return array
	 */
	public static function get_array( $key, $default = array() ) {
		$value = self::get( $key );

		if ( is_array( $value ) ) {
			return $value;
		} elseif ( ! empty( $value ) ) {
			return preg_split( "/[\r\n,;]+/", trim( $value ) );
		}

		return $default;
	}

	/**
	 * Returns array value.
	 *
	 * @param string $prefix  Prefix.
	 * @param array  $default Default value.
	 * @return array
	 */
	public static function get_as_array( $prefix, $default = array() ) {
		$request = self::get_request();
		$array   = array();

		foreach ( $request as $key => $value ) {
			if ( strpos( $key, $prefix ) === 0 || strpos( $key, str_replace( '.', '_', $prefix ) ) === 0 ) {
				$array[ substr( $key, strlen( $prefix ) ) ] = $value;
			}
		}
		return $array;
	}

	/**
	 * Returns request array.
	 *
	 * @return array
	 */
	public static function get_request() {
		if ( ! isset( $_GET ) ) {
			$_GET = array();
		}

		if ( ! isset( $_POST ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$_POST = array();
		}

		return array_merge( $_GET, $_POST ); // phpcs:ignore
	}
}
