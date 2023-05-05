<?php
/**
 * This file holds a function that needs to be loaded before WordPress itself
 * on WordPress.com.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Device_Detection;

/**
 * Determine if the current User Agent matches the passed $kind
 *
 * @param string $kind Category of mobile device to check for.
 *                         Either: any, dumb, smart.
 * @param bool   $return_matched_agent Boolean indicating if the UA should be returned.
 *
 * @return bool|string Boolean indicating if current UA matches $kind. If
 *                              $return_matched_agent is true, returns the UA string
 */
function jetpack_is_mobile( $kind = 'any', $return_matched_agent = false ) {

	if ( function_exists( 'apply_filters' ) ) {
		/**
		 * Filter the value of jetpack_is_mobile before it is calculated.
		 *
		 * Passing a truthy value to the filter will short-circuit determining the
		 * mobile type, returning the passed value instead.
		 *
		 * @since  4.2.0
		 *
		 * @param bool|string $matches Boolean if current UA matches $kind or not. If
		 *                             $return_matched_agent is true, should return the UA string
		 * @param string      $kind Category of mobile device being checked
		 * @param bool        $return_matched_agent Boolean indicating if the UA should be returned
		 */
		$pre = apply_filters( 'pre_jetpack_is_mobile', null, $kind, $return_matched_agent );
		if ( $pre ) {
			return $pre;
		}
	}

	$return      = false;
	$device_info = Device_Detection::get_info();

	if ( 'any' === $kind ) {
		$return = $device_info['is_phone'];
	} elseif ( 'smart' === $kind ) {
		$return = $device_info['is_smartphone'];
	} elseif ( 'dumb' === $kind ) {
		$return = $device_info['is_phone'] && ! $device_info['is_smartphone'];
	}

	if ( $return_matched_agent && true === $return ) {
		$return = $device_info['is_phone_matched_ua'];
	}

	if ( function_exists( 'apply_filters' ) ) {
		/**
		 * Filter the value of jetpack_is_mobile
		 *
		 * @since  4.2.0
		 *
		 * @param bool|string $matches Boolean if current UA matches $kind or not. If
		 *                             $return_matched_agent is true, should return the UA string
		 * @param string      $kind Category of mobile device being checked
		 * @param bool        $return_matched_agent Boolean indicating if the UA should be returned
		 */
		$return = apply_filters( 'jetpack_is_mobile', $return, $kind, $return_matched_agent );
	}

	return $return;
}
