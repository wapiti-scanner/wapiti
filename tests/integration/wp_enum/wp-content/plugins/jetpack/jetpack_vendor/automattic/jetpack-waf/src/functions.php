<?php
/**
 * Utility functions for WAF.
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf;

/**
 * A wrapper for WordPress's `wp_unslash()`.
 *
 * Even though PHP itself dropped the option to add slashes to superglobals a decade ago,
 * WordPress still does it through some misguided extreme backwards compatibility. 🙄
 *
 * If WordPress's function exists, assume it needs to be called. If not, assume it doesn't.
 *
 * @param string|array $value String or array of data to unslash.
 * @return string|array Possibly unslashed $value.
 */
function wp_unslash( $value ) {
	if ( function_exists( '\\wp_unslash' ) ) {
		return \wp_unslash( $value );
	} else {
		return $value;
	}
}

/**
 * PHP helpfully parses request data into nested arrays in superglobals like $_GET and $_POST,
 * and as part of that parsing turns field names like "myfield[x][y]" into a nested array
 * that looks like [ "myfield" => [ "x" => [ "y" => "..." ] ] ]
 * However, modsecurity (and thus our WAF rules) expect the original (non-nested) names.
 *
 * Therefore, this method takes an array of any depth and returns a single-depth array with nested
 * keys translated back to a single string with brackets.
 *
 * Because there might be multiple items with the same name, this function will return an array of tuples,
 * with the first item in the tuple the re-created original field name, and the second item the value.
 *
 * @example
 * flatten_array( [ "field1" => "abc", "field2" => [ "d", "e", "f" ] ] )
 * => [
 *       [ "field1", "abc" ],
 *       [ "field2[0]", "d" ],
 *       [ "field2[1]", "e" ],
 *       [ "field2[2]", "f" ],
 * ]
 *
 * @param array  $array       An array that resembles one of the PHP superglobals like $_GET or $_POST.
 * @param string $key_prefix  String that should be prepended to the keys output by this function.
 *                             Usually only used internally as part of recursion when flattening a nested array.
 * @return array{ 0: string, 1: scalar }[]  $key_prefix  An array of key/value tuples, one for each distinct value in the input array.
 */
function flatten_array( $array, $key_prefix = '' ) {
	$return = array();
	foreach ( $array as $source_key => $source_value ) {
		$key = ( '' === $key_prefix )
			// if this is the first level, the key name isn't enclosed in brackets
			? $source_key
			// for every level after the first, enclose the key name in brackets.
			: $key_prefix . '[' . $source_key . ']';
		if ( ! is_array( $source_value ) ) {
			$return[] = array( $key, $source_value );
		} else {
			$return = array_merge( $return, flatten_array( $source_value, $key ) );
		}
	}
	return $return;
}
