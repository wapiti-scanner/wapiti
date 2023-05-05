<?php
/**
 * Class for functions shared by the Brute force protection feature and its related json-endpoints
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf\Brute_Force_Protection;

use Automattic\Jetpack\IP\Utils as IP_Utils;
use Automattic\Jetpack\Waf\Waf_Rules_Manager;
use WP_Error;

/**
 * Shared Functions class.
 */
class Brute_Force_Protection_Shared_Functions {
	/**
	 * Returns an array of IP objects that will never be blocked by the Brute force protection feature
	 *
	 * @deprecated 0.11.0 Use format_allow_list()
	 */
	public static function format_whitelist() {
		_deprecated_function( __METHOD__, 'waf-0.11.0', __CLASS__ . '::format_allow_list' );
		return self::format_allow_list();
	}

	/**
	 * Returns an array of IP objects that will never be blocked by the Brute force protection feature
	 *
	 * The array is segmented into a local allow list which applies only to the current site
	 * and a global allow list which, for multisite installs, applies to the entire networko
	 *
	 * @return array
	 */
	public static function format_allow_list() {
		$local_allow_list = self::get_local_allow_list();
		$formatted        = array(
			'local' => array(),
		);
		foreach ( $local_allow_list as $item ) {
			if ( $item->range ) {
				$formatted['local'][] = $item->range_low . ' - ' . $item->range_high;
			} else {
				$formatted['local'][] = $item->ip_address;
			}
		}
		if ( is_multisite() && current_user_can( 'manage_network' ) ) {
			$formatted['global'] = array();
			$global_allow_list   = self::get_global_allow_list();
			if ( false === $global_allow_list ) {
				// If the global allow list has never been set, check for a legacy option set prior to 3.6.
				$global_allow_list = get_site_option( 'jetpack_protect_whitelist', array() );
			}
			foreach ( $global_allow_list as $item ) {
				if ( $item->range ) {
					$formatted['global'][] = $item->range_low . ' - ' . $item->range_high;
				} else {
					$formatted['global'][] = $item->ip_address;
				}
			}
		}
		return $formatted;
	}

	/**
	 * Gets the local Brute force protection allow list.
	 *
	 * @deprecated 0.11.0 Use get_local_allow_list()
	 */
	public static function get_local_whitelist() {
		_deprecated_function( __METHOD__, 'waf-0.11.0', __CLASS__ . '::get_local_allow_list' );
		return self::get_local_allow_list();
	}

	/**
	 * Gets the local Brute force protection allow list.
	 *
	 * The 'local' part of the allow list only really applies to multisite installs,
	 * which can have a network wide allow list, as well as a local list that applies
	 * only to the current site. On single site installs, there will only be a local
	 * allow list.
	 *
	 * @return array A list of IP Address objects or an empty array
	 */
	public static function get_local_allow_list() {
		$allow_list = get_option( Waf_Rules_Manager::IP_ALLOW_LIST_OPTION_NAME );
		if ( false === $allow_list ) {
			// The local allow list has never been set.
			if ( is_multisite() ) {
				// On a multisite, we can check for a legacy site_option that existed prior to v 3.6, or default to an empty array.
				$allow_list = get_site_option( 'jetpack_protect_whitelist', array() );
			} else {
				// On a single site, we can just use an empty array.
				$allow_list = array();
			}
		} else {
			$allow_list = IP_Utils::get_ip_addresses_from_string( $allow_list );
			$allow_list = array_map(
				function ( $ip_address ) {
					return self::create_ip_object( $ip_address );
				},
				$allow_list
			);
		}
		return $allow_list;
	}

	/**
	 * Get the global, network-wide allow list.
	 *
	 * @deprecated 0.11.0 Use get_global_allow_list()
	 */
	public static function get_global_whitelist() {
		_deprecated_function( __METHOD__, 'waf-0.11.0', __CLASS__ . '::get_global_allow_list' );
		return self::get_global_allow_list();
	}

	/**
	 * Get the global, network-wide allow list.
	 *
	 * It will revert to the legacy site_option if jetpack_protect_global_whitelist has never been set.
	 *
	 * @return array
	 */
	public static function get_global_allow_list() {
		$allow_list = get_site_option( 'jetpack_protect_global_whitelist' );
		if ( false === $allow_list ) {
			// The global allow list has never been set. Check for legacy site_option, or default to an empty array.
			$allow_list = get_site_option( 'jetpack_protect_whitelist', array() );
		}
		return $allow_list;
	}

	/**
	 * Convert a string into an IP Address object.
	 *
	 * @param string $ip_address The IP Address to convert.
	 * @return object An IP Address object.
	 */
	private static function create_ip_object( $ip_address ) {
		$range = false;
		if ( strpos( $ip_address, '-' ) ) {
			$ip_address = explode( '-', $ip_address );
			$range      = true;
		}
		$new_item        = new \stdClass();
		$new_item->range = $range;
		if ( $range ) {
			$new_item->range_low  = trim( $ip_address[0] );
			$new_item->range_high = trim( $ip_address[1] );
		} else {
			$new_item->ip_address = $ip_address;
		}
		return $new_item;
	}

	/**
	 * Save IP allow list.
	 *
	 * @deprecated 0.11.0 Use save_allow_list()
	 *
	 * @param mixed $allow_list IP allow list.
	 * @param bool  $global (default: false) Global.
	 */
	public static function save_whitelist( $allow_list, $global = false ) {
		_deprecated_function( __METHOD__, 'waf-0.11.0', __CLASS__ . '::save_allow_list' );
		return self::save_allow_list( $allow_list, $global );
	}

	/**
	 * Save IP allow list.
	 *
	 * @access public
	 * @param mixed $allow_list IP allow list.
	 * @param bool  $global (default: false) Global.
	 * @return Bool.
	 */
	public static function save_allow_list( $allow_list, $global = false ) {
		$allow_list_error = false;
		$new_items        = array();
		if ( ! is_array( $allow_list ) ) {
			return new WP_Error( 'invalid_parameters', __( 'Expecting an array', 'jetpack-waf' ) );
		}
		if ( $global && ! is_multisite() ) {
			return new WP_Error( 'invalid_parameters', __( 'Cannot use global flag on non-multisites', 'jetpack-waf' ) );
		}
		if ( $global && ! current_user_can( 'manage_network' ) ) {
			return new WP_Error( 'permission_denied', __( 'Only super admins can edit the global allow list', 'jetpack-waf' ) );
		}
		// Validate each item.
		foreach ( $allow_list as $item ) {
			$item = trim( $item );
			if ( empty( $item ) ) {
				continue;
			}
			$new_item = self::create_ip_object( $item );
			if ( $new_item->range ) {
				if ( ! filter_var( $new_item->range_low, FILTER_VALIDATE_IP ) || ! filter_var( $new_item->range_high, FILTER_VALIDATE_IP ) ) {
					$allow_list_error = true;
					break;
				}
				if ( ! IP_Utils::convert_ip_address( $new_item->range_low ) || ! IP_Utils::convert_ip_address( $new_item->range_high ) ) {
					$allow_list_error = true;
					break;
				}
			} else {
				if ( ! filter_var( $new_item->ip_address, FILTER_VALIDATE_IP ) ) {
					$allow_list_error = true;
					break;
				}
				if ( ! IP_Utils::convert_ip_address( $new_item->ip_address ) ) {
					$allow_list_error = true;
					break;
				}
			}
			$new_items[] = $new_item;
		} // End item loop.
		if ( ! empty( $allow_list_error ) ) {
			return new WP_Error( 'invalid_ip', __( 'One of your IP addresses was not valid.', 'jetpack-waf' ) );
		}
		if ( $global ) {
			update_site_option( 'jetpack_protect_global_whitelist', $new_items );
			// Once a user has saved their global allow list, we can permanently remove the legacy option.
			delete_site_option( 'jetpack_protect_whitelist' );
		} else {
			$new_items = array_map(
				function ( $item ) {
					if ( $item->range ) {
							return $item->range_low . '-' . $item->range_high;
					}
					return $item->ip_address;
				},
				$new_items
			);
			update_option( Waf_Rules_Manager::IP_ALLOW_LIST_OPTION_NAME, implode( ' ', $new_items ) );
		}
		return true;
	}
}
