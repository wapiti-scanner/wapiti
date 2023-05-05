<?php
/**
 * Pass state to subsequent requests via cookies.
 *
 * @package automattic/jetpack-status
 */

namespace Automattic\Jetpack;

/**
 * Class Automattic\Jetpack\Status
 *
 * Used to retrieve information about the current status of Jetpack and the site overall.
 */
class CookieState {

	/**
	 * State is passed via cookies from one request to the next, but never to subsequent requests.
	 * SET: state( $key, $value );
	 * GET: $value = state( $key );
	 *
	 * @param string $key State key.
	 * @param string $value Value.
	 * @param bool   $restate Reset the cookie (private).
	 */
	public function state( $key = null, $value = null, $restate = false ) {
		static $state = array();
		static $path, $domain;
		if ( ! isset( $path ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
			$admin_url = ( new Paths() )->admin_url();
			$bits      = wp_parse_url( $admin_url );

			if ( is_array( $bits ) ) {
				$path   = ( isset( $bits['path'] ) ) ? dirname( $bits['path'] ) : null;
				$domain = ( isset( $bits['host'] ) ) ? $bits['host'] : null;
			} else {
				$path   = null;
				$domain = null;
			}
		}

		// Extract state from cookies and delete cookies.
		if ( isset( $_COOKIE['jetpackState'] ) && is_array( $_COOKIE['jetpackState'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- User should sanitize if necessary.
			$yum = wp_unslash( $_COOKIE['jetpackState'] );
			unset( $_COOKIE['jetpackState'] );
			foreach ( $yum as $k => $v ) {
				if ( strlen( $v ) ) {
					$state[ $k ] = $v;
				}
				setcookie( "jetpackState[$k]", false, 0, $path, $domain, is_ssl(), true );
			}
		}

		if ( $restate ) {
			foreach ( $state as $k => $v ) {
				setcookie( "jetpackState[$k]", $v, 0, $path, $domain, is_ssl(), true );
			}
			return;
		}

		// Get a state variable.
		if ( isset( $key ) && ! isset( $value ) ) {
			if ( array_key_exists( $key, $state ) ) {
				return $state[ $key ];
			}
			return null;
		}

		// Set a state variable.
		if ( isset( $key ) && isset( $value ) ) {
			if ( is_array( $value ) && isset( $value[0] ) ) {
				$value = $value[0];
			}
			$state[ $key ] = $value;
			if ( ! headers_sent() ) {
				if ( $this->should_set_cookie( $key ) ) {
					setcookie( "jetpackState[$key]", $value, 0, $path, $domain, is_ssl(), true );
				}
			}
		}
	}

	/**
	 * Determines whether the jetpackState[$key] value should be added to the
	 * cookie.
	 *
	 * @param string $key The state key.
	 *
	 * @return boolean Whether the value should be added to the cookie.
	 */
	public function should_set_cookie( $key ) {
		global $current_screen;
		$page = isset( $current_screen->base ) ? $current_screen->base : null;

		if ( 'toplevel_page_jetpack' === $page && 'display_update_modal' === $key ) {
			return false;
		}

		return true;
	}
}
