<?php
namespace W3TC;

/**
 * W3TC Referrer detection
 */
define( 'W3TC_REFERRER_COOKIE_NAME', 'w3tc_referrer' );

/**
 * Class: Mobile_Referrer
 */
class Mobile_Referrer extends Mobile_Base {
	/**
	 * PHP5-style constructor
	 */
	public function __construct() {
		parent::__construct( 'referrer.rgroups', 'referrers' );
	}

	/**
	 * Returns HTTP referrer value.
	 *
	 * @return string
	 */
	public function get_http_referrer() {
		$http_referrer = '';

		if ( $this->has_enabled_groups() ) {
			if ( isset( $_COOKIE[ W3TC_REFERRER_COOKIE_NAME ] ) ) {
				$http_referrer = htmlspecialchars( $_COOKIE[ W3TC_REFERRER_COOKIE_NAME ] ); // phpcs:ignore
			} elseif ( isset( $_SERVER['HTTP_REFERER'] ) ) {
				$http_referrer = filter_var( $_SERVER['HTTP_REFERER'], FILTER_SANITIZE_URL ); // phpcs:ignore

				setcookie( W3TC_REFERRER_COOKIE_NAME, $http_referrer, 0, '/' /* not defined yet Util_Environment::network_home_url_uri()*/ );
			}
		} elseif ( isset( $_COOKIE[ W3TC_REFERRER_COOKIE_NAME ] ) ) {
			setcookie( W3TC_REFERRER_COOKIE_NAME, '', 1 );
		}

		return $http_referrer;
	}

	function group_verifier( $group_compare_value ) {
		static $http_referrer = null;
		if ( is_null( $http_referrer ) )
			$http_referrer = $this->get_http_referrer();
		return $http_referrer && preg_match( '~' . $group_compare_value . '~i', $http_referrer );
	}

	function do_get_group() {
		return $this->get_http_referrer();
	}
}
