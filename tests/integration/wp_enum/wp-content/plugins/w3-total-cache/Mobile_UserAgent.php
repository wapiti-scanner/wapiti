<?php
/**
 * File: Mobile_UserAgent.php
 *
 * W3TC Mobile detection.
 *
 * @package W3TC
 * @subpackage QA
 */

namespace W3TC;

/**
 * Class Mobile_UserAgent
 */
class Mobile_UserAgent extends Mobile_Base {
	/**
	 * PHP5-style constructor
	 */
	public function __construct() {
		parent::__construct( 'mobile.rgroups', 'agents' );
	}

	/**
	 * Group verifier.
	 *
	 * @param string $group_compare_value Group comparison value.
	 * @return int|false
	 */
	public function group_verifier( $group_compare_value ) {
		return preg_match(
			'~' . $group_compare_value . '~i',
			isset( $_SERVER['HTTP_USER_AGENT'] ) ?
				htmlspecialchars( $_SERVER['HTTP_USER_AGENT'] ) : '' // phpcs:ignore
		);
	}
}
