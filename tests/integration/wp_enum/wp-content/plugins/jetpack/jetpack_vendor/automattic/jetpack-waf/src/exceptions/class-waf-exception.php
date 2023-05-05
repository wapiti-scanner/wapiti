<?php
/**
 * Base custom exception for the WAF package.
 *
 * @since 0.10.1
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf;

use Exception;
use WP_Error;

/**
 * WAF exception.
 */
class Waf_Exception extends Exception {

	/**
	 * Error slug which maps to WP_Error::$code.
	 *
	 * @var string
	 */
	const SLUG = 'waf_error';

	/**
	 * Convert the exception into a WP_Error object.
	 *
	 * @return WP_Error
	 */
	public function get_wp_error() {
		return new WP_Error( static::SLUG, $this->getMessage() );
	}

}
