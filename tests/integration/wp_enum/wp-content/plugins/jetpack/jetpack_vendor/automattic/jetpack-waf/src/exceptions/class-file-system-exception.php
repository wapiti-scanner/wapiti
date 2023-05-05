<?php
/**
 * File system exception.
 *
 * @since 0.10.1
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf;

/**
 * Custom exception for WAF file system errors.
 */
class File_System_Exception extends Waf_Exception {

	/**
	 * Error slug which maps to WP_Error::$code.
	 *
	 * @var string
	 */
	const SLUG = 'file_system_error';

}
