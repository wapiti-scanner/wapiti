<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\VideoPress\XMLRPC;
/**
 * VideoPress playback module markup generator.
 *
 * @since 1.3
 */
class VideoPress_XMLRPC {

	/**
	 * Initialize the XMLRPC and get back a singleton instance.
	 *
	 * @return XMLRPC
	 * @deprecated 11.2
	 * @see Automattic\Jetpack\VideoPress\XMLRPC::init
	 */
	public static function init() {
		_deprecated_function( __METHOD__, 'jetpack-11.2', 'Automattic\Jetpack\VideoPress\XMLRPC' );
		return XMLRPC::init();
	}

}
