<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Fallback for the Crowdsignal Plugin.
 *
 * The PollDaddy/Crowdsignal prior to v. 2.033 called Jetpack_Sync as long as the Jetpack class was present. This stub is provided to prevent any fatals for older versions of the plugin.
 * This was resolved in 2016, but need to do just a little research before ripping it out.
 *
 * @see https://github.com/Automattic/crowdsignal-plugin/commit/941fc5758152ebf860a14d1cd0058245e8aed86b
 *
 * @package automattic/jetpack
 */

/**
 * Stub of Jetpack_Sync for Crowdsignal.
 */
class Jetpack_Sync {
	/**
	 * Stub of sync_options to prevent fatals for Crowdsignal.
	 */
	public static function sync_options() {
		_deprecated_function( __METHOD__, 'jetpack-4.2', 'jetpack_options_whitelist filter' );
	}
}
