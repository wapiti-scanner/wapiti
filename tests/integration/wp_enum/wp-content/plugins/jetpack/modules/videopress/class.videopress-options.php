<?php // phpcs:ignore WordPress.Files.FileName
/**
 * VideoPress Options
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\VideoPress\Options as Package_Options;

/**
 * VideoPress Options class.
 *
 * @deprecated 11.2
 */
class VideoPress_Options {

	/**
	 * Option name.
	 *
	 * @var string $option_name The 'videopress' option name
	 * @deprecated 11.2
	 */
	public static $option_name = 'videopress';

	/**
	 * VideoPress Options.
	 *
	 * @var array $options An array of associated VideoPress options (default empty)
	 * @deprecated 11.2
	 */
	protected static $options = array();

	/**
	 * Get VideoPress options
	 *
	 * @return array An array of VideoPress options.
	 * @deprecated 11.2
	 */
	public static function get_options() {
		_deprecated_function( __METHOD__, 'jetpack-11.2' );
		return Package_Options::get_options();
	}

	/**
	 * Update VideoPress options
	 *
	 * @param mixed $options VideoPress options.
	 */
	public static function update_options( $options ) {
		_deprecated_function( __METHOD__, 'jetpack-11.2' );
		return Package_Options::update_options( $options );
	}

	/**
	 * Runs when the VideoPress module is deactivated.
	 */
	public static function delete_options() {
		_deprecated_function( __METHOD__, 'jetpack-11.2' );
		return Package_Options::delete_options();
	}

}
