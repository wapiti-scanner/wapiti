<?php
/**
 * WordAds package information.
 *
 * @package automattic/jetpack-wordads
 */

namespace Automattic\Jetpack\WordAds;

/**
 * WordAds package general information
 */
class Package {
	const VERSION = '0.2.41';
	const SLUG    = 'wordads';

	/**
	 * The path where package is installed.
	 *
	 * @var string
	 */
	protected static $installed_path;

	/**
	 * Adds the package slug and version to the package version tracker's data.
	 *
	 * @param array $package_versions The package version array.
	 *
	 * @return array The package version array.
	 */
	public static function send_version_to_tracker( $package_versions ) {
		// Multiple versions could co-exist, we want to send the version which is in use.
		// `jetpack-autoloader` would load classes from the latest package, so we send the latest version here.
		if ( empty( $package_versions[ self::SLUG ] ) || version_compare( $package_versions[ self::SLUG ], self::VERSION, '<' ) ) {
			$package_versions[ self::SLUG ] = self::VERSION;
		}
		return $package_versions;
	}

	/**
	 * Whether Jetpack WordAds Package's version maps to a public release, or a development version.
	 */
	public static function is_development_version() {
		return (bool) apply_filters(
			'jetpack_wordads_is_development_version',
			! preg_match( '/^\d+(\.\d+)+$/', self::VERSION )
		);
	}

	/**
	 * Return the path where the package is installed with trailing slash.
	 * It's important not to use a constant, as there could be multiple versions of search package installed.
	 *
	 * @return string
	 */
	public static function get_installed_path() {
		if ( static::$installed_path === null ) {
			static::$installed_path = dirname( __DIR__ ) . DIRECTORY_SEPARATOR;
		}
		return apply_filters( 'jetpack_wordads_installed_path', static::$installed_path );
	}
}
