<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Jetpack Heartbeat.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Manager;
use Automattic\Jetpack\Heartbeat;

/**
 * Jetpack Heartbeat.
 */
class Jetpack_Heartbeat {

	/**
	 * Holds the singleton instance of this class
	 *
	 * @since 2.3.3
	 * @var Jetpack_Heartbeat
	 */
	private static $instance = false;

	/**
	 * Holds the singleton instance of the proxied class
	 *
	 * @since 8.9.0
	 * @var Automattic\Jetpack\Heartbeat
	 */
	private static $proxied_instance = false;

	/**
	 * Singleton
	 *
	 * @since 2.3.3
	 * @static
	 * @return Jetpack_Heartbeat
	 */
	public static function init() {
		if ( ! self::$instance ) {
			self::$instance         = new Jetpack_Heartbeat();
			self::$proxied_instance = Heartbeat::init();
		}

		return self::$instance;
	}

	/**
	 * Constructor for singleton
	 *
	 * @since 2.3.3
	 */
	private function __construct() {
		add_filter( 'jetpack_heartbeat_stats_array', array( $this, 'add_stats_to_heartbeat' ) );
	}

	/**
	 * Generates heartbeat stats data.
	 *
	 * @param string $prefix Prefix to add before stats identifier.
	 *
	 * @return array The stats array.
	 */
	public static function generate_stats_array( $prefix = '' ) {
		$return = array();

		$return[ "{$prefix}version" ]        = JETPACK__VERSION;
		$return[ "{$prefix}wp-version" ]     = get_bloginfo( 'version' );
		$return[ "{$prefix}php-version" ]    = PHP_VERSION;
		$return[ "{$prefix}branch" ]         = (float) JETPACK__VERSION;
		$return[ "{$prefix}wp-branch" ]      = (float) get_bloginfo( 'version' );
		$return[ "{$prefix}php-branch" ]     = (float) PHP_VERSION;
		$return[ "{$prefix}public" ]         = Jetpack_Options::get_option( 'public' );
		$return[ "{$prefix}ssl" ]            = Jetpack::permit_ssl();
		$return[ "{$prefix}is-https" ]       = is_ssl() ? 'https' : 'http';
		$return[ "{$prefix}language" ]       = get_bloginfo( 'language' );
		$return[ "{$prefix}charset" ]        = get_bloginfo( 'charset' );
		$return[ "{$prefix}is-multisite" ]   = is_multisite() ? 'multisite' : 'singlesite';
		$return[ "{$prefix}identitycrisis" ] = Jetpack::check_identity_crisis() ? 'yes' : 'no';
		$return[ "{$prefix}plugins" ]        = implode( ',', Jetpack::get_active_plugins() );
		if ( function_exists( 'get_mu_plugins' ) ) {
			$return[ "{$prefix}mu-plugins" ] = implode( ',', array_keys( get_mu_plugins() ) );
		}
		$return[ "{$prefix}manage-enabled" ] = true;

		if ( function_exists( 'get_space_used' ) ) { // Only available in multisite.
			$space_used = get_space_used();
		} else {
			// This is the same as `get_space_used`, except it does not apply the short-circuit filter.
			$upload_dir = wp_upload_dir();
			$space_used = get_dirsize( $upload_dir['basedir'] ) / MB_IN_BYTES;
		}

		$return[ "{$prefix}space-used" ] = $space_used;

		$xmlrpc_errors = Jetpack_Options::get_option( 'xmlrpc_errors', array() );
		if ( $xmlrpc_errors ) {
			$return[ "{$prefix}xmlrpc-errors" ] = implode( ',', array_keys( $xmlrpc_errors ) );
			Jetpack_Options::delete_option( 'xmlrpc_errors' );
		}

		// Missing the connection owner?
		$connection_manager                 = new Manager();
		$return[ "{$prefix}missing-owner" ] = $connection_manager->is_missing_connection_owner();

		// is-multi-network can have three values, `single-site`, `single-network`, and `multi-network`.
		$return[ "{$prefix}is-multi-network" ] = 'single-site';
		if ( is_multisite() ) {
			$return[ "{$prefix}is-multi-network" ] = Jetpack::is_multi_network() ? 'multi-network' : 'single-network';
		}

		if ( ! empty( $_SERVER['SERVER_ADDR'] ) || ! empty( $_SERVER['LOCAL_ADDR'] ) ) {
			$ip     = ! empty( $_SERVER['SERVER_ADDR'] ) ? wp_unslash( $_SERVER['SERVER_ADDR'] ) : wp_unslash( $_SERVER['LOCAL_ADDR'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized just below.
			$ip_arr = array_map( 'intval', explode( '.', $ip ) );
			if ( 4 === count( $ip_arr ) ) {
				$return[ "{$prefix}ip-2-octets" ] = implode( '.', array_slice( $ip_arr, 0, 2 ) );
			}
		}

		foreach ( Jetpack::get_available_modules() as $slug ) {
			$return[ "{$prefix}module-{$slug}" ] = Jetpack::is_module_active( $slug ) ? 'on' : 'off';
		}

		return $return;
	}

	/**
	 * Add Jetpack Stats array to Heartbeat if Jetpack is connected
	 *
	 * @since 8.9.0
	 *
	 * @param array $stats Jetpack Heartbeat stats.
	 * @return array $stats
	 */
	public function add_stats_to_heartbeat( $stats ) {

		if ( ! Jetpack::is_connection_ready() ) {
			return $stats;
		}

		$jetpack_stats = self::generate_stats_array();

		return array_merge( $stats, $jetpack_stats );
	}

}
