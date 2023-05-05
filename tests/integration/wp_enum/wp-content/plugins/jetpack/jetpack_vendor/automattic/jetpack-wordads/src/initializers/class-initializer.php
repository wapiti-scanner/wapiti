<?php
/**
 * Initializer base class.
 *
 * @package    @automattic/jetpack-wordads
 */

namespace Automattic\Jetpack\WordAds;

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Modules;
use WP_Error;
/**
 * Base class for the initializer pattern.
 */
class Initializer {

	/**
	 * Initialize the WordAds package.
	 */
	public static function init() {
		// Set up package version hook.
		add_filter( 'jetpack_package_versions', __NAMESPACE__ . '\Package::send_version_to_tracker' );

		/**
		 * The filter allows abortion of the WordAds package initialization.
		 *
		 * @since 0.1.0
		 *
		 * @param boolean $init_wordads_package Default value is true.
		 */
		if ( ! apply_filters( 'jetpack_wordads_init_wordads_package', true ) ) {
			/**
			 * Fires when the WordAds fails and would fallback to MySQL.
			 *
			 * @since Jetpack 7.9.0
			 * @param string $reason Reason for WordAds fallback.
			 * @param mixed  $data   Data associated with the request, such as attempted search parameters.
			 */
			do_action( 'jetpack_wordads_abort', 'jetpack_wordads_init_wordads_package_filter', null );
			return;
		}

		static::init_before_connection();

		// Check whether WordAds should be initialized in the first place .
		if ( ! static::is_connected() || ! static::is_wordads_supported() ) {
			/** This filter is documented in search/src/initalizers/class-initalizer.php */
			do_action( 'jetpack_wordads_abort', 'inactive', null );
			return;
		}

		$blog_id = Helper::get_wpcom_site_id();
		if ( ! $blog_id ) {
			/** This filter is documented in search/src/initalizers/class-initalizer.php */
			do_action( 'jetpack_wordads_abort', 'no_blog_id', null );
			return;
		}

		if ( ! ( new Modules() )->is_active( Package::SLUG ) ) {
			/** This filter is documented in search/src/initalizers/class-initalizer.php */
			do_action( 'jetpack_wordads_abort', 'module_inactive', null );
			return;
		}

		/**
		 * Fires when the WordAds package has been initialized.
		 *
		 * @since 0.1.0
		 */
		do_action( 'jetpack_wordads_loaded' );
	}

	/**
	 * Init functionality required for connection.
	 */
	protected static function init_before_connection() {
		// Set up WordAds API endpoints.
		add_action( 'rest_api_init', array( new REST_Controller(), 'register_rest_routes' ) );
		// The dashboard has to be initialized before connection.
		( new Dashboard() )->init_hooks();
	}

	/**
	 * Register jetpack-wordads CLI if `\CLI` exists.
	 *
	 * @return void
	 */
	protected static function init_cli() {
		if ( defined( 'WP_CLI' ) && \WP_CLI ) {
			\WP_CLI::add_command( 'wordads', __NAMESPACE__ . '\CLI' );
		}
	}

	/**
	 * Check if site has been connected.
	 */
	protected static function is_connected() {
		return ( new Connection_Manager( Package::SLUG ) )->is_connected();
	}

	/**
	 * Check if wordads is supported by current plan.
	 * TODO.
	 */
	protected static function is_wordads_supported() {
		return true;
	}

	/**
	 * Perform necessary initialization steps
	 *
	 * @deprecated
	 */
	public static function initialize() {
		return new WP_Error(
			'invalid-method',
			/* translators: %s: Method name. */
			sprintf( __( "Method '%s' not implemented. Must be overridden in subclass.", 'jetpack-wordads' ), __METHOD__ ),
			array( 'status' => 405 )
		);
	}
}
