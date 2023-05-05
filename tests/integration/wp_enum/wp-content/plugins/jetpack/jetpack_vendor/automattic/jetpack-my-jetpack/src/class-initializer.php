<?php
/**
 * WP Admin page with information and configuration shared among all Jetpack stand-alone plugins
 *
 * @package automattic/my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack;

use Automattic\Jetpack\Admin_UI\Admin_Menu;
use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Connection\Client as Client;
use Automattic\Jetpack\Connection\Initial_State as Connection_Initial_State;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Connection\Rest_Authentication as Connection_Rest_Authentication;
use Automattic\Jetpack\Constants as Jetpack_Constants;
use Automattic\Jetpack\JITMS\JITM as JITM;
use Automattic\Jetpack\Licensing;
use Automattic\Jetpack\Plugins_Installer;
use Automattic\Jetpack\Status as Status;
use Automattic\Jetpack\Terms_Of_Service;
use Automattic\Jetpack\Tracking;

/**
 * The main Initializer class that registers the admin menu and eneuque the assets.
 */
class Initializer {

	/**
	 * My Jetpack package version
	 *
	 * @var string
	 */
	const PACKAGE_VERSION = '2.11.0';

	/**
	 * Initialize My Jetpack
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! self::should_initialize() || did_action( 'my_jetpack_init' ) ) {
			return;
		}

		// Extend jetpack plugins action links.
		Products::extend_plugins_action_links();

		// Set up the REST authentication hooks.
		Connection_Rest_Authentication::init();

		if ( self::is_licensing_ui_enabled() ) {
			Licensing::instance()->initialize();
		}

		// Add custom WP REST API endoints.
		add_action( 'rest_api_init', array( __CLASS__, 'register_rest_endpoints' ) );

		$page_suffix = Admin_Menu::add_menu(
			__( 'My Jetpack', 'jetpack-my-jetpack' ),
			__( 'My Jetpack', 'jetpack-my-jetpack' ),
			'manage_options',
			'my-jetpack',
			array( __CLASS__, 'admin_page' ),
			999
		);

		add_action( 'load-' . $page_suffix, array( __CLASS__, 'admin_init' ) );

		// Sets up JITMS.
		JITM::configure();

		/**
		 * Fires after the My Jetpack package is initialized
		 *
		 * @since 0.1.0
		 */
		do_action( 'my_jetpack_init' );
	}

	/**
	 * Acts as a feature flag, returning a boolean for whether we should show the licensing UI.
	 *
	 * @since 1.2.0
	 *
	 * @return boolean
	 */
	public static function is_licensing_ui_enabled() {
		// Default changed to true in 1.5.0.
		$is_enabled = true;

		/*
		 * Bail if My Jetpack is not enabled,
		 * and thus the licensing UI shouldn't be enabled either.
		 */
		if ( ! self::should_initialize() ) {
			$is_enabled = false;
		}

		/**
		 * Acts as a feature flag, returning a boolean for whether we should show the licensing UI.
		 *
		 * @param bool $is_enabled Defaults to true.
		 *
		 * @since 1.2.0
		 * @since 1.5.0 Update default value to true.
		 */
		return apply_filters(
			'jetpack_my_jetpack_should_enable_add_license_screen',
			$is_enabled
		);
	}

	/**
	 * Callback for the load my jetpack page hook.
	 *
	 * @return void
	 */
	public static function admin_init() {
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_scripts' ) );
		// Product statuses are constantly changing, so we never want to cache the page.
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );
	}

	/**
	 * Returns whether we are in condition to track to use
	 * Analytics functionality like Tracks, MC, or GA.
	 */
	public static function can_use_analytics() {
		$status     = new Status();
		$connection = new Connection_Manager();
		$tracking   = new Tracking( 'jetpack', $connection );

		return $tracking->should_enable_tracking( new Terms_Of_Service(), $status );
	}
	/**
	 * Enqueue admin page assets.
	 *
	 * @return void
	 */
	public static function enqueue_scripts() {
		Assets::register_script(
			'my_jetpack_main_app',
			'../build/index.js',
			__FILE__,
			array(
				'enqueue'    => true,
				'in_footer'  => true,
				'textdomain' => 'jetpack-my-jetpack',
			)
		);
		wp_localize_script(
			'my_jetpack_main_app',
			'myJetpackInitialState',
			array(
				'products'              => array(
					'items' => Products::get_products(),
				),
				'purchases'             => array(
					'items' => array(),
				),
				'plugins'               => Plugins_Installer::get_plugins(),
				'myJetpackUrl'          => admin_url( 'admin.php?page=my-jetpack' ),
				'topJetpackMenuItemUrl' => Admin_Menu::get_top_level_menu_item_url(),
				'siteSuffix'            => ( new Status() )->get_site_suffix(),
				'myJetpackVersion'      => self::PACKAGE_VERSION,
				'myJetpackFlags'        => self::get_my_jetpack_flags(),
				'fileSystemWriteAccess' => self::has_file_system_write_access(),
				'loadAddLicenseScreen'  => self::is_licensing_ui_enabled(),
				'adminUrl'              => esc_url( admin_url() ),
			)
		);

		wp_localize_script(
			'my_jetpack_main_app',
			'myJetpackRest',
			array(
				'apiRoot'  => esc_url_raw( rest_url() ),
				'apiNonce' => wp_create_nonce( 'wp_rest' ),
			)
		);

		// Connection Initial State.
		wp_add_inline_script( 'my_jetpack_main_app', Connection_Initial_State::render(), 'before' );

		// Required for Analytics.
		if ( self::can_use_analytics() ) {
			Tracking::register_tracks_functions_scripts( true );
		}
	}

	/**
	 *  Build flags for My Jetpack UI
	 *
	 *  @return array
	 */
	public static function get_my_jetpack_flags() {
		$flags = array(
			'videoPressStats' => Jetpack_Constants::is_true( 'JETPACK_MY_JETPACK_VIDEOPRESS_STATS_ENABLED' ),
		);

		return $flags;
	}

	/**
	 * Echoes the admin page content.
	 *
	 * @return void
	 */
	public static function admin_page() {
		echo '<div id="my-jetpack-container"></div>';
	}

	/**
	 * Register the REST API routes.
	 *
	 * @return void
	 */
	public static function register_rest_endpoints() {
		new REST_Products();
		new REST_Purchases();

		register_rest_route(
			'my-jetpack/v1',
			'site',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_site',
				'permission_callback' => __CLASS__ . '::permissions_callback',
			)
		);
	}

	/**
	 * Check user capability to access the endpoint.
	 *
	 * @access public
	 * @static
	 *
	 * @return true|WP_Error
	 */
	public static function permissions_callback() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Return true if we should initialize the My Jetpack admin page.
	 */
	public static function should_initialize() {
		$should = true;

		if ( is_multisite() ) {
			$should = false;
		}

		/**
		 * Allows filtering whether My Jetpack should be initialized.
		 *
		 * @since 0.5.0-alpha
		 *
		 * @param bool $shoud_initialize Should we initialize My Jetpack?
		 */
		return apply_filters( 'jetpack_my_jetpack_should_initialize', $should );
	}

	/**
	 * Site full-data endpoint.
	 *
	 * @return object Site data.
	 */
	public static function get_site() {
		$site_id           = \Jetpack_Options::get_option( 'id' );
		$wpcom_endpoint    = sprintf( '/sites/%d?force=wpcom', $site_id );
		$wpcom_api_version = '1.1';
		$response          = Client::wpcom_json_api_request_as_blog( $wpcom_endpoint, $wpcom_api_version );
		$response_code     = wp_remote_retrieve_response_code( $response );
		$body              = json_decode( wp_remote_retrieve_body( $response ) );

		if ( is_wp_error( $response ) || empty( $response['body'] ) ) {
			return new \WP_Error( 'site_data_fetch_failed', 'Site data fetch failed', array( 'status' => $response_code ) );
		}

		return rest_ensure_response( $body, 200 );
	}

	/**
	 * Returns true if the site has file write access to the plugins folder, false otherwise.
	 *
	 * @return bool
	 **/
	public static function has_file_system_write_access() {

		$cache = get_transient( 'my_jetpack_write_access' );

		if ( false !== $cache ) {
			return $cache;
		}

		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		require_once ABSPATH . 'wp-admin/includes/template.php';

		$write_access = 'no';

		$filesystem_method = get_filesystem_method( array(), WP_PLUGIN_DIR );
		if ( 'direct' === $filesystem_method ) {
			$write_access = 'yes';
		}

		if ( ! $write_access ) {
			ob_start();
			$filesystem_credentials_are_stored = request_filesystem_credentials( self_admin_url() );
			ob_end_clean();

			if ( $filesystem_credentials_are_stored ) {
				$write_access = 'yes';
			}
		}

		set_transient( 'my_jetpack_write_access', $write_access, 30 * MINUTE_IN_SECONDS );

		return $write_access;
	}

}
