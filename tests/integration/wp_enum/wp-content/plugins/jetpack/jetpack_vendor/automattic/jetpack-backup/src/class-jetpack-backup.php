<?php
/**
 * Primary class file for the Jetpack Backup plugin.
 *
 * @package automattic/jetpack-backup-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Automattic\Jetpack\Admin_UI\Admin_Menu;
use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Backup\Initial_State as Backup_Initial_State;
use Automattic\Jetpack\Backup\Jetpack_Backup_Upgrades;
use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Initial_State as Connection_Initial_State;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Connection\Rest_Authentication as Connection_Rest_Authentication;
use Automattic\Jetpack\My_Jetpack\Wpcom_Products;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Terms_Of_Service;
use Automattic\Jetpack\Tracking;

/**
 * Class Jetpack_Backup
 */
class Jetpack_Backup {

	/**
	 * Slug.
	 *
	 * @var string
	 */
	const JETPACK_BACKUP_SLUG = 'jetpack-backup';

	/**
	 * Backup name.
	 *
	 * @var string
	 */
	const JETPACK_BACKUP_NAME = 'Jetpack Backup';

	/**
	 * Backup URL.
	 *
	 * @var string
	 */
	const JETPACK_BACKUP_URI = 'https://jetpack.com/jetpack-backup';

	/**
	 * Promoted product.
	 *
	 * @var string
	 */
	const JETPACK_BACKUP_PROMOTED_PRODUCT = 'jetpack_backup_t1_yearly';

	/**
	 * Licenses product ID.
	 *
	 * @var string
	 */
	const JETPACK_BACKUP_PRODUCT_IDS = array(
		2014, // JETPACK_COMPLETE.
		2015, // JETPACK_COMPLETE_MONTHLY.
		2016, // JETPACK_SECURITY_TIER_1_YEARLY.
		2017, // JETPACK_SECURITY_TIER_1_MONTHLY.
		2019, // JETPACK_SECURITY_TIER_2_YEARLY.
		2020, // JETPACK_SECURITY_TIER_2_MONTHLY.
		2112, // JETPACK_BACKUP_TIER_1_YEARLY.
		2113, // JETPACK_BACKUP_TIER_1_MONTHLY.
		2114, // JETPACK_BACKUP_TIER_2_YEARLY.
		2115, // JETPACK_BACKUP_TIER_2_MONTHLY.
	);

	/**
	 * Jetpack Backup DB version.
	 *
	 * @var string
	 */
	const JETPACK_BACKUP_DB_VERSION = '2';

	/**
	 * Constructor.
	 */
	public static function initialize() {
		if ( did_action( 'jetpack_backup_initialized' ) ) {
			return;
		}

		// Set up the REST authentication hooks.
		Connection_Rest_Authentication::init();

		add_action( 'rest_api_init', array( __CLASS__, 'register_rest_routes' ) );

		$page_suffix = Admin_Menu::add_menu(
			__( 'Jetpack VaultPress Backup', 'jetpack-backup-pkg' ),
			_x( 'VaultPress Backup', 'The Jetpack VaultPress Backup product name, without the Jetpack prefix', 'jetpack-backup-pkg' ),
			'manage_options',
			'jetpack-backup',
			array( __CLASS__, 'plugin_settings_page' ),
			99
		);
		add_action( 'load-' . $page_suffix, array( __CLASS__, 'admin_init' ) );

		// Init Jetpack packages.
		add_action(
			'plugins_loaded',
			function () {
				$config = new Automattic\Jetpack\Config();
				// Connection package.
				$config->ensure(
					'connection',
					array(
						'slug'     => self::JETPACK_BACKUP_SLUG,
						'name'     => self::JETPACK_BACKUP_NAME,
						'url_info' => self::JETPACK_BACKUP_URI,
					)
				);
				// Sync package.
				$config->ensure( 'sync' );

				// Identity crisis package.
				$config->ensure( 'identity_crisis' );
			},
			1
		);

		add_action( 'plugins_loaded', array( __CLASS__, 'maybe_upgrade_db' ), 20 );

		add_filter( 'jetpack_connection_user_has_license', array( __CLASS__, 'jetpack_check_user_licenses' ), 10, 3 );

		/**
		 * Runs right after the Jetpack Backup package is initialized.
		 *
		 * @since 1.3.0
		 */
		do_action( 'jetpack_backup_initialized' );
	}

	/**
	 * Initialize the admin resources.
	 */
	public static function admin_init() {
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_admin_scripts' ) );
	}

	/**
	 * Checks current version against version in code and run upgrades if we are running a new version
	 */
	public static function maybe_upgrade_db() {
		$current_db_version = get_option( 'jetpack_backup_db_version' );
		if ( version_compare( $current_db_version, self::JETPACK_BACKUP_DB_VERSION, '<' ) ) {
			update_option( 'jetpack_backup_db_version', self::JETPACK_BACKUP_DB_VERSION );
			Jetpack_Backup_Upgrades::upgrade();
		}
	}

	/**
	 * Returns whether we are in condition to track to use
	 * Analytics functionality like Tracks, MC, or GA.
	 */
	public static function can_use_analytics() {
		$status     = new Status();
		$connection = new Connection_Manager( 'jetpack-backup' );
		$tracking   = new Tracking( 'jetpack', $connection );

		return $tracking->should_enable_tracking( new Terms_Of_Service(), $status );
	}

	/**
	 * Enqueue plugin admin scripts and styles.
	 */
	public static function enqueue_admin_scripts() {
		Assets::register_script(
			'jetpack-backup',
			'../build/index.js',
			__FILE__,
			array(
				'in_footer'  => true,
				'textdomain' => 'jetpack-backup-pkg',
			)
		);
		Assets::enqueue_script( 'jetpack-backup' );
		// Initial JS state including JP Connection data.
		wp_add_inline_script( 'jetpack-backup', self::get_initial_state(), 'before' );
		wp_add_inline_script( 'jetpack-backup', Connection_Initial_State::render(), 'before' );

		// Load script for analytics.
		if ( self::can_use_analytics() ) {
			Tracking::register_tracks_functions_scripts( true );
		}
	}

	/**
	 * Main plugin settings page.
	 */
	public static function plugin_settings_page() {
		?>
			<div id="jetpack-backup-root"></div>
		<?php
	}

	/**
	 * Return the rendered initial state JavaScript code.
	 *
	 * @return string
	 */
	private static function get_initial_state() {
		return ( new Backup_Initial_State() )->render();
	}

	/**
	 * Register REST API
	 */
	public static function register_rest_routes() {

		// Get information on most recent 10 backups.
		register_rest_route(
			'jetpack/v4',
			'/backups',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_recent_backups',
				'permission_callback' => __CLASS__ . '::backups_permissions_callback',
			)
		);

		// Get site backup/scan/anti-spam capabilities.
		register_rest_route(
			'jetpack/v4',
			'/backup-capabilities',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_backup_capabilities',
				'permission_callback' => __CLASS__ . '::backups_permissions_callback',
			)
		);

		// Get whether the site has a backup plan
		register_rest_route(
			'jetpack/v4',
			'/has-backup-plan',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::has_backup_plan',
				'permission_callback' => __CLASS__ . '::backups_permissions_callback',
			)
		);

		// Get site rewind data.
		register_rest_route(
			'jetpack/v4',
			'/restores',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_recent_restores',
				'permission_callback' => __CLASS__ . '::backups_permissions_callback',
			)
		);

		// Get information on site products.
		// Backup plugin version of /site/purchases from JP plugin.
		// Revert once this route and MyPlan component are extracted to a common package.
		register_rest_route(
			'jetpack/v4',
			'/site/current-purchases',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_site_current_purchases',
				'permission_callback' => __CLASS__ . '::backups_permissions_callback',
			)
		);

		// Get currently promoted product from the product's endpoint.
			register_rest_route(
				'jetpack/v4',
				'/backup-promoted-product-info',
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => __CLASS__ . '::get_backup_promoted_product_info',
					'permission_callback' => __CLASS__ . '::backups_permissions_callback',
				)
			);

		// Get and set value of dismissed_backup_review_request option
		register_rest_route(
			'jetpack/v4',
			'/site/dismissed-review-request',
			array(
				'methods'             => \WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::manage_dismissed_backup_review_request',
				'permission_callback' => __CLASS__ . '::backups_permissions_callback',
				'args'                => array(
					'option_name'    => array(
						'required' => true,
						'type'     => 'string',
					),
					'should_dismiss' => array(
						'required' => true,
						'type'     => 'boolean',
					),
				),
			)
		);

		// Get site size
		register_rest_route(
			'jetpack/v4',
			'/site/backup/size',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_site_backup_size',
				'permission_callback' => __CLASS__ . '::backups_permissions_callback',
			)
		);

		// Get site policies
		register_rest_route(
			'jetpack/v4',
			'/site/backup/policies',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_site_backup_policies',
				'permission_callback' => __CLASS__ . '::backups_permissions_callback',
			)
		);

		// Get site add-on offer
		register_rest_route(
			'jetpack/v4',
			'/site/backup/addon-offer',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_site_backup_addon_offer',
				'permission_callback' => __CLASS__ . '::backups_permissions_callback',
				'args'                => array(
					'storage_size'  => array(
						'required' => true,
						'type'     => 'numeric',
					),
					'storage_limit' => array(
						'required' => true,
						'type'     => 'numeric',
					),
				),
			)
		);
	}

	/**
	 * The backup calls should only occur from a signed in admin user
	 *
	 * @access public
	 * @static
	 *
	 * @return true|WP_Error
	 */
	public static function backups_permissions_callback() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Get information about recent backups
	 *
	 * @access public
	 * @static
	 *
	 * @return array An array of recent backups
	 */
	public static function get_recent_backups() {
		$blog_id = \Jetpack_Options::get_option( 'id' );

		$response = Automattic\Jetpack\Connection\Client::wpcom_json_api_request_as_blog(
			'/sites/' . $blog_id . '/rewind/backups',
			'v2',
			array(),
			null,
			'wpcom'
		);

		if ( 200 !== $response['response']['code'] ) {
			return null;
		}

		return rest_ensure_response(
			json_decode( $response['body'], true )
		);
	}

	/**
	 * Hits the wpcom api to check rewind status.
	 *
	 * @return Object|WP_Error
	 */
	private static function get_rewind_state_from_wpcom() {
		static $status = null;

		if ( $status !== null ) {
			return $status;
		}

		$site_id = Jetpack_Options::get_option( 'id' );

		$response = Client::wpcom_json_api_request_as_blog( sprintf( '/sites/%d/rewind', $site_id ) . '?force=wpcom', '2', array( 'timeout' => 2 ), null, 'wpcom' );

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'rewind_state_fetch_failed' );
		}

		$body   = wp_remote_retrieve_body( $response );
		$status = json_decode( $body );
		return $status;
	}

	/**
	 * Checks whether the current plan (or purchases) of the site already supports the product
	 *
	 * @return boolean
	 */
	public static function has_backup_plan() {
		$rewind_data = static::get_rewind_state_from_wpcom();
		if ( is_wp_error( $rewind_data ) ) {
			return false;
		}
		return is_object( $rewind_data ) && isset( $rewind_data->state ) && 'unavailable' !== $rewind_data->state;
	}

	/**
	 * Get an array of backup/scan/anti-spam site capabilities
	 *
	 * @access public
	 * @static
	 *
	 * @return array An array of capabilities
	 */
	public static function get_backup_capabilities() {
		$blog_id = \Jetpack_Options::get_option( 'id' );

		$response = Automattic\Jetpack\Connection\Client::wpcom_json_api_request_as_user(
			'/sites/' . $blog_id . '/rewind/capabilities',
			'v2',
			array(),
			null,
			'wpcom'
		);

		if ( is_wp_error( $response ) ) {
			return null;
		}

		if ( 200 !== $response['response']['code'] ) {
			return null;
		}

		return rest_ensure_response(
			json_decode( $response['body'], true )
		);
	}

	/**
	 * Get information about recent restores
	 *
	 * @access public
	 * @static
	 *
	 * @return array An array of recent restores
	 */
	public static function get_recent_restores() {
		$blog_id  = \Jetpack_Options::get_option( 'id' );
		$response = Automattic\Jetpack\Connection\Client::wpcom_json_api_request_as_blog(
			'/sites/' . $blog_id . '/rewind/restores',
			'v2',
			array(),
			null,
			'wpcom'
		);

		if ( 200 !== $response['response']['code'] ) {
			return null;
		}

		return rest_ensure_response(
			json_decode( $response['body'], true )
		);
	}

	/**
	 * Gets information about the currently promoted backup product.
	 *
	 * @return string|WP_Error A JSON object of the current backup product being promoted if the request was successful, or a WP_Error otherwise.
	 */
	public static function get_backup_promoted_product_info() {
		$request_url   = 'https://public-api.wordpress.com/rest/v1.1/products?locale=' . get_user_locale() . '&type=jetpack';
		$wpcom_request = wp_remote_get( esc_url_raw( $request_url ) );
		$response_code = wp_remote_retrieve_response_code( $wpcom_request );
		if ( 200 === $response_code ) {
			$products = json_decode( wp_remote_retrieve_body( $wpcom_request ) );
			return $products->{self::JETPACK_BACKUP_PROMOTED_PRODUCT};
		} else {
			// Something went wrong so we'll just return the response without caching.
			return new WP_Error(
				'failed_to_fetch_data',
				esc_html__( 'Unable to fetch the requested data.', 'jetpack-backup-pkg' ),
				array(
					'status'  => $response_code,
					'request' => $wpcom_request,
				)
			);
		}
	}

	/**
	 * Check for user licenses.
	 *
	 * @param boolean $has_license If the user already has a license found.
	 * @param array   $licenses List of unattached licenses belonging to the user.
	 * @param string  $plugin_slug The plugin that initiated the flow.
	 *
	 * @return boolean
	 */
	public static function jetpack_check_user_licenses( $has_license, $licenses, $plugin_slug ) {
		if ( $plugin_slug !== static::JETPACK_BACKUP_SLUG || $has_license ) {
			return $has_license;
		}

		$license_found = false;

		foreach ( $licenses as $license ) {
			if ( in_array( $license->product_id, static::JETPACK_BACKUP_PRODUCT_IDS, true ) ) {
				$license_found = true;
				break;
			}
		}

		// Checking for existing backup plan is costly, so only check if there's an appropriate license.
		return $license_found && ! static::has_backup_plan();
	}

	/**
	 * Returns the result of `/sites/%d/purchases` endpoint call.
	 *
	 * @return array of site purchases.
	 */
	public static function get_site_current_purchases() {

		$request  = sprintf( '/sites/%d/purchases', \Jetpack_Options::get_option( 'id' ) );
		$response = Automattic\Jetpack\Connection\Client::wpcom_json_api_request_as_blog( $request, '1.1' );

		// Bail if there was an error or malformed response.
		if ( is_wp_error( $response ) || ! is_array( $response ) || ! isset( $response['body'] ) ) {
			return self::get_failed_fetch_error();
		}

		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return self::get_failed_fetch_error();
		}

		return rest_ensure_response(
			json_decode( $response['body'], true )
		);
	}

	/**
	 * Set value of the dismissed_backup_review_request Jetack option.
	 * Get value if should_dismiss is false
	 *
	 * @access public
	 * @static
	 * @param array $request arguments should_dismiss and option_name.
	 * @return bool value of option if value is requested | updated or not if value is updated.
	 */
	public static function manage_dismissed_backup_review_request( $request ) {

		if ( ! $request['should_dismiss'] ) {

			return rest_ensure_response(
				\Jetpack_Options::get_option( 'dismissed_backup_review_' . $request['option_name'] )
			);
		}

		return \Jetpack_Options::update_option( 'dismissed_backup_review_' . $request['option_name'], true );
	}

	/**
	 * Get site storage size
	 *
	 * @return string|WP_Error A JSON object with the site storage size if the request was successful, or a WP_Error otherwise.
	 */
	public static function get_site_backup_size() {
		$blog_id = \Jetpack_Options::get_option( 'id' );

		$response = Automattic\Jetpack\Connection\Client::wpcom_json_api_request_as_user(
			'/sites/' . $blog_id . '/rewind/size?force=wpcom',
			'v2',
			array(),
			null,
			'wpcom'
		);

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		return rest_ensure_response(
			json_decode( $response['body'], true )
		);
	}

	/**
	 * Get site policies from WPCOM. It includes the storage limit and activity log limit, if apply.
	 *
	 * @return string|WP_Error A JSON object with the site storage policies if the request was successful,
	 *                         or a WP_Error otherwise.
	 */
	public static function get_site_backup_policies() {
		$blog_id = \Jetpack_Options::get_option( 'id' );

		$response = Automattic\Jetpack\Connection\Client::wpcom_json_api_request_as_user(
			'/sites/' . $blog_id . '/rewind/policies?force=wpcom',
			'v2',
			array(),
			null,
			'wpcom'
		);

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		return rest_ensure_response(
			json_decode( $response['body'], true )
		);
	}

	/**
	 * Get suggested storage addon based on storage usage
	 *
	 * @param int $bytes_used      Storage used.
	 * @param int $bytes_available Storage limit.
	 * @return string Suggested addon storage slug
	 */
	public static function get_storage_addon_upsell_slug( $bytes_used, $bytes_available ) {
		$bytes_10gb  = 10 * 1024 * 1024 * 1024; // 10GB in bytes
		$bytes_100gb = 100 * 1024 * 1024 * 1024; // 100GB in bytes
		$bytes_1tb   = 1024 * 1024 * 1024 * 1024; // 1TB in bytes

		$upsell_products = array(
			$bytes_10gb  => 'jetpack_backup_addon_storage_10gb_monthly',
			$bytes_100gb => 'jetpack_backup_addon_storage_100gb_monthly',
			$bytes_1tb   => 'jetpack_backup_addon_storage_1tb_monthly',
		);

		// If usage has crossed over the storage limit, then dynamically calculate the upgrade option
		if ( $bytes_used > $bytes_available ) {
			$additional_bytes_used = $bytes_used - $bytes_available;

			// Add aditional 25% buffer
			$additional_bytes_needed = $additional_bytes_used + $additional_bytes_used * 0.25;

			// Since 1TB is our max upgrade but the additional storage needed is greater than 1TB, then just return 1TB
			if ( $additional_bytes_needed > $bytes_1tb ) {
				return $upsell_products[ $bytes_1tb ];
			}

			foreach ( $upsell_products as $bytes => $product ) {
				if ( $bytes > $additional_bytes_needed ) {
					$matched_bytes = $bytes;
					break;
				}
			}

			if ( ! $matched_bytes ) {
				$matched_bytes = $bytes_10gb;
			}

			return $upsell_products[ $matched_bytes ];
		}

		// For 1 TB we are going to offer 1 TB by default
		if ( $bytes_1tb === $bytes_available ) {
			return $upsell_products[ $bytes_1tb ];
		}

		// Otherwise, we are going to offer 10 GB
		return $upsell_products[ $bytes_10gb ];
	}

	/**
	 * Get the best addon offer for this site, including pricing details
	 *
	 * @param WP_Request $request Object including storage usage.
	 * @return string|WP_Error A JSON object with the suggested storage addon details if the request was successful,
	 *                         or a WP_Error otherwise.
	 */
	public static function get_site_backup_addon_offer( $request ) {
		$suggested_addon = self::get_storage_addon_upsell_slug(
			$request['storage_size'],
			$request['storage_limit']
		);

		$addons_size_text_map = array(
			'jetpack_backup_addon_storage_10gb_monthly'  => '10GB',
			'jetpack_backup_addon_storage_100gb_monthly' => '100GB',
			'jetpack_backup_addon_storage_1tb_monthly'   => '1TB',
		);

		// Fetch addon storage price information
		$pricing_info = Wpcom_Products::get_product_pricing( $suggested_addon );

		// Response
		$response = array(
			'slug'      => $suggested_addon,
			'size_text' => $addons_size_text_map[ $suggested_addon ],
			'pricing'   => $pricing_info,
		);

		return rest_ensure_response( $response );
	}

	/**
	 * Removes plugin from the connection manager
	 * If it's the last plugin using the connection, the site will be disconnected.
	 *
	 * @access public
	 * @static
	 */
	public static function plugin_deactivation() {
		$manager = new Connection_Manager( 'jetpack-backup' );
		$manager->remove_connection();
	}

}
