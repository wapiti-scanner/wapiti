<?php
/**
 * A class that defines syncable actions for Jetpack.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use Automattic\Jetpack\Connection\Manager as Jetpack_Connection;
use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Identity_Crisis;
use Automattic\Jetpack\Status;
use WP_Error;

/**
 * The role of this class is to hook the Sync subsystem into WordPress - when to listen for actions,
 * when to send, when to perform a full sync, etc.
 *
 * It also binds the action to send data to WPCOM to Jetpack's XMLRPC client object.
 */
class Actions {

	/**
	 * Name of the retry-after option prefix.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const RETRY_AFTER_PREFIX = 'jp_sync_retry_after_';

	/**
	 * Name of the error log option prefix.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const ERROR_LOG_PREFIX = 'jp_sync_error_log_';

	/**
	 * Name of the last successful sync option prefix.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const LAST_SUCCESS_PREFIX = 'jp_sync_last_success_';

	/**
	 * A variable to hold a sync sender object.
	 *
	 * @access public
	 * @static
	 *
	 * @var Automattic\Jetpack\Sync\Sender
	 */
	public static $sender = null;

	/**
	 * A variable to hold a sync listener object.
	 *
	 * @access public
	 * @static
	 *
	 * @var Automattic\Jetpack\Sync\Listener
	 */
	public static $listener = null;

	/**
	 * Name of the sync cron schedule.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const DEFAULT_SYNC_CRON_INTERVAL_NAME = 'jetpack_sync_interval';

	/**
	 * Interval between the last and the next sync cron action.
	 *
	 * @access public
	 *
	 * @var int
	 */
	const DEFAULT_SYNC_CRON_INTERVAL_VALUE = 300; // 5 * MINUTE_IN_SECONDS;

	/**
	 * Initialize Sync for cron jobs, set up listeners for WordPress Actions,
	 * and set up a shut-down action for sending actions to WordPress.com
	 * If dedicated Sync is enabled and this is a dedicated Sync request
	 * up an init action for sending actions to WordPress.com instead.
	 *
	 * @access public
	 * @static
	 */
	public static function init() {
		// Everything below this point should only happen if we're a valid sync site.
		if ( ! self::sync_allowed() ) {
			return;
		}

		// If dedicated Sync is enabled and this is a dedicated Sync request, no need to
		// initialize Sync for cron jobs or set up a shut-down action for sending actions to WordPress.com.
		// We only need to set up an init action for sending actions to WordPress.com and exit early.
		// Note: We also need to initialize the listener so that callable and constant changes, eg actions that
		// rely on 'jetpack_sync_before_send_queue_sync' are picked up and added to the queue if needed.
		if ( Settings::is_dedicated_sync_enabled() && Dedicated_Sender::is_dedicated_sync_request() ) {
			self::initialize_listener();
			add_action( 'init', array( __CLASS__, 'add_dedicated_sync_sender_init' ), 90 );
			return;
		}

		if ( self::sync_via_cron_allowed() ) {
			self::init_sync_cron_jobs();
		} elseif ( wp_next_scheduled( 'jetpack_sync_cron' ) ) {
			self::clear_sync_cron_jobs();
		}
		// When importing via cron, do not sync.
		add_action( 'wp_cron_importer_hook', array( __CLASS__, 'set_is_importing_true' ), 1 );

		// Sync connected user role changes to WordPress.com.
		Users::init();

		// Publicize filter to prevent publicizing blacklisted post types.
		add_filter( 'publicize_should_publicize_published_post', array( __CLASS__, 'prevent_publicize_blacklisted_posts' ), 10, 2 );

		/**
		 * Fires on every request before default loading sync listener code.
		 * Return false to not load sync listener code that monitors common
		 * WP actions to be serialized.
		 *
		 * By default this returns true for cron jobs, non-GET-requests, or requests where the
		 * user is logged-in.
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param bool should we load sync listener code for this request
		 */
		if ( apply_filters( 'jetpack_sync_listener_should_load', true ) ) {
			self::initialize_listener();
		}

		add_action( 'init', array( __CLASS__, 'add_sender_shutdown' ), 90 );
	}

	/**
	 * Prepares sync to send actions on shutdown for the current request.
	 *
	 * @access public
	 * @static
	 */
	public static function add_sender_shutdown() {
		/**
		 * Fires on every request before default loading sync sender code.
		 * Return false to not load sync sender code that serializes pending
		 * data and sends it to WPCOM for processing.
		 *
		 * By default this returns true for cron jobs, POST requests, admin requests, or requests
		 * by users who can manage_options.
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param bool should we load sync sender code for this request
		 */
		if ( apply_filters(
			'jetpack_sync_sender_should_load',
			self::should_initialize_sender()
		) ) {
			self::initialize_sender();
			add_action( 'shutdown', array( self::$sender, 'do_sync' ), 9998 );
			add_action( 'shutdown', array( self::$sender, 'do_full_sync' ), 9999 );
		}
	}

	/**
	 * Immediately sends actions on init for the current dedicated Sync request.
	 *
	 * @access public
	 * @static
	 */
	public static function add_dedicated_sync_sender_init() {
		if ( apply_filters(
			'jetpack_sync_sender_should_load',
			true
		) ) {
			self::initialize_sender();
			self::$sender->do_dedicated_sync_and_exit();
		}
	}

	/**
	 * Define JETPACK_SYNC_READ_ONLY constant if not defined.
	 * This notifies sync to not run in shutdown if it was initialized during init.
	 *
	 * @access public
	 * @static
	 */
	public static function mark_sync_read_only() {
		Constants::set_constant( 'JETPACK_SYNC_READ_ONLY', true );
	}

	/**
	 * Decides if the sender should run on shutdown for this request.
	 *
	 * @access public
	 * @static
	 *
	 * @return bool
	 */
	public static function should_initialize_sender() {

		// Allow for explicit disable of Sync from request param jetpack_sync_read_only.
		if ( isset( $_REQUEST['jetpack_sync_read_only'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			self::mark_sync_read_only();
			return false;
		}

		if ( Constants::is_true( 'DOING_CRON' ) ) {
			return self::sync_via_cron_allowed();
		}

		/**
		 * For now, if dedicated Sync is enabled we will always initialize send, even for GET and unauthenticated requests.
		 */
		if ( Settings::is_dedicated_sync_enabled() ) {
			return true;
		}

		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			return true;
		}

		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		if ( is_admin() ) {
			return true;
		}

		if ( defined( 'PHPUNIT_JETPACK_TESTSUITE' ) ) {
			return true;
		}

		if ( Constants::get_constant( 'WP_CLI' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Decides if the sender should run on shutdown when actions are queued.
	 *
	 * @access public
	 * @static
	 *
	 * @param bool $enable Should we initilize sender.
	 * @return bool
	 */
	public static function should_initialize_sender_enqueue( $enable ) {

		// If $enabled is false don't modify it, only check cron if enabled.
		if ( false === $enable ) {
			return $enable;
		}

		if ( Constants::is_true( 'DOING_CRON' ) ) {
			return self::sync_via_cron_allowed();
		}

		return true;
	}

	/**
	 * Decides if sync should run at all during this request.
	 *
	 * @access public
	 * @static
	 *
	 * @return bool
	 */
	public static function sync_allowed() {
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			return false;
		}

		if ( defined( 'PHPUNIT_JETPACK_TESTSUITE' ) ) {
			return true;
		}

		if ( ! Settings::is_sync_enabled() ) {
			return false;
		}

		if ( ( new Status() )->is_offline_mode() ) {
			return false;
		}

		if ( ( new Status() )->is_staging_site() ) {
			return false;
		}

		$connection = new Jetpack_Connection();
		if ( ! $connection->is_connected() ) {
			if ( ! doing_action( 'jetpack_site_registered' ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Helper function to get details as to why sync is not allowed, if it is not allowed.
	 *
	 * @return array
	 */
	public static function get_debug_details() {
		$debug                                  = array();
		$debug['debug_details']['sync_allowed'] = self::sync_allowed();
		$debug['debug_details']['sync_health']  = Health::get_status();
		if ( false === $debug['debug_details']['sync_allowed'] ) {
			if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
				$debug['debug_details']['is_wpcom'] = true;
			}
			if ( defined( 'PHPUNIT_JETPACK_TESTSUITE' ) ) {
				$debug['debug_details']['PHPUNIT_JETPACK_TESTSUITE'] = true;
			}
			if ( ! Settings::is_sync_enabled() ) {
				$debug['debug_details']['is_sync_enabled']              = false;
				$debug['debug_details']['jetpack_sync_disable']         = Settings::get_setting( 'disable' );
				$debug['debug_details']['jetpack_sync_network_disable'] = Settings::get_setting( 'network_disable' );
			}
			if ( ( new Status() )->is_offline_mode() ) {
				$debug['debug_details']['is_offline_mode'] = true;
			}
			if ( ( new Status() )->is_staging_site() ) {
				$debug['debug_details']['is_staging_site'] = true;
			}
			$connection = new Jetpack_Connection();
			if ( ! $connection->is_connected() ) {
				$debug['debug_details']['active_connection'] = false;
			}
		}

		// Sync locks.
		$debug['debug_details']['dedicated_sync_enabled'] = Settings::is_dedicated_sync_enabled();

		$queue      = self::$sender->get_sync_queue();
		$full_queue = self::$sender->get_full_sync_queue();

		$debug['debug_details']['sync_locks'] = array(
			'retry_time_sync'                       => get_option( self::RETRY_AFTER_PREFIX . 'sync' ),
			'retry_time_full_sync'                  => get_option( self::RETRY_AFTER_PREFIX . 'full_sync' ),
			'next_sync_time_sync'                   => self::$sender->get_next_sync_time( 'sync' ),
			'next_sync_time_full_sync'              => self::$sender->get_next_sync_time( 'full_sync' ),
			'queue_locked_sync'                     => $queue->is_locked(),
			'queue_locked_full_sync'                => $full_queue->is_locked(),
			'dedicated_sync_request_lock'           => \Jetpack_Options::get_raw_option( Dedicated_Sender::DEDICATED_SYNC_REQUEST_LOCK_OPTION_NAME, null ),
			'dedicated_sync_temporary_disable_flag' => get_transient( Dedicated_Sender::DEDICATED_SYNC_TEMPORARY_DISABLE_FLAG ),
		);

		// Sync Logs.
		$debug['debug_details']['last_succesful_sync'] = get_option( self::LAST_SUCCESS_PREFIX . 'sync', '' );
		$debug['debug_details']['sync_error_log']      = get_option( self::ERROR_LOG_PREFIX . 'sync', '' );

		return $debug;
	}

	/**
	 * Determines if syncing during a cron job is allowed.
	 *
	 * @access public
	 * @static
	 *
	 * @return bool|int
	 */
	public static function sync_via_cron_allowed() {
		return ( Settings::get_setting( 'sync_via_cron' ) );
	}

	/**
	 * Decides if the given post should be Publicized based on its type.
	 *
	 * @access public
	 * @static
	 *
	 * @param bool     $should_publicize  Publicize status prior to this filter running.
	 * @param \WP_Post $post              The post to test for Publicizability.
	 * @return bool
	 */
	public static function prevent_publicize_blacklisted_posts( $should_publicize, $post ) {
		if ( in_array( $post->post_type, Settings::get_setting( 'post_types_blacklist' ), true ) ) {
			return false;
		}

		return $should_publicize;
	}

	/**
	 * Set an importing flag to `true` in sync settings.
	 *
	 * @access public
	 * @static
	 */
	public static function set_is_importing_true() {
		Settings::set_importing( true );
	}

	/**
	 * Sends data to WordPress.com via an XMLRPC request.
	 *
	 * @access public
	 * @static
	 *
	 * @param object $data                   Data relating to a sync action.
	 * @param string $codec_name             The name of the codec that encodes the data.
	 * @param float  $sent_timestamp         Current server time so we can compensate for clock differences.
	 * @param string $queue_id               The queue the action belongs to, sync or full_sync.
	 * @param float  $checkout_duration      Time spent retrieving queue items from the DB.
	 * @param float  $preprocess_duration    Time spent converting queue items into data to send.
	 * @param int    $queue_size             The size of the sync queue at the time of processing.
	 * @param string $buffer_id              The ID of the Queue buffer checked out for processing.
	 * @return mixed|WP_Error                The result of the sending request.
	 */
	public static function send_data( $data, $codec_name, $sent_timestamp, $queue_id, $checkout_duration, $preprocess_duration, $queue_size = null, $buffer_id = null ) {

		$query_args = array(
			'sync'           => '1',             // Add an extra parameter to the URL so we can tell it's a sync action.
			'codec'          => $codec_name,
			'timestamp'      => $sent_timestamp,
			'queue'          => $queue_id,
			'cd'             => sprintf( '%.4f', $checkout_duration ),
			'pd'             => sprintf( '%.4f', $preprocess_duration ),
			'queue_size'     => $queue_size,
			'buffer_id'      => $buffer_id,
			// TODO this will be extended in the future. Might be good to extract in a separate method to support future entries too.
			'sync_flow_type' => Settings::is_dedicated_sync_enabled() ? 'dedicated' : 'default',
		);

		$query_args['timeout'] = Settings::is_doing_cron() ? 30 : 20;

		if ( 'immediate-send' === $queue_id ) {
			$query_args['timeout'] = 30;
		}

		/**
		 * Filters query parameters appended to the Sync request URL sent to WordPress.com.
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.7.0
		 *
		 * @param array $query_args associative array of query parameters.
		 */
		$query_args = apply_filters( 'jetpack_sync_send_data_query_args', $query_args );

		$connection = new Jetpack_Connection();
		$url        = add_query_arg( $query_args, $connection->xmlrpc_api_url() );

		// If we're currently updating to Jetpack 7.7, the IXR client may be missing briefly
		// because since 7.7 it's being autoloaded with Composer.
		if ( ! class_exists( '\\Jetpack_IXR_Client' ) ) {
			return new WP_Error(
				'ixr_client_missing',
				esc_html__( 'Sync has been aborted because the IXR client is missing.', 'jetpack-sync' )
			);
		}

		$rpc = new \Jetpack_IXR_Client(
			array(
				'url'     => $url,
				'timeout' => $query_args['timeout'],
			)
		);

		$result = $rpc->query( 'jetpack.syncActions', $data );

		// Adhere to Retry-After headers.
		$retry_after = $rpc->get_response_header( 'Retry-After' );
		if ( false !== $retry_after ) {
			if ( (int) $retry_after > 0 ) {
				update_option( self::RETRY_AFTER_PREFIX . $queue_id, microtime( true ) + (int) $retry_after, false );
			} else {
				// if unexpected value default to 3 minutes.
				update_option( self::RETRY_AFTER_PREFIX . $queue_id, microtime( true ) + 180, false );
			}
		}

		// Enable/Disable Dedicated Sync flow via response headers.
		$dedicated_sync_header = $rpc->get_response_header( 'Jetpack-Dedicated-Sync' );
		if ( false !== $dedicated_sync_header ) {
			Dedicated_Sender::maybe_change_dedicated_sync_status_from_wpcom_header( $dedicated_sync_header );
		}

		if ( ! $result ) {
			if ( false === $retry_after ) {
				// We received a non standard response from WP.com, lets backoff from sending requests for 1 minute.
				update_option( self::RETRY_AFTER_PREFIX . $queue_id, microtime( true ) + 60, false );
			}
			// Record Sync Errors.
			$error_log = get_option( self::ERROR_LOG_PREFIX . $queue_id, array() );
			if ( ! is_array( $error_log ) ) {
				$error_log = array();
			}
			// Trim existing array to last 4 entries.
			if ( 5 <= count( $error_log ) ) {
				$error_log = array_slice( $error_log, -4, null, true );
			}
			// Add new error indexed to time.
			$error = $rpc->get_jetpack_error();
			$error->add_data( $rpc->get_last_response() );
			$error_log[ (string) microtime( true ) ] = $error;
			// Update the error log.
			update_option( self::ERROR_LOG_PREFIX . $queue_id, $error_log );

			// return request error.
			return $rpc->get_jetpack_error();
		}

		$response = $rpc->getResponse();

		// Check if WordPress.com IDC mitigation blocked the sync request.
		if ( Identity_Crisis::init()->check_response_for_idc( $response ) ) {
			return new WP_Error(
				'sync_error_idc',
				esc_html__( 'Sync has been blocked from WordPress.com because it would cause an identity crisis', 'jetpack-sync' )
			);
		}

		// Record last successful sync.
		update_option( self::LAST_SUCCESS_PREFIX . $queue_id, microtime( true ), false );

		return $response;
	}

	/**
	 * Kicks off the initial sync.
	 *
	 * @access public
	 * @static
	 *
	 * @return bool|null False if sync is not allowed.
	 */
	public static function do_initial_sync() {
		// Let's not sync if we are not supposed to.
		if ( ! self::sync_allowed() ) {
			return false;
		}

		// Don't start new sync if a full sync is in process.
		$full_sync_module = Modules::get_module( 'full-sync' );
		if ( $full_sync_module && $full_sync_module->is_started() && ! $full_sync_module->is_finished() ) {
			return false;
		}

		$initial_sync_config = array(
			'options'         => true,
			'functions'       => true,
			'constants'       => true,
			'users'           => array( get_current_user_id() ),
			'network_options' => true,
		);

		self::do_full_sync( $initial_sync_config );
	}

	/**
	 * Do an initial full sync only if one has not already been started.
	 *
	 * @return bool|null False if the initial full sync was already started, otherwise null.
	 */
	public static function do_only_first_initial_sync() {
		$full_sync_module = Modules::get_module( 'full-sync' );
		if ( $full_sync_module && $full_sync_module->is_started() ) {
			return false;
		}

		static::do_initial_sync();
	}

	/**
	 * Kicks off a full sync.
	 *
	 * @access public
	 * @static
	 *
	 * @param array $modules  The sync modules should be included in this full sync. All will be included if null.
	 * @return bool           True if full sync was successfully started.
	 */
	public static function do_full_sync( $modules = null ) {
		if ( ! self::sync_allowed() ) {
			return false;
		}

		$full_sync_module = Modules::get_module( 'full-sync' );

		if ( ! $full_sync_module ) {
			return false;
		}

		self::initialize_listener();

		$full_sync_module->start( $modules );

		return true;
	}

	/**
	 * Adds a cron schedule for regular syncing via cron, unless the schedule already exists.
	 *
	 * @access public
	 * @static
	 *
	 * @param array $schedules  The list of WordPress cron schedules prior to this filter.
	 * @return array            A list of WordPress cron schedules with the Jetpack sync interval added.
	 */
	public static function jetpack_cron_schedule( $schedules ) {
		if ( ! isset( $schedules[ self::DEFAULT_SYNC_CRON_INTERVAL_NAME ] ) ) {
			$minutes = (int) ( self::DEFAULT_SYNC_CRON_INTERVAL_VALUE / 60 );
			$display = ( 1 === $minutes ) ?
				__( 'Every minute', 'jetpack-sync' ) :
				/* translators: %d is an integer indicating the number of minutes. */
				sprintf( __( 'Every %d minutes', 'jetpack-sync' ), $minutes );
			$schedules[ self::DEFAULT_SYNC_CRON_INTERVAL_NAME ] = array(
				'interval' => self::DEFAULT_SYNC_CRON_INTERVAL_VALUE,
				'display'  => $display,
			);
		}
		return $schedules;
	}

	/**
	 * Starts an incremental sync via cron.
	 *
	 * @access public
	 * @static
	 */
	public static function do_cron_sync() {
		self::do_cron_sync_by_type( 'sync' );
	}

	/**
	 * Starts a full sync via cron.
	 *
	 * @access public
	 * @static
	 */
	public static function do_cron_full_sync() {
		self::do_cron_sync_by_type( 'full_sync' );
	}

	/**
	 * Try to send actions until we run out of things to send,
	 * or have to wait more than 15s before sending again,
	 * or we hit a lock or some other sending issue
	 *
	 * @access public
	 * @static
	 *
	 * @param string $type Sync type. Can be `sync` or `full_sync`.
	 */
	public static function do_cron_sync_by_type( $type ) {
		if ( ! self::sync_allowed() || ( 'sync' !== $type && 'full_sync' !== $type ) ) {
			return;
		}

		self::initialize_sender();

		$time_limit = Settings::get_setting( 'cron_sync_time_limit' );
		$start_time = time();
		$executions = 0;

		do {
			$next_sync_time = self::$sender->get_next_sync_time( $type );

			if ( $next_sync_time ) {
				$delay = $next_sync_time - time() + 1;
				if ( $delay > 15 ) {
					break;
				} elseif ( $delay > 0 ) {
					sleep( $delay );
				}
			}

			// Explicitly only allow 1 do_full_sync call until issue with Immediate Full Sync is resolved.
			// For more context see p1HpG7-9pe-p2.
			if ( 'full_sync' === $type && $executions >= 1 ) {
				break;
			}

			/**
			 * Only try to sync once if Dedicated Sync is enabled. Dedicated Sync has its own requeueing mechanism
			 * that will re-run it if there are items in the queue at the end.
			 */
			if ( 'sync' === $type && $executions >= 1 && Settings::is_dedicated_sync_enabled() ) {
				break;
			}

			$result = 'full_sync' === $type ? self::$sender->do_full_sync() : self::$sender->do_sync();

			// # of send actions performed.
			++$executions;

		} while ( $result && ! is_wp_error( $result ) && ( $start_time + $time_limit ) > time() );

		return $executions;
	}

	/**
	 * Initialize the sync listener.
	 *
	 * @access public
	 * @static
	 */
	public static function initialize_listener() {
		self::$listener = Listener::get_instance();
	}

	/**
	 * Initializes the sync sender.
	 *
	 * @access public
	 * @static
	 */
	public static function initialize_sender() {
		self::$sender = Sender::get_instance();
		add_filter( 'jetpack_sync_send_data', array( __CLASS__, 'send_data' ), 10, 8 );
	}

	/**
	 * Initializes sync for WooCommerce.
	 *
	 * @access public
	 * @static
	 */
	public static function initialize_woocommerce() {
		if ( false === class_exists( 'WooCommerce' ) ) {
			return;
		}
		add_filter( 'jetpack_sync_modules', array( __CLASS__, 'add_woocommerce_sync_module' ) );
	}

	/**
	 * Initializes sync for Instant Search.
	 *
	 * @access public
	 * @static
	 */
	public static function initialize_search() {
		if ( false === class_exists( 'Automattic\\Jetpack\\Search\\Module_Control' ) ) {
			return;
		}
		$search_module = new \Automattic\Jetpack\Search\Module_Control();
		if ( $search_module->is_instant_search_enabled() ) {
			add_filter( 'jetpack_sync_modules', array( __CLASS__, 'add_search_sync_module' ) );
		}
	}

	/**
	 * Add Search updates to Sync Filters.
	 *
	 * @access public
	 * @static
	 *
	 * @param array $sync_modules The list of sync modules declared prior to this filter.
	 * @return array A list of sync modules that now includes Search's modules.
	 */
	public static function add_search_sync_module( $sync_modules ) {
		$sync_modules[] = 'Automattic\\Jetpack\\Sync\\Modules\\Search';
		return $sync_modules;
	}

	/**
	 * Adds Woo's sync modules to existing modules for sending.
	 *
	 * @access public
	 * @static
	 *
	 * @param array $sync_modules The list of sync modules declared prior to this filter.
	 * @return array A list of sync modules that now includes Woo's modules.
	 */
	public static function add_woocommerce_sync_module( $sync_modules ) {
		$sync_modules[] = 'Automattic\\Jetpack\\Sync\\Modules\\WooCommerce';
		return $sync_modules;
	}

	/**
	 * Initializes sync for WP Super Cache.
	 *
	 * @access public
	 * @static
	 */
	public static function initialize_wp_super_cache() {
		if ( false === function_exists( 'wp_cache_is_enabled' ) ) {
			return;
		}
		add_filter( 'jetpack_sync_modules', array( __CLASS__, 'add_wp_super_cache_sync_module' ) );
	}

	/**
	 * Adds WP Super Cache's sync modules to existing modules for sending.
	 *
	 * @access public
	 * @static
	 *
	 * @param array $sync_modules The list of sync modules declared prior to this filer.
	 * @return array A list of sync modules that now includes WP Super Cache's modules.
	 */
	public static function add_wp_super_cache_sync_module( $sync_modules ) {
		$sync_modules[] = 'Automattic\\Jetpack\\Sync\\Modules\\WP_Super_Cache';
		return $sync_modules;
	}

	/**
	 * Sanitizes the name of sync's cron schedule.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $schedule The name of a WordPress cron schedule.
	 * @return string The sanitized name of sync's cron schedule.
	 */
	public static function sanitize_filtered_sync_cron_schedule( $schedule ) {
		$schedule  = sanitize_key( $schedule );
		$schedules = wp_get_schedules();

		// Make sure that the schedule has actually been registered using the `cron_intervals` filter.
		if ( isset( $schedules[ $schedule ] ) ) {
			return $schedule;
		}

		return self::DEFAULT_SYNC_CRON_INTERVAL_NAME;
	}

	/**
	 * Allows offsetting of start times for sync cron jobs.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $schedule The name of a cron schedule.
	 * @param string $hook     The hook that this method is responding to.
	 * @return int The offset for the sync cron schedule.
	 */
	public static function get_start_time_offset( $schedule = '', $hook = '' ) {
		$start_time_offset = is_multisite()
			? wp_rand( 0, ( 2 * self::DEFAULT_SYNC_CRON_INTERVAL_VALUE ) )
			: 0;

		/**
		 * Allows overriding the offset that the sync cron jobs will first run. This can be useful when scheduling
		 * cron jobs across multiple sites in a network.
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.5.0
		 *
		 * @param int    $start_time_offset
		 * @param string $hook
		 * @param string $schedule
		 */
		return (int) apply_filters(
			'jetpack_sync_cron_start_time_offset',
			$start_time_offset,
			$hook,
			$schedule
		);
	}

	/**
	 * Decides if a sync cron should be scheduled.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $schedule The name of a cron schedule.
	 * @param string $hook     The hook that this method is responding to.
	 */
	public static function maybe_schedule_sync_cron( $schedule, $hook ) {
		if ( ! $hook ) {
			return;
		}
		$schedule = self::sanitize_filtered_sync_cron_schedule( $schedule );

		$start_time = time() + self::get_start_time_offset( $schedule, $hook );
		if ( ! wp_next_scheduled( $hook ) ) {
			// Schedule a job to send pending queue items once a minute.
			wp_schedule_event( $start_time, $schedule, $hook );
		} elseif ( wp_get_schedule( $hook ) !== $schedule ) {
			// If the schedule has changed, update the schedule.
			wp_clear_scheduled_hook( $hook );
			wp_schedule_event( $start_time, $schedule, $hook );
		}
	}

	/**
	 * Clears Jetpack sync cron jobs.
	 *
	 * @access public
	 * @static
	 */
	public static function clear_sync_cron_jobs() {
		wp_clear_scheduled_hook( 'jetpack_sync_cron' );
		wp_clear_scheduled_hook( 'jetpack_sync_full_cron' );
	}

	/**
	 * Initializes Jetpack sync cron jobs.
	 *
	 * @access public
	 * @static
	 */
	public static function init_sync_cron_jobs() {
		add_filter( 'cron_schedules', array( __CLASS__, 'jetpack_cron_schedule' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected

		add_action( 'jetpack_sync_cron', array( __CLASS__, 'do_cron_sync' ) );
		add_action( 'jetpack_sync_full_cron', array( __CLASS__, 'do_cron_full_sync' ) );

		/**
		 * Allows overriding of the default incremental sync cron schedule which defaults to once every 5 minutes.
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.3.2
		 *
		 * @param string self::DEFAULT_SYNC_CRON_INTERVAL_NAME
		 */
		$incremental_sync_cron_schedule = apply_filters( 'jetpack_sync_incremental_sync_interval', self::DEFAULT_SYNC_CRON_INTERVAL_NAME );
		self::maybe_schedule_sync_cron( $incremental_sync_cron_schedule, 'jetpack_sync_cron' );

		/**
		 * Allows overriding of the full sync cron schedule which defaults to once every 5 minutes.
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.3.2
		 *
		 * @param string self::DEFAULT_SYNC_CRON_INTERVAL_NAME
		 */
		$full_sync_cron_schedule = apply_filters( 'jetpack_sync_full_sync_interval', self::DEFAULT_SYNC_CRON_INTERVAL_NAME );
		self::maybe_schedule_sync_cron( $full_sync_cron_schedule, 'jetpack_sync_full_cron' );
	}

	/**
	 * Perform maintenance when a plugin upgrade occurs.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $new_version New version of the plugin.
	 * @param string $old_version Old version of the plugin.
	 */
	public static function cleanup_on_upgrade( $new_version = '', $old_version = '' ) {
		if ( wp_next_scheduled( 'jetpack_sync_send_db_checksum' ) ) {
			wp_clear_scheduled_hook( 'jetpack_sync_send_db_checksum' );
		}

		$is_new_sync_upgrade = version_compare( $old_version, '4.2', '>=' );
		if ( ! empty( $old_version ) && $is_new_sync_upgrade && version_compare( $old_version, '4.5', '<' ) ) {
			self::clear_sync_cron_jobs();
			Settings::update_settings(
				array(
					'render_filtered_content' => Defaults::$default_render_filtered_content,
				)
			);
		}

		Health::on_jetpack_upgraded();
	}

	/**
	 * Get syncing status for the given fields.
	 *
	 * @access public
	 * @static
	 *
	 * @param string|null $fields A comma-separated string of the fields to include in the array from the JSON response.
	 * @return array An associative array with the status report.
	 */
	public static function get_sync_status( $fields = null ) {
		self::initialize_sender();

		$sync_module = Modules::get_module( 'full-sync' );
		$queue       = self::$sender->get_sync_queue();

		// _get_cron_array can be false
		$cron_timestamps = ( _get_cron_array() ) ? array_keys( _get_cron_array() ) : array();
		$next_cron       = ( ! empty( $cron_timestamps ) ) ? $cron_timestamps[0] - time() : '';

		$checksums = array();
		$debug     = array();

		if ( ! empty( $fields ) ) {
			$store         = new Replicastore();
			$fields_params = array_map( 'trim', explode( ',', $fields ) );

			if ( in_array( 'posts_checksum', $fields_params, true ) ) {
				$checksums['posts_checksum'] = $store->posts_checksum();
			}
			if ( in_array( 'comments_checksum', $fields_params, true ) ) {
				$checksums['comments_checksum'] = $store->comments_checksum();
			}
			if ( in_array( 'post_meta_checksum', $fields_params, true ) ) {
				$checksums['post_meta_checksum'] = $store->post_meta_checksum();
			}
			if ( in_array( 'comment_meta_checksum', $fields_params, true ) ) {
				$checksums['comment_meta_checksum'] = $store->comment_meta_checksum();
			}

			if ( in_array( 'debug_details', $fields_params, true ) ) {
				$debug = self::get_debug_details();
			}
		}

		$full_sync_status = ( $sync_module ) ? $sync_module->get_status() : array();

		$full_queue = self::$sender->get_full_sync_queue();

		$result = array_merge(
			$full_sync_status,
			$checksums,
			$debug,
			array(
				'cron_size'            => count( $cron_timestamps ),
				'next_cron'            => $next_cron,
				'queue_size'           => $queue->size(),
				'queue_lag'            => $queue->lag(),
				'queue_next_sync'      => ( self::$sender->get_next_sync_time( 'sync' ) - microtime( true ) ),
				'full_queue_next_sync' => ( self::$sender->get_next_sync_time( 'full_sync' ) - microtime( true ) ),
			)
		);

		// Verify $sync_module is not false.
		if ( ( $sync_module ) && false === strpos( get_class( $sync_module ), 'Full_Sync_Immediately' ) ) {
			$result['full_queue_size'] = $full_queue->size();
			$result['full_queue_lag']  = $full_queue->lag();
		}
		return $result;
	}

	/**
	 * Reset Sync locks.
	 *
	 * @access public
	 * @static
	 * @since 1.43.0
	 *
	 * @param bool $unlock_queues Whether to unlock Sync queues. Defaults to true.
	 */
	public static function reset_sync_locks( $unlock_queues = true ) {
		// Next sync locks.
		delete_option( Sender::NEXT_SYNC_TIME_OPTION_NAME . '_sync' );
		delete_option( Sender::NEXT_SYNC_TIME_OPTION_NAME . '_full_sync' );
		delete_option( Sender::NEXT_SYNC_TIME_OPTION_NAME . '_full-sync-enqueue' );
		// Retry after locks.
		delete_option( self::RETRY_AFTER_PREFIX . 'sync' );
		delete_option( self::RETRY_AFTER_PREFIX . 'full_sync' );
		// Dedicated sync locks.
		\Jetpack_Options::delete_raw_option( Dedicated_Sender::DEDICATED_SYNC_REQUEST_LOCK_OPTION_NAME );
		delete_transient( Dedicated_Sender::DEDICATED_SYNC_TEMPORARY_DISABLE_FLAG );

		// Queue locks.
		// Note that we are just unlocking the queues here, not reseting them.
		if ( $unlock_queues ) {
			$sync_queue = new Queue( 'sync' );
			$sync_queue->unlock();

			$full_sync_queue = new Queue( 'full_sync' );
			$full_sync_queue->unlock();
		}
	}
}
