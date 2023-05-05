<?php
/**
 * Sync package.
 *
 * @package  automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use Automattic\Jetpack\Connection\Rest_Authentication;
use WP_Error;
use WP_REST_Server;

/**
 * This class will handle Sync v4 REST Endpoints.
 *
 * @since 1.23.1
 */
class REST_Endpoints {

	/**
	 *  Items pending send.
	 *
	 * @var array
	 */
	public $items = array();

	/**
	 * Initialize REST routes.
	 */
	public static function initialize_rest_api() {

		// Request a Full Sync.
		register_rest_route(
			'jetpack/v4',
			'/sync/full-sync',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::full_sync_start',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
				'args'                => array(
					'modules'  => array(
						'description' => __( 'Data Modules that should be included in Full Sync', 'jetpack-sync' ),
						'type'        => 'array',
						'required'    => false,
					),
					'users'    => array(
						'description' => __( 'User IDs to include in Full Sync or "initial"', 'jetpack-sync' ),
						'required'    => false,
					),
					'posts'    => array(
						'description' => __( 'Post IDs to include in Full Sync', 'jetpack-sync' ),
						'type'        => 'array',
						'required'    => false,
					),
					'comments' => array(
						'description' => __( 'Comment IDs to include in Full Sync', 'jetpack-sync' ),
						'type'        => 'array',
						'required'    => false,
					),
				),
			)
		);

		// Obtain Sync status.
		register_rest_route(
			'jetpack/v4',
			'/sync/status',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::sync_status',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
				'args'                => array(
					'fields' => array(
						'description' => __( 'Comma seperated list of additional fields that should be included in status.', 'jetpack-sync' ),
						'type'        => 'string',
						'required'    => false,
					),
				),
			)
		);

		// Update Sync health status.
		register_rest_route(
			'jetpack/v4',
			'/sync/health',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::sync_health',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
				'args'                => array(
					'status' => array(
						'description' => __( 'New Sync health status', 'jetpack-sync' ),
						'type'        => 'string',
						'required'    => true,
					),
				),
			)
		);

		// Obtain Sync settings.
		register_rest_route(
			'jetpack/v4',
			'/sync/settings',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => __CLASS__ . '::get_sync_settings',
					'permission_callback' => __CLASS__ . '::verify_default_permissions',
				),
				array(
					'methods'             => WP_REST_Server::EDITABLE,
					'callback'            => __CLASS__ . '::update_sync_settings',
					'permission_callback' => __CLASS__ . '::verify_default_permissions',
				),
			)
		);

		// Retrieve Sync Object(s).
		register_rest_route(
			'jetpack/v4',
			'/sync/object',
			array(
				'methods'             => WP_REST_Server::ALLMETHODS,
				'callback'            => __CLASS__ . '::get_sync_objects',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
				'args'                => array(
					'module_name' => array(
						'description' => __( 'Name of Sync module', 'jetpack-sync' ),
						'type'        => 'string',
						'required'    => false,
					),
					'object_type' => array(
						'description' => __( 'Object Type', 'jetpack-sync' ),
						'type'        => 'string',
						'required'    => false,
					),
					'object_ids'  => array(
						'description' => __( 'Objects Identifiers', 'jetpack-sync' ),
						'type'        => 'array',
						'required'    => false,
					),
				),
			)
		);

		// Retrieve Sync Object(s).
		register_rest_route(
			'jetpack/v4',
			'/sync/now',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::do_sync',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
				'args'                => array(
					'queue' => array(
						'description' => __( 'Name of Sync queue.', 'jetpack-sync' ),
						'type'        => 'string',
						'required'    => true,
					),
				),
			)
		);

		// Checkout Sync Objects.
		register_rest_route(
			'jetpack/v4',
			'/sync/checkout',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::checkout',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
			)
		);

		// Checkin Sync Objects.
		register_rest_route(
			'jetpack/v4',
			'/sync/close',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::close',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
			)
		);

		// Unlock Sync Queue.
		register_rest_route(
			'jetpack/v4',
			'/sync/unlock',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::unlock_queue',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
				'args'                => array(
					'queue' => array(
						'description' => __( 'Name of Sync queue.', 'jetpack-sync' ),
						'type'        => 'string',
						'required'    => true,
					),
				),
			)
		);

		// Retrieve range of Object Ids.
		register_rest_route(
			'jetpack/v4',
			'/sync/object-id-range',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_object_id_range',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
				'args'                => array(
					'sync_module' => array(
						'description' => __( 'Name of Sync module.', 'jetpack-sync' ),
						'type'        => 'string',
						'required'    => true,
					),
					'batch_size'  => array(
						'description' => __( 'Size of batches', 'jetpack-sync' ),
						'type'        => 'int',
						'required'    => true,
					),
				),
			)
		);

		// Obtain table checksums.
		register_rest_route(
			'jetpack/v4',
			'/sync/data-check',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::data_check',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
				'args'                => array(
					'perform_text_conversion' => array(
						'description' => __( 'If text fields should be converted to latin1 in checksum calculation.', 'jetpack-sync' ),
						'type'        => 'boolean',
						'required'    => false,
					),
				),
			)
		);

		// Obtain histogram.
		register_rest_route(
			'jetpack/v4',
			'/sync/data-histogram',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::data_histogram',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
				'args'                => array(
					'columns'                 => array(
						'description' => __( 'Column mappings', 'jetpack-sync' ),
						'type'        => 'array',
						'required'    => false,
					),
					'object_type'             => array(
						'description' => __( 'Object Type', 'jetpack-sync' ),
						'type'        => 'string',
						'required'    => false,
					),
					'buckets'                 => array(
						'description' => __( 'Number of histogram buckets.', 'jetpack-sync' ),
						'type'        => 'int',
						'required'    => false,
					),
					'start_id'                => array(
						'description' => __( 'Start ID for the histogram', 'jetpack-sync' ),
						'type'        => 'int',
						'required'    => false,
					),
					'end_id'                  => array(
						'description' => __( 'End ID for the histogram', 'jetpack-sync' ),
						'type'        => 'int',
						'required'    => false,
					),
					'strip_non_ascii'         => array(
						'description' => __( 'Strip non-ascii characters?', 'jetpack-sync' ),
						'type'        => 'boolean',
						'required'    => false,
					),
					'shared_salt'             => array(
						'description' => __( 'Shared Salt to use when generating checksum', 'jetpack-sync' ),
						'type'        => 'string',
						'required'    => false,
					),
					'only_range_edges'        => array(
						'description' => __( 'Should only range endges be returned', 'jetpack-sync' ),
						'type'        => 'boolean',
						'required'    => false,
					),
					'detailed_drilldown'      => array(
						'description' => __( 'Do we want the checksum or object ids.', 'jetpack-sync' ),
						'type'        => 'boolean',
						'required'    => false,
					),
					'perform_text_conversion' => array(
						'description' => __( 'If text fields should be converted to latin1 in checksum calculation.', 'jetpack-sync' ),
						'type'        => 'boolean',
						'required'    => false,
					),
				),
			)
		);

		// Trigger Dedicated Sync request.
		register_rest_route(
			'jetpack/v4',
			'/sync/spawn-sync',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::spawn_sync',
				'permission_callback' => '__return_true',
			)
		);

		// Reset Sync locks.
		register_rest_route(
			'jetpack/v4',
			'/sync/locks',
			array(
				'methods'             => WP_REST_Server::DELETABLE,
				'callback'            => __CLASS__ . '::reset_locks',
				'permission_callback' => __CLASS__ . '::verify_default_permissions',
			)
		);
	}

	/**
	 * Trigger a Full Sync of specified modules.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response|WP_Error
	 */
	public static function full_sync_start( $request ) {

		$modules = $request->get_param( 'modules' );

		// convert list of modules into array format of "$modulename => true".
		if ( ! empty( $modules ) ) {
			$modules = array_map( '__return_true', array_flip( $modules ) );
		}

		// Process additional options.
		foreach ( array( 'posts', 'comments', 'users' ) as $module_name ) {
			if ( 'users' === $module_name && 'initial' === $request->get_param( 'users' ) ) {
				$modules['users'] = 'initial';
			} elseif ( is_array( $request->get_param( $module_name ) ) ) {
				$ids = $request->get_param( $module_name );
				if ( count( $ids ) > 0 ) {
					$modules[ $module_name ] = $ids;
				}
			}
		}

		if ( empty( $modules ) ) {
			$modules = null;
		}

		return rest_ensure_response(
			array(
				'scheduled' => Actions::do_full_sync( $modules ),
			)
		);
	}

	/**
	 * Return Sync's status.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function sync_status( $request ) {
		$fields = $request->get_param( 'fields' );
		return rest_ensure_response( Actions::get_sync_status( $fields ) );
	}

	/**
	 * Return table checksums.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function data_check( $request ) {
		// Disable Sync during this call, so we can resolve faster.
		Actions::mark_sync_read_only();
		$store = new Replicastore();

		$perform_text_conversion = false;
		if ( true === $request->get_param( 'perform_text_conversion' ) ) {
			$perform_text_conversion = true;
		}

		return rest_ensure_response( $store->checksum_all( $perform_text_conversion ) );
	}

	/**
	 * Return Histogram.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function data_histogram( $request ) {

		// Disable Sync during this call, so we can resolve faster.
		Actions::mark_sync_read_only();

		$args = $request->get_params();

		if ( empty( $args['columns'] ) ) {
			$args['columns'] = null; // go with defaults.
		}

		if ( false !== $args['strip_non_ascii'] ) {
			$args['strip_non_ascii'] = true;
		}

		if ( true !== $args['perform_text_conversion'] ) {
			$args['perform_text_conversion'] = false;
		}

		/**
		 * Hack: nullify the values of `start_id` and `end_id` if we're only requesting ranges.
		 *
		 * The endpoint doesn't support nullable values :(
		 */
		if ( true === $args['only_range_edges'] ) {
			if ( 0 === $args['start_id'] ) {
				$args['start_id'] = null;
			}

			if ( 0 === $args['end_id'] ) {
				$args['end_id'] = null;
			}
		}

		$store     = new Replicastore();
		$histogram = $store->checksum_histogram( $args['object_type'], $args['buckets'], $args['start_id'], $args['end_id'], $args['columns'], $args['strip_non_ascii'], $args['shared_salt'], $args['only_range_edges'], $args['detailed_drilldown'], $args['perform_text_conversion'] );

		return rest_ensure_response(
			array(
				'histogram' => $histogram,
				'type'      => $store->get_checksum_type(),
			)
		);
	}

	/**
	 * Update Sync health.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function sync_health( $request ) {

		switch ( $request->get_param( 'status' ) ) {
			case Health::STATUS_IN_SYNC:
			case Health::STATUS_OUT_OF_SYNC:
				Health::update_status( $request->get_param( 'status' ) );
				break;
			default:
				return new WP_Error( 'invalid_status', 'Invalid Sync Status Provided.' );
		}

		// re-fetch so we see what's really being stored.
		return rest_ensure_response(
			array(
				'success' => Health::get_status(),
			)
		);
	}

	/**
	 * Obtain Sync settings.
	 *
	 * @since 1.23.1
	 *
	 * @return \WP_REST_Response
	 */
	public static function get_sync_settings() {
		return rest_ensure_response( Settings::get_settings() );
	}

	/**
	 * Update Sync settings.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function update_sync_settings( $request ) {
		$args          = $request->get_params();
		$sync_settings = Settings::get_settings();

		foreach ( $args as $key => $value ) {
			if ( false !== $value ) {
				if ( is_numeric( $value ) ) {
					$value = (int) $value;
				}

				// special case for sending empty arrays - a string with value 'empty'.
				if ( 'empty' === $value ) {
					$value = array();
				}

				$sync_settings[ $key ] = $value;
			}
		}

		Settings::update_settings( $sync_settings );

		// re-fetch so we see what's really being stored.
		return rest_ensure_response( Settings::get_settings() );
	}

	/**
	 * Retrieve Sync Objects.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function get_sync_objects( $request ) {
		$args = $request->get_params();

		$module_name = $args['module_name'];
		// Verify valid Sync Module.
		$sync_module = Modules::get_module( $module_name );
		if ( ! $sync_module ) {
			return new WP_Error( 'invalid_module', 'You specified an invalid sync module' );
		}

		Actions::mark_sync_read_only();

		$codec = Sender::get_instance()->get_codec();
		Settings::set_is_syncing( true );
		$objects = $codec->encode( $sync_module->get_objects_by_id( $args['object_type'], $args['object_ids'] ) );
		Settings::set_is_syncing( false );

		return rest_ensure_response(
			array(
				'objects' => $objects,
				'codec'   => $codec->name(),
			)
		);
	}

	/**
	 * Request Sync processing.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function do_sync( $request ) {

		$queue_name = self::validate_queue( $request->get_param( 'queue' ) );
		if ( is_wp_error( $queue_name ) ) {
			return $queue_name;
		}

		$sender   = Sender::get_instance();
		$response = $sender->do_sync_for_queue( new Queue( $queue_name ) );

		return rest_ensure_response(
			array(
				'response' => $response,
			)
		);
	}

	/**
	 * Request sync data from specified queue.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function checkout( $request ) {
		$args       = $request->get_params();
		$queue_name = self::validate_queue( $args['queue'] );

		if ( is_wp_error( $queue_name ) ) {
			return $queue_name;
		}

		$number_of_items = $args['number_of_items'];
		if ( $number_of_items < 1 || $number_of_items > 100 ) {
			return new WP_Error( 'invalid_number_of_items', 'Number of items needs to be an integer that is larger than 0 and less then 100', 400 );
		}

		// REST Sender.
		$sender = new REST_Sender();

		if ( 'immediate' === $queue_name ) {
			return rest_ensure_response( $sender->immediate_full_sync_pull( $number_of_items ) );
		}

		return rest_ensure_response( $sender->queue_pull( $queue_name, $number_of_items, $args ) );
	}

	/**
	 * Unlock a Sync queue.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function unlock_queue( $request ) {

		$queue_name = $request->get_param( 'queue' );

		if ( ! in_array( $queue_name, array( 'sync', 'full_sync' ), true ) ) {
			return new WP_Error( 'invalid_queue', 'Queue name should be sync or full_sync', 400 );
		}
		$queue = new Queue( $queue_name );

		// False means that there was no lock to delete.
		$response = $queue->unlock();
		return rest_ensure_response(
			array(
				'success' => $response,
			)
		);
	}

	/**
	 * Checkin Sync actions.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function close( $request ) {

		$request_body = $request->get_params();
		$queue_name   = self::validate_queue( $request_body['queue'] );

		if ( is_wp_error( $queue_name ) ) {
			return $queue_name;
		}

		if ( empty( $request_body['buffer_id'] ) ) {
			return new WP_Error( 'missing_buffer_id', 'Please provide a buffer id', 400 );
		}

		if ( ! is_array( $request_body['item_ids'] ) ) {
			return new WP_Error( 'missing_item_ids', 'Please provide a list of item ids in the item_ids argument', 400 );
		}

		// Limit to A-Z,a-z,0-9,_,- .
		$request_body['buffer_id'] = preg_replace( '/[^A-Za-z0-9]/', '', $request_body['buffer_id'] );
		$request_body['item_ids']  = array_filter( array_map( array( 'Automattic\Jetpack\Sync\REST_Endpoints', 'sanitize_item_ids' ), $request_body['item_ids'] ) );

		$queue = new Queue( $queue_name );

		$items = $queue->peek_by_id( $request_body['item_ids'] );

		// Update Full Sync Status if queue is "full_sync".
		if ( 'full_sync' === $queue_name ) {
			$full_sync_module = Modules::get_module( 'full-sync' );
			$full_sync_module->update_sent_progress_action( $items );
		}

		$buffer   = new Queue_Buffer( $request_body['buffer_id'], $request_body['item_ids'] );
		$response = $queue->close( $buffer, $request_body['item_ids'] );

		// Perform another checkout?
		if ( isset( $request_body['continue'] ) && $request_body['continue'] ) {
			if ( in_array( $queue_name, array( 'full_sync', 'immediate' ), true ) ) {
				// Send Full Sync Actions.
				Sender::get_instance()->do_full_sync();
			} elseif ( $queue->has_any_items() ) {
				// Send Incremental Sync Actions.
				Sender::get_instance()->do_sync();
			}
		}

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return rest_ensure_response(
			array(
				'success' => $response,
				'status'  => Actions::get_sync_status(),
			)
		);
	}

	/**
	 * Retrieve range of Object Ids for a specified Sync module.
	 *
	 * @since 1.23.1
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response
	 */
	public static function get_object_id_range( $request ) {

		$module_name = $request->get_param( 'sync_module' );
		$batch_size  = $request->get_param( 'batch_size' );

		if ( ! self::is_valid_sync_module( $module_name ) ) {
			return new WP_Error( 'invalid_module', 'This sync module cannot be used to calculate a range.', 400 );
		}
		$module = Modules::get_module( $module_name );

		return rest_ensure_response(
			array(
				'ranges' => $module->get_min_max_object_ids_for_batches( $batch_size ),
			)
		);
	}

	/**
	 * This endpoint is used by Sync to spawn a
	 * dedicated Sync request which will trigger Sync to run.
	 *
	 * If Dedicated Sync is enabled, this callback should never run as
	 * processing of Sync actions will occur earlier and exit.
	 *
	 * @see Actions::init
	 * @see Sender::do_dedicated_sync_and_exit
	 *
	 * @since $$next_version$$
	 *
	 * @return \WP_REST_Response
	 */
	public static function spawn_sync() {
		nocache_headers();

		if ( ! Settings::is_dedicated_sync_enabled() ) {
			return new WP_Error(
				'dedicated_sync_disabled',
				'Dedicated Sync flow is disabled.',
				array( 'status' => 422 )
			);
		}

		return new WP_Error(
			'dedicated_sync_failed',
			'Failed to process Dedicated Sync request',
			array( 'status' => 500 )
		);
	}

	/**
	 * Reset Sync locks.
	 *
	 * @since 1.43.0
	 *
	 * @return \WP_REST_Response
	 */
	public static function reset_locks() {
		Actions::reset_sync_locks();

		return rest_ensure_response(
			array(
				'success' => true,
			)
		);
	}

	/**
	 * Verify that request has default permissions to perform sync actions.
	 *
	 * @since 1.23.1
	 *
	 * @return bool Whether user has capability 'manage_options' or a blog token is used.
	 */
	public static function verify_default_permissions() {
		if ( current_user_can( 'manage_options' ) || Rest_Authentication::is_signed_with_blog_token() ) {
			return true;
		}

		$error_msg = esc_html__(
			'You do not have the correct user permissions to perform this action.
			Please contact your site admin if you think this is a mistake.',
			'jetpack-sync'
		);

		return new WP_Error( 'invalid_user_permission_sync', $error_msg, array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Validate Queue name.
	 *
	 * @param string $value Queue Name.
	 *
	 * @return WP_Error
	 */
	protected static function validate_queue( $value ) {
		if ( ! isset( $value ) ) {
			return new WP_Error( 'invalid_queue', 'Queue name is required', 400 );
		}

		if ( ! in_array( $value, array( 'sync', 'full_sync', 'immediate' ), true ) ) {
			return new WP_Error( 'invalid_queue', 'Queue name should be sync, full_sync or immediate', 400 );
		}
		return $value;
	}

	/**
	 * Validate name is a valid Sync module.
	 *
	 * @param string $module_name Name of Sync Module.
	 *
	 * @return bool
	 */
	protected static function is_valid_sync_module( $module_name ) {
		return in_array(
			$module_name,
			array(
				'comments',
				'posts',
				'terms',
				'term_relationships',
				'users',
			),
			true
		);
	}

	/**
	 * Sanitize Item Ids.
	 *
	 * @param string $item Sync item identifier.
	 *
	 * @return string|string[]|null
	 */
	protected static function sanitize_item_ids( $item ) {
		// lets not delete any options that don't start with jpsq_sync- .
		if ( ! is_string( $item ) || substr( $item, 0, 5 ) !== 'jpsq_' ) {
			return null;
		}
		// Limit to A-Z,a-z,0-9,_,-,. .
		return preg_replace( '/[^A-Za-z0-9-_.]/', '', $item );
	}

}
