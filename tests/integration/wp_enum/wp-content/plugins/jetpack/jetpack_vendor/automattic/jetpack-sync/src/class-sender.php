<?php
/**
 * Sync sender.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use Automattic\Jetpack\Connection\Manager;
use Automattic\Jetpack\Constants;
use WP_Error;

/**
 * This class grabs pending actions from the queue and sends them
 */
class Sender {
	/**
	 * Name of the option that stores the time of the next sync.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const NEXT_SYNC_TIME_OPTION_NAME = 'jetpack_next_sync_time';

	/**
	 * Sync timeout after a WPCOM error.
	 *
	 * @access public
	 *
	 * @var int
	 */
	const WPCOM_ERROR_SYNC_DELAY = 60;

	/**
	 * Sync timeout after a queue has been locked.
	 *
	 * @access public
	 *
	 * @var int
	 */
	const QUEUE_LOCKED_SYNC_DELAY = 10;

	/**
	 * Maximum bytes to checkout without exceeding the memory limit.
	 *
	 * @access private
	 *
	 * @var int
	 */
	private $dequeue_max_bytes;

	/**
	 * Maximum bytes in a single encoded item.
	 *
	 * @access private
	 *
	 * @var int
	 */
	private $upload_max_bytes;

	/**
	 * Maximum number of sync items in a single action.
	 *
	 * @access private
	 *
	 * @var int
	 */
	private $upload_max_rows;

	/**
	 * Maximum time for perfirming a checkout of items from the queue (in seconds).
	 *
	 * @access private
	 *
	 * @var int
	 */
	private $max_dequeue_time;

	/**
	 * How many seconds to wait after sending sync items after exceeding the sync wait threshold (in seconds).
	 *
	 * @access private
	 *
	 * @var int
	 */
	private $sync_wait_time;

	/**
	 * How much maximum time to wait for the checkout to finish (in seconds).
	 *
	 * @access private
	 *
	 * @var int
	 */
	private $sync_wait_threshold;

	/**
	 * How much maximum time to wait for the sync items to be queued for sending (in seconds).
	 *
	 * @access private
	 *
	 * @var int
	 */
	private $enqueue_wait_time;

	/**
	 * Incremental sync queue object.
	 *
	 * @access private
	 *
	 * @var Automattic\Jetpack\Sync\Queue
	 */
	private $sync_queue;

	/**
	 * Full sync queue object.
	 *
	 * @access private
	 *
	 * @var Automattic\Jetpack\Sync\Queue
	 */
	private $full_sync_queue;

	/**
	 * Codec object for encoding and decoding sync items.
	 *
	 * @access private
	 *
	 * @var Automattic\Jetpack\Sync\Codec_Interface
	 */
	private $codec;

	/**
	 * The current user before we change or clear it.
	 *
	 * @access private
	 *
	 * @var \WP_User
	 */
	private $old_user;

	/**
	 * Container for the singleton instance of this class.
	 *
	 * @access private
	 * @static
	 *
	 * @var Automattic\Jetpack\Sync\Sender
	 */
	private static $instance;

	/**
	 * Retrieve the singleton instance of this class.
	 *
	 * @access public
	 * @static
	 *
	 * @return Sender
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Constructor.
	 * This is necessary because you can't use "new" when you declare instance properties >:(
	 *
	 * @access protected
	 * @static
	 */
	protected function __construct() {
		$this->set_defaults();
		$this->init();
	}

	/**
	 * Initialize the sender.
	 * Prepares the current user and initializes all sync modules.
	 *
	 * @access private
	 */
	private function init() {
		add_action( 'jetpack_sync_before_send_queue_sync', array( $this, 'maybe_set_user_from_token' ), 1 );
		add_action( 'jetpack_sync_before_send_queue_sync', array( $this, 'maybe_clear_user_from_token' ), 20 );
		add_filter( 'jetpack_xmlrpc_unauthenticated_methods', array( $this, 'register_jetpack_xmlrpc_methods' ) );
		foreach ( Modules::get_modules() as $module ) {
			$module->init_before_send();
		}
	}

	/**
	 * Detect if this is a XMLRPC request with a valid signature.
	 * If so, changes the user to the new one.
	 *
	 * @access public
	 */
	public function maybe_set_user_from_token() {
		$connection    = new Manager();
		$verified_user = $connection->verify_xml_rpc_signature();
		if ( Constants::is_true( 'XMLRPC_REQUEST' ) &&
			! is_wp_error( $verified_user )
			&& $verified_user
		) {
			$old_user       = wp_get_current_user();
			$this->old_user = isset( $old_user->ID ) ? $old_user->ID : 0;
			wp_set_current_user( $verified_user['user_id'] );
		}
	}

	/**
	 * If we used to have a previous current user, revert back to it.
	 *
	 * @access public
	 */
	public function maybe_clear_user_from_token() {
		if ( isset( $this->old_user ) ) {
			wp_set_current_user( $this->old_user );
		}
	}

	/**
	 * Retrieve the next sync time.
	 *
	 * Update @since 1.43.2
	 * Sometimes when we process Sync requests in Jetpack, the server clock can be a
	 * bit in the future and this can lock Sync to not send stuff for a while.
	 * We are introducing an extra check, to make sure to limit the next_sync_time
	 * to be at most one hour in the future from the current time.
	 *
	 * @access public
	 *
	 * @param string $queue_name Name of the queue.
	 * @return float Timestamp of the next sync.
	 */
	public function get_next_sync_time( $queue_name ) {
		$option_name    = self::NEXT_SYNC_TIME_OPTION_NAME . '_' . $queue_name;
		$next_sync_time = (float) get_option( $option_name, 0 );

		$is_more_than_one_hour = ( $next_sync_time - microtime( true ) ) >= HOUR_IN_SECONDS;

		if ( $is_more_than_one_hour ) {
			delete_option( $option_name );
			$next_sync_time = 0;
		}

		return $next_sync_time;
	}

	/**
	 * Set the next sync time.
	 *
	 * @access public
	 *
	 * @param int    $time       Timestamp of the next sync.
	 * @param string $queue_name Name of the queue.
	 * @return boolean True if update was successful, false otherwise.
	 */
	public function set_next_sync_time( $time, $queue_name ) {
		return update_option( self::NEXT_SYNC_TIME_OPTION_NAME . '_' . $queue_name, $time, true );
	}

	/**
	 * Trigger a full sync.
	 *
	 * @access public
	 *
	 * @return boolean|WP_Error True if this sync sending was successful, error object otherwise.
	 */
	public function do_full_sync() {
		$sync_module = Modules::get_module( 'full-sync' );
		if ( ! $sync_module ) {
			return;
		}
		// Full Sync Disabled.
		if ( ! Settings::get_setting( 'full_sync_sender_enabled' ) ) {
			return;
		}

		// Don't sync if request is marked as read only.
		if ( Constants::is_true( 'JETPACK_SYNC_READ_ONLY' ) ) {
			return new WP_Error( 'jetpack_sync_read_only' );
		}

		// Sync not started or Sync finished.
		$status = $sync_module->get_status();
		if ( false === $status['started'] || ( ! empty( $status['started'] ) && ! empty( $status['finished'] ) ) ) {
			return false;
		}

		$this->continue_full_sync_enqueue();
		// immediate full sync sends data in continue_full_sync_enqueue.
		if ( false === strpos( get_class( $sync_module ), 'Full_Sync_Immediately' ) ) {
			return $this->do_sync_and_set_delays( $this->full_sync_queue );
		} else {
			$status = $sync_module->get_status();
			// Sync not started or Sync finished.
			if ( false === $status['started'] || ( ! empty( $status['started'] ) && ! empty( $status['finished'] ) ) ) {
				return false;
			} else {
				return true;
			}
		}
	}

	/**
	 * Enqueue the next sync items for sending.
	 * Will not be done if the current request is a WP import one.
	 * Will be delayed until the next sync time comes.
	 *
	 * @access private
	 */
	private function continue_full_sync_enqueue() {
		if ( defined( 'WP_IMPORTING' ) && WP_IMPORTING ) {
			return false;
		}

		if ( $this->get_next_sync_time( 'full-sync-enqueue' ) > microtime( true ) ) {
			return false;
		}

		Modules::get_module( 'full-sync' )->continue_enqueuing();

		$this->set_next_sync_time( time() + $this->get_enqueue_wait_time(), 'full-sync-enqueue' );
	}

	/**
	 * Trigger incremental sync.
	 *
	 * @access public
	 *
	 * @return boolean|WP_Error True if this sync sending was successful, error object otherwise.
	 */
	public function do_sync() {
		if ( ! Settings::is_dedicated_sync_enabled() ) {
			$result = $this->do_sync_and_set_delays( $this->sync_queue );
		} else {
			$result = Dedicated_Sender::spawn_sync( $this->sync_queue );
		}

		return $result;
	}

	/**
	 * Trigger incremental sync and early exit on Dedicated Sync request.
	 *
	 * @access public
	 *
	 * @param bool $do_real_exit If we should exit at the end of the request. We should by default.
	 *                           In the context of running this in the REST API, we actually want to return an error.
	 *
	 * @return void|WP_Error
	 */
	public function do_dedicated_sync_and_exit( $do_real_exit = true ) {
		nocache_headers();

		if ( ! Settings::is_dedicated_sync_enabled() ) {
			return new WP_Error( 'dedicated_sync_disabled', 'Dedicated Sync flow is disabled.' );
		}

		if ( ! Dedicated_Sender::is_dedicated_sync_request() ) {
			return new WP_Error( 'non_dedicated_sync_request', 'Not a Dedicated Sync request.' );
		}

		/**
		 * Output an `OK` to show that Dedicated Sync is enabled and we can process events.
		 * This is used to test the feature is working.
		 *
		 * @see \Automattic\Jetpack\Sync\Dedicated_Sender::can_spawn_dedicated_sync_request
		 */
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo Dedicated_Sender::DEDICATED_SYNC_VALIDATION_STRING;

		// Try to disconnect the request as quickly as possible and process things in the background.
		$this->fastcgi_finish_request();

		/**
		 * Close the PHP session to free up the server threads to handle other requests while we
		 * send sync data with Dedicated Sync.
		 *
		 * When we spawn Dedicated Sync, we send `$_COOKIES` with the request to help out with any
		 * firewall and/or caching functionality that might prevent us to ping the site directly.
		 *
		 * This will cause Dedicated Sync to reuse the visitor's PHP session and lock it until the
		 * request finishes, which can take anywhere from 1 to 30+ seconds, depending on the server
		 * `max_execution_time` configuration.
		 *
		 * By closing the session we're freeing up the session, so other requests can acquire the
		 * lock and proceed with their own tasks.
		 */
		if ( session_status() === PHP_SESSION_ACTIVE ) {
			session_write_close();
		}

		// Output not used right now. Try to release dedicated sync lock
		Dedicated_Sender::try_release_lock_spawn_request();

		// Actually try to send Sync events.
		$result = $this->do_sync_and_set_delays( $this->sync_queue );

		// If no errors occurred, re-spawn a dedicated Sync request.
		if ( true === $result ) {
			Dedicated_Sender::spawn_sync( $this->sync_queue );
		}

		if ( $do_real_exit ) {
			exit;
		}
	}

	/**
	 * Trigger sync for a certain sync queue.
	 * Responsible for setting next sync time.
	 * Will not be delayed if the current request is a WP import one.
	 * Will be delayed until the next sync time comes.
	 *
	 * @access public
	 *
	 * @param Automattic\Jetpack\Sync\Queue $queue Queue object.
	 *
	 * @return boolean|WP_Error True if this sync sending was successful, error object otherwise.
	 */
	public function do_sync_and_set_delays( $queue ) {
		// Don't sync if importing.
		if ( defined( 'WP_IMPORTING' ) && WP_IMPORTING ) {
			return new WP_Error( 'is_importing' );
		}

		// Don't sync if request is marked as read only.
		if ( Constants::is_true( 'JETPACK_SYNC_READ_ONLY' ) ) {
			return new WP_Error( 'jetpack_sync_read_only' );
		}

		if ( ! Settings::is_sender_enabled( $queue->id ) ) {
			return new WP_Error( 'sender_disabled_for_queue_' . $queue->id );
		}

		// Return early if we've gotten a retry-after header response.
		$retry_time = get_option( Actions::RETRY_AFTER_PREFIX . $queue->id );
		if ( $retry_time ) {
			// If expired update to false but don't send. Send will occurr in new request to avoid race conditions.
			if ( microtime( true ) > $retry_time ) {
				update_option( Actions::RETRY_AFTER_PREFIX . $queue->id, false, false );
			}
			return new WP_Error( 'retry_after' );
		}

		// Don't sync if we are throttled.
		if ( $this->get_next_sync_time( $queue->id ) > microtime( true ) ) {
			return new WP_Error( 'sync_throttled' );
		}

		$start_time = microtime( true );

		Settings::set_is_syncing( true );

		$sync_result = $this->do_sync_for_queue( $queue );

		Settings::set_is_syncing( false );

		$exceeded_sync_wait_threshold = ( microtime( true ) - $start_time ) > (float) $this->get_sync_wait_threshold();

		if ( is_wp_error( $sync_result ) ) {
			if ( 'unclosed_buffer' === $sync_result->get_error_code() ) {
				$this->set_next_sync_time( time() + self::QUEUE_LOCKED_SYNC_DELAY, $queue->id );
			}
			if ( 'wpcom_error' === $sync_result->get_error_code() ) {
				$this->set_next_sync_time( time() + self::WPCOM_ERROR_SYNC_DELAY, $queue->id );
			}
		} elseif ( $exceeded_sync_wait_threshold ) {
			// If we actually sent data and it took a while, wait before sending again.
			$this->set_next_sync_time( time() + $this->get_sync_wait_time(), $queue->id );
		}

		return $sync_result;
	}

	/**
	 * Retrieve the next sync items to send.
	 *
	 * @access public
	 *
	 * @param (array|Automattic\Jetpack\Sync\Queue_Buffer) $buffer_or_items Queue buffer or array of objects.
	 * @param boolean                                      $encode Whether to encode the items.
	 * @return array Sync items to send.
	 */
	public function get_items_to_send( $buffer_or_items, $encode = true ) {
		// Track how long we've been processing so we can avoid request timeouts.
		$start_time    = microtime( true );
		$upload_size   = 0;
		$items_to_send = array();
		$items         = is_array( $buffer_or_items ) ? $buffer_or_items : $buffer_or_items->get_items();
		if ( ! is_array( $items ) ) {
			$items = array();
		}

		// Set up current screen to avoid errors rendering content.
		require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
		require_once ABSPATH . 'wp-admin/includes/screen.php';
		set_current_screen( 'sync' );
		$skipped_items_ids = array();
		/**
		 * We estimate the total encoded size as we go by encoding each item individually.
		 * This is expensive, but the only way to really know :/
		 */
		foreach ( $items as $key => $item ) {
			// Suspending cache addition help prevent overloading in memory cache of large sites.
			wp_suspend_cache_addition( true );
			/**
			 * Modify the data within an action before it is serialized and sent to the server
			 * For example, during full sync this expands Post ID's into full Post objects,
			 * so that we don't have to serialize the whole object into the queue.
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.2.0
			 *
			 * @param array The action parameters
			 * @param int The ID of the user who triggered the action
			 */
			$item[1] = apply_filters( 'jetpack_sync_before_send_' . $item[0], $item[1], $item[2] );
			wp_suspend_cache_addition( false );
			// Serialization usage can lead to empty, null or false action_name. Lets skip as there is no information to send.
			if ( empty( $item[0] ) || false === $item[1] ) {
				$skipped_items_ids[] = $key;
				continue;
			}
			$encoded_item = $this->codec->encode( $item );
			$upload_size += strlen( $encoded_item );
			if ( $upload_size > $this->upload_max_bytes && count( $items_to_send ) > 0 ) {
				break;
			}
			$items_to_send[ $key ] = $encode ? $encoded_item : $item;
			if ( microtime( true ) - $start_time > $this->max_dequeue_time ) {
				break;
			}
		}

		return array( $items_to_send, $skipped_items_ids, $items, microtime( true ) - $start_time );
	}

	/**
	 * If supported, flush all response data to the client and finish the request.
	 * This allows for time consuming tasks to be performed without leaving the connection open.
	 *
	 * @access private
	 */
	private function fastcgi_finish_request() {
		if ( function_exists( 'fastcgi_finish_request' ) && version_compare( phpversion(), '7.0.16', '>=' ) ) {
			fastcgi_finish_request();
		}
	}

	/**
	 * Perform sync for a certain sync queue.
	 *
	 * @access public
	 *
	 * @param Automattic\Jetpack\Sync\Queue $queue Queue object.
	 *
	 * @return boolean|WP_Error True if this sync sending was successful, error object otherwise.
	 */
	public function do_sync_for_queue( $queue ) {
		do_action( 'jetpack_sync_before_send_queue_' . $queue->id );
		if ( $queue->size() === 0 ) {
			return new WP_Error( 'empty_queue_' . $queue->id );
		}

		/**
		 * Now that we're sure we are about to sync, try to ignore user abort
		 * so we can avoid getting into a bad state.
		 */
		if ( function_exists( 'ignore_user_abort' ) ) {
			ignore_user_abort( true );
		}

		/* Don't make the request block till we finish, if possible. */
		if ( Constants::is_true( 'REST_REQUEST' ) || Constants::is_true( 'XMLRPC_REQUEST' ) ) {
			$this->fastcgi_finish_request();
		}

		$checkout_start_time = microtime( true );

		$buffer = $queue->checkout_with_memory_limit( $this->dequeue_max_bytes, $this->upload_max_rows );

		if ( ! $buffer ) {
			// Buffer has no items.
			return new WP_Error( 'empty_buffer' );
		}

		if ( is_wp_error( $buffer ) ) {
			return $buffer;
		}

		$checkout_duration = microtime( true ) - $checkout_start_time;

		list( $items_to_send, $skipped_items_ids, $items, $preprocess_duration ) = $this->get_items_to_send( $buffer, true );
		if ( ! empty( $items_to_send ) ) {
			/**
			 * Fires when data is ready to send to the server.
			 * Return false or WP_Error to abort the sync (e.g. if there's an error)
			 * The items will be automatically re-sent later
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.2.0
			 *
			 * @param array  $data The action buffer
			 * @param string $codec The codec name used to encode the data
			 * @param double $time The current time
			 * @param string $queue The queue used to send ('sync' or 'full_sync')
			 * @param float  $checkout_duration The duration of the checkout operation.
			 * @param float  $preprocess_duration The duration of the pre-process operation.
			 * @param int    $queue_size The size of the sync queue at the time of processing.
			 */
			Settings::set_is_sending( true );
			$processed_item_ids = apply_filters( 'jetpack_sync_send_data', $items_to_send, $this->codec->name(), microtime( true ), $queue->id, $checkout_duration, $preprocess_duration, $queue->size(), $buffer->id );
			Settings::set_is_sending( false );
		} else {
			$processed_item_ids = $skipped_items_ids;
			$skipped_items_ids  = array();
		}

		if ( 'non-blocking' !== $processed_item_ids ) {
			if ( ! $processed_item_ids || is_wp_error( $processed_item_ids ) ) {
				$checked_in_item_ids = $queue->checkin( $buffer );
				if ( is_wp_error( $checked_in_item_ids ) ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
					error_log( 'Error checking in buffer: ' . $checked_in_item_ids->get_error_message() );
					$queue->force_checkin();
				}
				if ( is_wp_error( $processed_item_ids ) ) {
					return new WP_Error( 'wpcom_error', $processed_item_ids->get_error_code() );
				}

				// Returning a wpcom_error is a sign to the caller that we should wait a while before syncing again.
				return new WP_Error( 'wpcom_error', 'jetpack_sync_send_data_false' );
			} else {
				// Detect if the last item ID was an error.
				$had_wp_error = is_wp_error( end( $processed_item_ids ) );
				if ( $had_wp_error ) {
					$wp_error = array_pop( $processed_item_ids );
				}
				// Also checkin any items that were skipped.
				if ( count( $skipped_items_ids ) > 0 ) {
					$processed_item_ids = array_merge( $processed_item_ids, $skipped_items_ids );
				}
				$processed_items = array_intersect_key( $items, array_flip( $processed_item_ids ) );
				/**
				 * Allows us to keep track of all the actions that have been sent.
				 * Allows us to calculate the progress of specific actions.
				 *
				 * @since 1.6.3
				 * @since-jetpack 4.2.0
				 *
				 * @param array $processed_actions The actions that we send successfully.
				 */
				do_action( 'jetpack_sync_processed_actions', $processed_items );
				$queue->close( $buffer, $processed_item_ids );
				// Returning a WP_Error is a sign to the caller that we should wait a while before syncing again.
				if ( $had_wp_error ) {
					return new WP_Error( 'wpcom_error', $wp_error->get_error_code() );
				}
			}
		}

		return true;
	}

	/**
	 * Immediately sends a single item without firing or enqueuing it
	 *
	 * @param string $action_name The action.
	 * @param array  $data The data associated with the action.
	 *
	 * @return Items processed. TODO: this doesn't make much sense anymore, it should probably be just a bool.
	 */
	public function send_action( $action_name, $data = null ) {
		if ( ! Settings::is_sender_enabled( 'full_sync' ) ) {
			return array();
		}

		// Compose the data to be sent.
		$action_to_send = $this->create_action_to_send( $action_name, $data );

		list( $items_to_send, $skipped_items_ids, $items, $preprocess_duration ) = $this->get_items_to_send( $action_to_send, true ); // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		Settings::set_is_sending( true );
		$processed_item_ids = apply_filters( 'jetpack_sync_send_data', $items_to_send, $this->get_codec()->name(), microtime( true ), 'immediate-send', 0, $preprocess_duration );
		Settings::set_is_sending( false );

		/**
		 * Allows us to keep track of all the actions that have been sent.
		 * Allows us to calculate the progress of specific actions.
		 *
		 * @param array $processed_actions The actions that we send successfully.
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 */
		do_action( 'jetpack_sync_processed_actions', $action_to_send );

		return $processed_item_ids;
	}

	/**
	 * Create an synthetic action for direct sending to WPCOM during full sync (for example)
	 *
	 * @access private
	 *
	 * @param string $action_name The action.
	 * @param array  $data The data associated with the action.
	 * @return array An array of synthetic sync actions keyed by current microtime(true)
	 */
	private function create_action_to_send( $action_name, $data ) {
		return array(
			(string) microtime( true ) => array(
				$action_name,
				$data,
				get_current_user_id(),
				microtime( true ),
				Settings::is_importing(),
			),
		);
	}

	/**
	 * Returns any object that is able to be synced.
	 *
	 * @access public
	 *
	 * @param array $args the synchronized object parameters.
	 * @return string Encoded sync object.
	 */
	public function sync_object( $args ) {
		// For example: posts, post, 5.
		list( $module_name, $object_type, $id ) = $args;

		$sync_module = Modules::get_module( $module_name );
		$codec       = $this->get_codec();

		return $codec->encode( $sync_module->get_object_by_id( $object_type, $id ) );
	}

	/**
	 * Register additional sync XML-RPC methods available to Jetpack for authenticated users.
	 *
	 * @access public
	 * @since 1.6.3
	 * @since-jetpack 7.8.0
	 *
	 * @param array $jetpack_methods XML-RPC methods available to the Jetpack Server.
	 * @return array Filtered XML-RPC methods.
	 */
	public function register_jetpack_xmlrpc_methods( $jetpack_methods ) {
		$jetpack_methods['jetpack.syncObject'] = array( $this, 'sync_object' );
		return $jetpack_methods;
	}

	/**
	 * Get the incremental sync queue object.
	 *
	 * @access public
	 *
	 * @return Automattic\Jetpack\Sync\Queue Queue object.
	 */
	public function get_sync_queue() {
		return $this->sync_queue;
	}

	/**
	 * Get the full sync queue object.
	 *
	 * @access public
	 *
	 * @return Automattic\Jetpack\Sync\Queue Queue object.
	 */
	public function get_full_sync_queue() {
		return $this->full_sync_queue;
	}

	/**
	 * Get the codec object.
	 *
	 * @access public
	 *
	 * @return Automattic\Jetpack\Sync\Codec_Interface Codec object.
	 */
	public function get_codec() {
		return $this->codec;
	}

	/**
	 * Determine the codec object.
	 * Use gzip deflate if supported.
	 *
	 * @access public
	 */
	public function set_codec() {
		if ( function_exists( 'gzinflate' ) ) {
			$this->codec = new JSON_Deflate_Array_Codec();
		} else {
			$this->codec = new Simple_Codec();
		}
	}

	/**
	 * Compute and send all the checksums.
	 *
	 * @access public
	 */
	public function send_checksum() {
		$store = new Replicastore();
		do_action( 'jetpack_sync_checksum', $store->checksum_all() );
	}

	/**
	 * Reset the incremental sync queue.
	 *
	 * @access public
	 */
	public function reset_sync_queue() {
		$this->sync_queue->reset();
	}

	/**
	 * Reset the full sync queue.
	 *
	 * @access public
	 */
	public function reset_full_sync_queue() {
		$this->full_sync_queue->reset();
	}

	/**
	 * Set the maximum bytes to checkout without exceeding the memory limit.
	 *
	 * @access public
	 *
	 * @param int $size Maximum bytes to checkout.
	 */
	public function set_dequeue_max_bytes( $size ) {
		$this->dequeue_max_bytes = $size;
	}

	/**
	 * Set the maximum bytes in a single encoded item.
	 *
	 * @access public
	 *
	 * @param int $max_bytes Maximum bytes in a single encoded item.
	 */
	public function set_upload_max_bytes( $max_bytes ) {
		$this->upload_max_bytes = $max_bytes;
	}

	/**
	 * Set the maximum number of sync items in a single action.
	 *
	 * @access public
	 *
	 * @param int $max_rows Maximum number of sync items.
	 */
	public function set_upload_max_rows( $max_rows ) {
		$this->upload_max_rows = $max_rows;
	}

	/**
	 * Set the sync wait time (in seconds).
	 *
	 * @access public
	 *
	 * @param int $seconds Sync wait time.
	 */
	public function set_sync_wait_time( $seconds ) {
		$this->sync_wait_time = $seconds;
	}

	/**
	 * Get current sync wait time (in seconds).
	 *
	 * @access public
	 *
	 * @return int Sync wait time.
	 */
	public function get_sync_wait_time() {
		return $this->sync_wait_time;
	}

	/**
	 * Set the enqueue wait time (in seconds).
	 *
	 * @access public
	 *
	 * @param int $seconds Enqueue wait time.
	 */
	public function set_enqueue_wait_time( $seconds ) {
		$this->enqueue_wait_time = $seconds;
	}

	/**
	 * Get current enqueue wait time (in seconds).
	 *
	 * @access public
	 *
	 * @return int Enqueue wait time.
	 */
	public function get_enqueue_wait_time() {
		return $this->enqueue_wait_time;
	}

	/**
	 * Set the sync wait threshold (in seconds).
	 *
	 * @access public
	 *
	 * @param int $seconds Sync wait threshold.
	 */
	public function set_sync_wait_threshold( $seconds ) {
		$this->sync_wait_threshold = $seconds;
	}

	/**
	 * Get current sync wait threshold (in seconds).
	 *
	 * @access public
	 *
	 * @return int Sync wait threshold.
	 */
	public function get_sync_wait_threshold() {
		return $this->sync_wait_threshold;
	}

	/**
	 * Set the maximum time for perfirming a checkout of items from the queue (in seconds).
	 *
	 * @access public
	 *
	 * @param int $seconds Maximum dequeue time.
	 */
	public function set_max_dequeue_time( $seconds ) {
		$this->max_dequeue_time = $seconds;
	}

	/**
	 * Initialize the sync queues, codec and set the default settings.
	 *
	 * @access public
	 */
	public function set_defaults() {
		$this->sync_queue      = new Queue( 'sync' );
		$this->full_sync_queue = new Queue( 'full_sync' );
		$this->set_codec();

		// Saved settings.
		Settings::set_importing( null );
		$settings = Settings::get_settings();
		$this->set_dequeue_max_bytes( $settings['dequeue_max_bytes'] );
		$this->set_upload_max_bytes( $settings['upload_max_bytes'] );
		$this->set_upload_max_rows( $settings['upload_max_rows'] );
		$this->set_sync_wait_time( $settings['sync_wait_time'] );
		$this->set_enqueue_wait_time( $settings['enqueue_wait_time'] );
		$this->set_sync_wait_threshold( $settings['sync_wait_threshold'] );
		$this->set_max_dequeue_time( Defaults::get_max_sync_execution_time() );
	}

	/**
	 * Reset sync queues, modules and settings.
	 *
	 * @access public
	 */
	public function reset_data() {
		$this->reset_sync_queue();
		$this->reset_full_sync_queue();

		foreach ( Modules::get_modules() as $module ) {
			$module->reset_data();
		}
		// Reset Sync locks without unlocking queues since we already reset those.
		Actions::reset_sync_locks( false );

		Settings::reset_data();
	}

	/**
	 * Perform cleanup at the event of plugin uninstallation.
	 *
	 * @access public
	 */
	public function uninstall() {
		// Lets delete all the other fun stuff like transient and option and the sync queue.
		$this->reset_data();

		// Delete the full sync status.
		delete_option( 'jetpack_full_sync_status' );

		// Clear the sync cron.
		wp_clear_scheduled_hook( 'jetpack_sync_cron' );
		wp_clear_scheduled_hook( 'jetpack_sync_full_cron' );
	}
}
