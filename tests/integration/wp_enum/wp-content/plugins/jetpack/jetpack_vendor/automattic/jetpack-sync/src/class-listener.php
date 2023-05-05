<?php
/**
 * Jetpack's Sync Listener
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\IP\Utils as IP_Utils;
use Automattic\Jetpack\Roles;

/**
 * This class monitors actions and logs them to the queue to be sent.
 */
class Listener {
	const QUEUE_STATE_CHECK_TRANSIENT = 'jetpack_sync_last_checked_queue_state';
	const QUEUE_STATE_CHECK_TIMEOUT   = 30; // 30 seconds.

	/**
	 * Sync queue.
	 *
	 * @var object
	 */
	private $sync_queue;

	/**
	 * Full sync queue.
	 *
	 * @var object
	 */
	private $full_sync_queue;

	/**
	 * Sync queue size limit.
	 *
	 * @var int size limit.
	 */
	private $sync_queue_size_limit;

	/**
	 * Sync queue lag limit.
	 *
	 * @var int Lag limit.
	 */
	private $sync_queue_lag_limit;

	/**
	 * Singleton implementation.
	 *
	 * @var Listener
	 */
	private static $instance;

	/**
	 * Get the Listener instance.
	 *
	 * @return Listener
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Listener constructor.
	 *
	 * This is necessary because you can't use "new" when you declare instance properties >:(
	 */
	protected function __construct() {
		$this->set_defaults();
		$this->init();
	}

	/**
	 * Sync Listener init.
	 */
	private function init() {
		$handler           = array( $this, 'action_handler' );
		$full_sync_handler = array( $this, 'full_sync_action_handler' );

		foreach ( Modules::get_modules() as $module ) {
			$module->init_listeners( $handler );
			$module->init_full_sync_listeners( $full_sync_handler );
		}

		// Module Activation.
		add_action( 'jetpack_activate_module', $handler );
		add_action( 'jetpack_deactivate_module', $handler );

		// Jetpack Upgrade.
		add_action( 'updating_jetpack_version', $handler, 10, 2 );

		// Send periodic checksum.
		add_action( 'jetpack_sync_checksum', $handler );
	}

	/**
	 * Get incremental sync queue.
	 */
	public function get_sync_queue() {
		return $this->sync_queue;
	}

	/**
	 * Gets the full sync queue.
	 */
	public function get_full_sync_queue() {
		return $this->full_sync_queue;
	}

	/**
	 * Sets queue size limit.
	 *
	 * @param int $limit Queue size limit.
	 */
	public function set_queue_size_limit( $limit ) {
		$this->sync_queue_size_limit = $limit;
	}

	/**
	 * Get queue size limit.
	 */
	public function get_queue_size_limit() {
		return $this->sync_queue_size_limit;
	}

	/**
	 * Sets the queue lag limit.
	 *
	 * @param int $age Queue lag limit.
	 */
	public function set_queue_lag_limit( $age ) {
		$this->sync_queue_lag_limit = $age;
	}

	/**
	 * Return value of queue lag limit.
	 */
	public function get_queue_lag_limit() {
		return $this->sync_queue_lag_limit;
	}

	/**
	 * Force a recheck of the queue limit.
	 */
	public function force_recheck_queue_limit() {
		delete_transient( self::QUEUE_STATE_CHECK_TRANSIENT . '_' . $this->sync_queue->id );
		delete_transient( self::QUEUE_STATE_CHECK_TRANSIENT . '_' . $this->full_sync_queue->id );
	}

	/**
	 * Determine if an item can be added to the queue.
	 *
	 * Prevent adding items to the queue if it hasn't sent an item for 15 mins
	 * AND the queue is over 1000 items long (by default).
	 *
	 * @param object $queue Sync queue.
	 * @return bool
	 */
	public function can_add_to_queue( $queue ) {
		if ( ! Settings::is_sync_enabled() ) {
			return false;
		}

		$state_transient_name = self::QUEUE_STATE_CHECK_TRANSIENT . '_' . $queue->id;

		$queue_state = get_transient( $state_transient_name );

		if ( false === $queue_state ) {
			$queue_state = array( $queue->size(), $queue->lag() );
			set_transient( $state_transient_name, $queue_state, self::QUEUE_STATE_CHECK_TIMEOUT );
		}

		list( $queue_size, $queue_age ) = $queue_state;

		return ( $queue_age < $this->sync_queue_lag_limit )
			||
			( ( $queue_size + 1 ) < $this->sync_queue_size_limit );
	}

	/**
	 * Full sync action handler.
	 *
	 * @param mixed ...$args Args passed to the action.
	 */
	public function full_sync_action_handler( ...$args ) {
		$this->enqueue_action( current_filter(), $args, $this->full_sync_queue );
	}

	/**
	 * Action handler.
	 *
	 * @param mixed ...$args Args passed to the action.
	 */
	public function action_handler( ...$args ) {
		$this->enqueue_action( current_filter(), $args, $this->sync_queue );
	}

	// add many actions to the queue directly, without invoking them.

	/**
	 * Bulk add action to the queue.
	 *
	 * @param string $action_name The name the full sync action.
	 * @param array  $args_array Array of chunked arguments.
	 */
	public function bulk_enqueue_full_sync_actions( $action_name, $args_array ) {
		$queue = $this->get_full_sync_queue();

		/*
		 * If we add any items to the queue, we should try to ensure that our script
		 * can't be killed before they are sent.
		 */
		if ( function_exists( 'ignore_user_abort' ) ) {
			ignore_user_abort( true );
		}

		$data_to_enqueue = array();
		$user_id         = get_current_user_id();
		$currtime        = microtime( true );
		$is_importing    = Settings::is_importing();

		foreach ( $args_array as $args ) {
			$previous_end = isset( $args['previous_end'] ) ? $args['previous_end'] : null;
			$args         = isset( $args['ids'] ) ? $args['ids'] : $args;

			/**
			 * Modify or reject the data within an action before it is enqueued locally.
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.2.0
			 *
			 * @module sync
			 *
			 * @param array The action parameters
			 */
			$args        = apply_filters( "jetpack_sync_before_enqueue_$action_name", $args );
			$action_data = array( $args );
			if ( $previous_end !== null ) {
				$action_data[] = $previous_end;
			}
			// allow listeners to abort.
			if ( false === $args ) {
				continue;
			}

			$data_to_enqueue[] = array(
				$action_name,
				$action_data,
				$user_id,
				$currtime,
				$is_importing,
			);
		}

		$queue->add_all( $data_to_enqueue );
	}

	/**
	 * Enqueue the action.
	 *
	 * @param string $current_filter Current WordPress filter.
	 * @param object $args Sync args.
	 * @param string $queue Sync queue.
	 */
	public function enqueue_action( $current_filter, $args, $queue ) {
		// don't enqueue an action during the outbound http request - this prevents recursion.
		if ( Settings::is_sending() ) {
			return;
		}

		if ( ! ( new Connection_Manager() )->is_connected() ) {
			// Don't enqueue an action if the site is disconnected.
			return;
		}

		/**
		 * Add an action hook to execute when anything on the whitelist gets sent to the queue to sync.
		 *
		 * @module sync
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.9.0
		 */
		do_action( 'jetpack_sync_action_before_enqueue' );

		/**
		 * Modify or reject the data within an action before it is enqueued locally.
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param array The action parameters
		 */
		$args = apply_filters( "jetpack_sync_before_enqueue_$current_filter", $args );

		// allow listeners to abort.
		if ( false === $args ) {
			return;
		}

		/*
		 * Periodically check the size of the queue, and disable adding to it if
		 * it exceeds some limit AND the oldest item exceeds the age limit (i.e. sending has stopped).
		 */
		if ( ! $this->can_add_to_queue( $queue ) ) {
			if ( 'sync' === $queue->id ) {
				$this->sync_data_loss( $queue );
			}
			return;
		}

		/*
		 * If we add any items to the queue, we should try to ensure that our script
		 * can't be killed before they are sent.
		 */
		if ( function_exists( 'ignore_user_abort' ) ) {
			ignore_user_abort( true );
		}

		if (
			'sync' === $queue->id ||
			in_array(
				$current_filter,
				array(
					'jetpack_full_sync_start',
					'jetpack_full_sync_end',
					'jetpack_full_sync_cancel',
				),
				true
			)
		) {
			$queue->add(
				array(
					$current_filter,
					$args,
					get_current_user_id(),
					microtime( true ),
					Settings::is_importing(),
					$this->get_actor( $current_filter, $args ),
				)
			);
		} else {
			$queue->add(
				array(
					$current_filter,
					$args,
					get_current_user_id(),
					microtime( true ),
					Settings::is_importing(),
				)
			);
		}

		// since we've added some items, let's try to load the sender so we can send them as quickly as possible.
		if ( ! Actions::$sender ) {
			add_filter( 'jetpack_sync_sender_should_load', __NAMESPACE__ . '\Actions::should_initialize_sender_enqueue', 10, 1 );
			if ( did_action( 'init' ) ) {
				Actions::add_sender_shutdown();
			}
		}
	}

	/**
	 * Sync Data Loss Handler
	 *
	 * @param Queue $queue Sync queue.
	 * @return boolean was send successful
	 */
	public function sync_data_loss( $queue ) {
		if ( ! Settings::is_sync_enabled() ) {
			return;
		}
		$updated = Health::update_status( Health::STATUS_OUT_OF_SYNC );

		if ( ! $updated ) {
			return;
		}

		$data = array(
			'timestamp'  => microtime( true ),
			'queue_size' => $queue->size(),
			'queue_lag'  => $queue->lag(),
		);

		$sender = Sender::get_instance();
		return $sender->send_action( 'jetpack_sync_data_loss', $data );
	}

	/**
	 * Get the event's actor.
	 *
	 * @param string $current_filter Current wp-admin page.
	 * @param object $args Sync event.
	 * @return array Actor information.
	 */
	public function get_actor( $current_filter, $args ) {
		if ( 'wp_login' === $current_filter ) {
			$user = get_user_by( 'ID', $args[1]->data->ID );
		} else {
			$user = wp_get_current_user();
		}

		$roles           = new Roles();
		$translated_role = $roles->translate_user_to_role( $user );

		$actor = array(
			'wpcom_user_id'    => null,
			'external_user_id' => isset( $user->ID ) ? $user->ID : null,
			'display_name'     => isset( $user->display_name ) ? $user->display_name : null,
			'user_email'       => isset( $user->user_email ) ? $user->user_email : null,
			'user_roles'       => isset( $user->roles ) ? $user->roles : null,
			'translated_role'  => $translated_role ? $translated_role : null,
			'is_cron'          => defined( 'DOING_CRON' ) ? DOING_CRON : false,
			'is_rest'          => defined( 'REST_API_REQUEST' ) ? REST_API_REQUEST : false,
			'is_xmlrpc'        => defined( 'XMLRPC_REQUEST' ) ? XMLRPC_REQUEST : false,
			'is_wp_rest'       => defined( 'REST_REQUEST' ) ? REST_REQUEST : false,
			'is_ajax'          => defined( 'DOING_AJAX' ) ? DOING_AJAX : false,
			'is_wp_admin'      => is_admin(),
			'is_cli'           => defined( 'WP_CLI' ) ? WP_CLI : false,
			'from_url'         => $this->get_request_url(),
		);

		if ( $this->should_send_user_data_with_actor( $current_filter ) ) {
			$ip = IP_Utils::get_ip();

			$actor['ip']         = $ip ? $ip : '';
			$actor['user_agent'] = isset( $_SERVER['HTTP_USER_AGENT'] ) ? filter_var( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'unknown';
		}

		return $actor;
	}

	/**
	 * Should user data be sent as the actor?
	 *
	 * @param string $current_filter The current WordPress filter being executed.
	 * @return bool
	 */
	public function should_send_user_data_with_actor( $current_filter ) {
		$should_send = in_array( $current_filter, array( 'jetpack_wp_login', 'wp_logout', 'jetpack_valid_failed_login_attempt' ), true );
		/**
		 * Allow or deny sending actor's user data ( IP and UA ) during a sync event
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.8.0
		 *
		 * @module sync
		 *
		 * @param bool True if we should send user data
		 * @param string The current filter that is performing the sync action
		 */
		return apply_filters( 'jetpack_sync_actor_user_data', $should_send, $current_filter );
	}

	/**
	 * Sets Listener defaults.
	 */
	public function set_defaults() {
		$this->sync_queue      = new Queue( 'sync' );
		$this->full_sync_queue = new Queue( 'full_sync' );
		$this->set_queue_size_limit( Settings::get_setting( 'max_queue_size' ) );
		$this->set_queue_lag_limit( Settings::get_setting( 'max_queue_lag' ) );
	}

	/**
	 * Get the request URL.
	 *
	 * @return string Request URL, if known. Otherwise, wp-admin or home_url.
	 */
	public function get_request_url() {
		if ( isset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- False positive, sniff misses the call to esc_url_raw.
			return esc_url_raw( 'http' . ( isset( $_SERVER['HTTPS'] ) ? 's' : '' ) . '://' . wp_unslash( "{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}" ) );
		}
		return is_admin() ? get_admin_url( get_current_blog_id() ) : home_url();
	}
}
