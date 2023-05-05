<?php
/**
 * Sync server.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use WP_Error;

/**
 * Simple version of a Jetpack Sync Server - just receives arrays of events and
 * issues them locally with the 'jetpack_sync_remote_action' action.
 */
class Server {
	/**
	 * Codec used to decode sync events.
	 *
	 * @access private
	 *
	 * @var Automattic\Jetpack\Sync\Codec_Interface
	 */
	private $codec;

	/**
	 * Maximum time for processing sync actions.
	 *
	 * @access public
	 *
	 * @var int
	 */
	const MAX_TIME_PER_REQUEST_IN_SECONDS = 15;

	/**
	 * Prefix of the blog lock transient.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const BLOG_LOCK_TRANSIENT_PREFIX = 'jp_sync_req_lock_';

	/**
	 * Lifetime of the blog lock transient.
	 *
	 * @access public
	 *
	 * @var int
	 */
	const BLOG_LOCK_TRANSIENT_EXPIRY = 60; // Seconds.

	/**
	 * Constructor.
	 *
	 * This is necessary because you can't use "new" when you declare instance properties >:(
	 *
	 * @access public
	 */
	public function __construct() {
		$this->codec = new JSON_Deflate_Array_Codec();
	}

	/**
	 * Set the codec instance.
	 *
	 * @access public
	 *
	 * @param Automattic\Jetpack\Sync\Codec_Interface $codec Codec instance.
	 */
	public function set_codec( Codec_Interface $codec ) {
		$this->codec = $codec;
	}

	/**
	 * Attempt to lock the request when the server receives concurrent requests from the same blog.
	 *
	 * @access public
	 *
	 * @param int $blog_id ID of the blog.
	 * @param int $expiry  Blog lock transient lifetime.
	 * @return boolean True if succeeded, false otherwise.
	 */
	public function attempt_request_lock( $blog_id, $expiry = self::BLOG_LOCK_TRANSIENT_EXPIRY ) {
		$transient_name = $this->get_concurrent_request_transient_name( $blog_id );
		$locked_time    = get_site_transient( $transient_name );
		if ( $locked_time ) {
			return false;
		}
		set_site_transient( $transient_name, microtime( true ), $expiry );

		return true;
	}

	/**
	 * Retrieve the blog lock transient name for a particular blog.
	 *
	 * @access public
	 *
	 * @param int $blog_id ID of the blog.
	 * @return string Name of the blog lock transient.
	 */
	private function get_concurrent_request_transient_name( $blog_id ) {
		return self::BLOG_LOCK_TRANSIENT_PREFIX . $blog_id;
	}

	/**
	 * Remove the request lock from a particular blog ID.
	 *
	 * @access public
	 *
	 * @param int $blog_id ID of the blog.
	 */
	public function remove_request_lock( $blog_id ) {
		delete_site_transient( $this->get_concurrent_request_transient_name( $blog_id ) );
	}

	/**
	 * Receive and process sync events.
	 *
	 * @access public
	 *
	 * @param array  $data           Sync events.
	 * @param object $token          The auth token used to invoke the API.
	 * @param int    $sent_timestamp Timestamp (in seconds) when the actions were transmitted.
	 * @param string $queue_id       ID of the queue from which the event was sent (`sync` or `full_sync`).
	 * @return array Processed sync events.
	 */
	public function receive( $data, $token = null, $sent_timestamp = null, $queue_id = null ) {
		$start_time = microtime( true );
		if ( ! is_array( $data ) ) {
			return new WP_Error( 'action_decoder_error', 'Events must be an array' );
		}

		if ( $token && ! $this->attempt_request_lock( $token->blog_id ) ) {
			/**
			 * Fires when the server receives two concurrent requests from the same blog
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.2.0
			 *
			 * @param token The token object of the misbehaving site
			 */
			do_action( 'jetpack_sync_multi_request_fail', $token );

			return new WP_Error( 'concurrent_request_error', 'There is another request running for the same blog ID' );
		}

		$events           = wp_unslash( array_map( array( $this->codec, 'decode' ), $data ) );
		$events_processed = array();

		/**
		 * Fires when an array of actions are received from a remote Jetpack site
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param array Array of actions received from the remote site
		 */
		do_action( 'jetpack_sync_remote_actions', $events, $token );

		foreach ( $events as $key => $event ) {
			list( $action_name, $args, $user_id, $timestamp, $silent ) = $event;

			/**
			 * Fires when an action is received from a remote Jetpack site
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.2.0
			 *
			 * @param string $action_name The name of the action executed on the remote site
			 * @param array $args The arguments passed to the action
			 * @param int $user_id The external_user_id who did the action
			 * @param bool $silent Whether the item was created via import
			 * @param double $timestamp Timestamp (in seconds) when the action occurred
			 * @param double $sent_timestamp Timestamp (in seconds) when the action was transmitted
			 * @param string $queue_id ID of the queue from which the event was sent (sync or full_sync)
			 * @param array $token The auth token used to invoke the API
			 */
			do_action( 'jetpack_sync_remote_action', $action_name, $args, $user_id, $silent, $timestamp, $sent_timestamp, $queue_id, $token );

			$events_processed[] = $key;

			if ( microtime( true ) - $start_time > self::MAX_TIME_PER_REQUEST_IN_SECONDS ) {
				break;
			}
		}

		if ( $token ) {
			$this->remove_request_lock( $token->blog_id );
		}

		return $events_processed;
	}
}
