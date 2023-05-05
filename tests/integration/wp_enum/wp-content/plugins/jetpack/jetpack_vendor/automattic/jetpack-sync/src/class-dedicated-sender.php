<?php
/**
 * Dedicated Sender.
 *
 * The class is responsible for spawning dedicated Sync requests.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use WP_Error;
/**
 * Class to manage Sync spawning.
 * The purpose of this class is to provide the means to unblock Sync
 * from running in the shutdown hook of regular requests by spawning a
 * dedicated Sync request instead which will trigger Sync to run.
 */
class Dedicated_Sender {

	/**
	 * The transient name for storing the response code
	 * after spawning a dedicated sync test request.
	 */
	const DEDICATED_SYNC_CHECK_TRANSIENT = 'jetpack_sync_dedicated_sync_spawn_check';

	/**
	 * Validation string to check if the endpoint is working correctly.
	 *
	 * This is extracted and not hardcoded, as we might want to change it in the future.
	 */
	const DEDICATED_SYNC_VALIDATION_STRING = 'DEDICATED SYNC OK';

	/**
	 * Option name to use to keep the current request lock.
	 *
	 * The option format is `microtime(true)`.
	 */
	const DEDICATED_SYNC_REQUEST_LOCK_OPTION_NAME = 'jetpack_sync_dedicated_spawn_lock';

	/**
	 * What's the timeout for the request lock in seconds.
	 *
	 * 5 seconds as default value seems sane, but we might want to adjust that in the future.
	 */
	const DEDICATED_SYNC_REQUEST_LOCK_TIMEOUT = 5;

	/**
	 * The query parameter name to use when passing the current lock id.
	 */
	const DEDICATED_SYNC_REQUEST_LOCK_QUERY_PARAM_NAME = 'request_lock_id';

	/**
	 * The name of the transient to use to temporarily disable enabling of Dedicated sync.
	 */
	const DEDICATED_SYNC_TEMPORARY_DISABLE_FLAG = 'jetpack_sync_dedicated_sync_temp_disable';

	/**
	 * Filter a URL to check if Dedicated Sync is enabled.
	 * We need to remove slashes and then run it through `urldecode` as sometimes the
	 * URL is in an encoded form, depending on server configuration.
	 *
	 * @param string $url The URL to filter.
	 *
	 * @return string
	 */
	public static function prepare_url_for_dedicated_request_check( $url ) {
		return urldecode( $url );
	}
	/**
	 * Check if this request should trigger Sync to run.
	 *
	 * @access public
	 *
	 * @return boolean True if this is a 'jetpack/v4/sync/spawn-sync', false otherwise.
	 */
	public static function is_dedicated_sync_request() {
		/**
		 * Check $_SERVER['REQUEST_URI'] first, to see if we're in the right context.
		 * This is done to make sure we can hook in very early in the initialization of WordPress to
		 * be able to send sync requests to the backend as fast as possible, without needing to continue
		 * loading things for the request.
		 */
		if ( ! isset( $_SERVER['REQUEST_URI'] ) ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.NonceVerification.Recommended
		$check_url = self::prepare_url_for_dedicated_request_check( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		if ( strpos( $check_url, 'jetpack/v4/sync/spawn-sync' ) !== false ) {
			return true;
		}

		/**
		 * If the above check failed, we might have an issue with detecting calls to the REST endpoint early on.
		 * Sometimes, like when permalinks are disabled, the REST path is sent via the `rest_route` GET parameter.
		 * We want to check it too, to make sure we managed to cover more cases and be more certain we actually
		 * catch calls to the endpoint.
		 */
		if ( ! isset( $_GET['rest_route'] ) ) { //phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return false;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.NonceVerification.Recommended
		$check_url = self::prepare_url_for_dedicated_request_check( wp_unslash( $_GET['rest_route'] ) );
		if ( strpos( $check_url, 'jetpack/v4/sync/spawn-sync' ) !== false ) {
			return true;
		}

		return false;
	}

	/**
	 * Send a request to run Sync for a certain sync queue
	 * through HTTP request that doesn't halt page loading.
	 *
	 * @access public
	 *
	 * @param \Automattic\Jetpack\Sync\Queue $queue Queue object.
	 *
	 * @return boolean|WP_Error True if spawned, WP_Error otherwise.
	 */
	public static function spawn_sync( $queue ) {
		if ( ! Settings::is_dedicated_sync_enabled() ) {
			return new WP_Error( 'dedicated_sync_disabled', 'Dedicated Sync flow is disabled.' );
		}

		if ( $queue->is_locked() ) {
			return new WP_Error( 'locked_queue_' . $queue->id );
		}

		if ( $queue->size() === 0 ) {
			return new WP_Error( 'empty_queue_' . $queue->id );
		}

		// Return early if we've gotten a retry-after header response that is not expired.
		$retry_time = get_option( Actions::RETRY_AFTER_PREFIX . $queue->id );
		if ( $retry_time && $retry_time >= microtime( true ) ) {
			return new WP_Error( 'retry_after_' . $queue->id );
		}

		// Don't sync if we are throttled.
		$sync_next_time = Sender::get_instance()->get_next_sync_time( $queue->id );
		if ( $sync_next_time > microtime( true ) ) {
			return new WP_Error( 'sync_throttled_' . $queue->id );
		}
		/**
		 * How much time to wait before we start suspecting Dedicated Sync is in trouble.
		 */
		$queue_send_time_threshold = 30 * MINUTE_IN_SECONDS;

		$queue_lag = $queue->lag();

		// Only check if we're failing to send events if the queue lag is longer than the threshold.
		if ( $queue_lag > $queue_send_time_threshold ) {
			/**
			 * Check if Dedicated Sync is healthy and revert to Default Sync if such case is detected.
			 */
			$last_successful_queue_send_time = get_option( Actions::LAST_SUCCESS_PREFIX . $queue->id, null );

			if ( $last_successful_queue_send_time === null ) {
				/**
				 * No successful sync sending completed. This might be either a "new" sync site or a site that's totally stuck.
				 */
				self::on_dedicated_sync_lag_not_sending_threshold_reached();

				return new WP_Error( 'dedicated_sync_not_sending', 'Dedicated Sync is not successfully sending events' );
			} else {
				/**
				 * We have recorded a successful sending of events. Let's see if that is not too long ago in the past.
				 */
				$time_since_last_succesful_send = time() - $last_successful_queue_send_time;

				if ( $time_since_last_succesful_send > $queue_send_time_threshold ) {
					// We haven't successfully sent stuff in more than 30 minutes. Revert to Default Sync
					self::on_dedicated_sync_lag_not_sending_threshold_reached();

					return new WP_Error( 'dedicated_sync_not_sending', 'Dedicated Sync is not successfully sending events' );
				}
			}
		}

		/**
		 * Try to acquire a request lock, so we don't spawn multiple requests at the same time.
		 * This should prevent cases where sites might have limits on the amount of simultaneous requests.
		 */
		$request_lock = self::try_lock_spawn_request();
		if ( ! $request_lock ) {
			return new WP_Error( 'dedicated_request_lock', 'Unable to acquire request lock' );
		}

		$url = rest_url( 'jetpack/v4/sync/spawn-sync' );
		$url = add_query_arg( 'time', time(), $url ); // Enforce Cache busting.
		$url = add_query_arg( self::DEDICATED_SYNC_REQUEST_LOCK_QUERY_PARAM_NAME, $request_lock, $url );

		$args = array(
			'cookies'   => $_COOKIE,
			'blocking'  => false,
			'timeout'   => 0.01,
			/** This filter is documented in wp-includes/class-wp-http-streams.php */
			'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
		);

		$result = wp_remote_get( $url, $args );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return true;
	}

	/**
	 * Attempt to acquire a request lock.
	 *
	 * To avoid spawning multiple requests at the same time, we need to have a quick lock that will
	 * allow only a single request to continue if we try to spawn multiple at the same time.
	 *
	 * @return false|mixed|string
	 */
	public static function try_lock_spawn_request() {
		$current_microtime = (string) microtime( true );

		$current_lock_value = \Jetpack_Options::get_raw_option( self::DEDICATED_SYNC_REQUEST_LOCK_OPTION_NAME, null );

		if ( ! empty( $current_lock_value ) ) {
			// Check if time has passed to overwrite the lock - min 5s?
			if ( is_numeric( $current_lock_value ) && ( ( $current_microtime - $current_lock_value ) < self::DEDICATED_SYNC_REQUEST_LOCK_TIMEOUT ) ) {
				// Still in previous lock, quit
				return false;
			}

			// If the value is not numeric (float/current time), we want to just overwrite it and continue.
		}

		// Update. We don't want it to autoload, as we want to fetch it right before the checks.
		\Jetpack_Options::update_raw_option( self::DEDICATED_SYNC_REQUEST_LOCK_OPTION_NAME, $current_microtime, false );
		// Give some time for the update to happen
		usleep( wp_rand( 1000, 3000 ) );

		$updated_value = \Jetpack_Options::get_raw_option( self::DEDICATED_SYNC_REQUEST_LOCK_OPTION_NAME, null );

		if ( $updated_value === $current_microtime ) {
			return $current_microtime;
		}

		return false;
	}

	/**
	 * Attempt to release the request lock.
	 *
	 * @param string $lock_id The request lock that's currently being held.
	 *
	 * @return bool|WP_Error
	 */
	public static function try_release_lock_spawn_request( $lock_id = '' ) {
		// Try to get the lock_id from the current request if it's not supplied.
		if ( empty( $lock_id ) ) {
			$lock_id = self::get_request_lock_id_from_request();
		}

		// If it's still not a valid lock_id, throw an error and let the lock process figure it out.
		if ( empty( $lock_id ) || ! is_numeric( $lock_id ) ) {
			return new WP_Error( 'dedicated_request_lock_invalid', 'Invalid lock_id supplied for unlock' );
		}

		$current_lock_value = \Jetpack_Options::get_raw_option( self::DEDICATED_SYNC_REQUEST_LOCK_OPTION_NAME, null );

		// If this is the flow that has the lock, let's release it so we can spawn other requests afterwards
		if ( (string) $lock_id === $current_lock_value ) {
			\Jetpack_Options::delete_raw_option( self::DEDICATED_SYNC_REQUEST_LOCK_OPTION_NAME );
			return true;
		}

		return false;
	}

	/**
	 * Try to get the request lock id from the current request.
	 *
	 * @return array|string|string[]|null
	 */
	public static function get_request_lock_id_from_request() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET[ self::DEDICATED_SYNC_REQUEST_LOCK_QUERY_PARAM_NAME ] ) || ! is_numeric( $_GET[ self::DEDICATED_SYNC_REQUEST_LOCK_QUERY_PARAM_NAME ] ) ) {
			return null;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		return wp_unslash( $_GET[ self::DEDICATED_SYNC_REQUEST_LOCK_QUERY_PARAM_NAME ] );
	}

	/**
	 * Test Sync spawning functionality by making a request to the
	 * Sync spawning endpoint and storing the result (status code) in a transient.
	 *
	 * @since $$next_version$$
	 *
	 * @return bool True if we got a successful response, false otherwise.
	 */
	public static function can_spawn_dedicated_sync_request() {
		$dedicated_sync_check_transient = self::DEDICATED_SYNC_CHECK_TRANSIENT;

		$dedicated_sync_response_body = get_transient( $dedicated_sync_check_transient );

		if ( false === $dedicated_sync_response_body ) {
			$url  = rest_url( 'jetpack/v4/sync/spawn-sync' );
			$url  = add_query_arg( 'time', time(), $url ); // Enforce Cache busting.
			$args = array(
				'cookies'   => $_COOKIE,
				'timeout'   => 30,
				/** This filter is documented in wp-includes/class-wp-http-streams.php */
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			);

			$response                     = wp_remote_get( $url, $args );
			$dedicated_sync_response_code = wp_remote_retrieve_response_code( $response );
			$dedicated_sync_response_body = trim( wp_remote_retrieve_body( $response ) );

			/**
			 * Limit the size of the body that we save in the transient to avoid cases where an error
			 * occurs and a whole generated HTML page is returned. We don't need to store the whole thing.
			 *
			 * The regexp check is done to make sure we can detect the string even if the body returns some additional
			 * output, like some caching plugins do when they try to pad the request.
			 */
			$regexp = '!' . preg_quote( self::DEDICATED_SYNC_VALIDATION_STRING, '!' ) . '!uis';
			if ( preg_match( $regexp, $dedicated_sync_response_body ) ) {
				$saved_response_body = self::DEDICATED_SYNC_VALIDATION_STRING;
			} else {
				$saved_response_body = time();
			}

			set_transient( $dedicated_sync_check_transient, $saved_response_body, HOUR_IN_SECONDS );

			// Send a bit more information to WordPress.com to help debugging issues.
			if ( $saved_response_body !== self::DEDICATED_SYNC_VALIDATION_STRING ) {
				$data = array(
					'timestamp'      => microtime( true ),
					'response_code'  => $dedicated_sync_response_code,
					'response_body'  => $dedicated_sync_response_body,

					// Send the flow type that was attempted.
					'sync_flow_type' => 'dedicated',
				);

				$sender = Sender::get_instance();

				$sender->send_action( 'jetpack_sync_flow_error_enable', $data );
			}
		}

		return self::DEDICATED_SYNC_VALIDATION_STRING === $dedicated_sync_response_body;
	}

	/**
	 * Disable dedicated sync and set a transient to prevent re-enabling it for some time.
	 *
	 * @return void
	 */
	public static function on_dedicated_sync_lag_not_sending_threshold_reached() {
		set_transient( self::DEDICATED_SYNC_TEMPORARY_DISABLE_FLAG, true, 6 * HOUR_IN_SECONDS );

		Settings::update_settings(
			array(
				'dedicated_sync_enabled' => 0,
			)
		);

		// Inform that we had to temporarily disable Dedicated Sync
		$data = array(
			'timestamp'      => microtime( true ),

			// Send the flow type that was attempted.
			'sync_flow_type' => 'dedicated',
		);

		$sender = Sender::get_instance();

		$sender->send_action( 'jetpack_sync_flow_error_temp_disable', $data );
	}

	/**
	 * Disable or enable Dedicated Sync sender based on the header value returned from WordPress.com
	 *
	 * @param string $dedicated_sync_header The Dedicated Sync header value - `on` or `off`.
	 *
	 * @return bool Whether Dedicated Sync is going to be enabled or not.
	 */
	public static function maybe_change_dedicated_sync_status_from_wpcom_header( $dedicated_sync_header ) {
		$dedicated_sync_enabled = 'on' === $dedicated_sync_header ? 1 : 0;

		// Prevent enabling of Dedicated sync via header flag if we're in an autoheal timeout.
		if ( $dedicated_sync_enabled ) {
			$check_transient = get_transient( self::DEDICATED_SYNC_TEMPORARY_DISABLE_FLAG );

			if ( $check_transient ) {
				// Something happened and Dedicated Sync should not be automatically re-enabled.
				return false;
			}
		}

		Settings::update_settings(
			array(
				'dedicated_sync_enabled' => $dedicated_sync_enabled,
			)
		);

		return Settings::is_dedicated_sync_enabled();
	}
}
