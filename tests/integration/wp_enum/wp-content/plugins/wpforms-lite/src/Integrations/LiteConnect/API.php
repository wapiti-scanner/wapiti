<?php

namespace WPForms\Integrations\LiteConnect;

use WPForms\Helpers\Transient;

/**
 * Class API.
 *
 * @since 1.7.4
 */
class API {

	/**
	 * Option name.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const LITE_CONNECT_OPTION = 'wpforms_lite_connect';

	/**
	 * Staging option name.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const STAGING_LITE_CONNECT_OPTION = 'wpforms_lite_connect_staging';

	/**
	 * Lite Connect API URL.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const API_URL = 'https://wpformsliteconnect.com';

	/**
	 * Lite Connect staging API URL.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const STAGING_API_URL = 'https://staging.wpformsliteconnect.com';

	/**
	 * Lite Connect generate_site_key() lock transient name.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const LITE_CONNECT_SITE_KEY_LOCK = 'lite_connect_site_key_lock';

	/**
	 * Lite Connect generate_access_token() lock transient name.
	 *
	 * @since 1.7.4
	 */
	const LITE_CONNECT_ACCESS_TOKEN_LOCK = 'lite_connect_access_token_lock';

	/**
	 * Lite Connect create_not_logged_in_nonce() action.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const KEY_NONCE_ACTION = 'lite_connect_key_action';

	/**
	 * Max number of attempts for generate_site_key().
	 *
	 * @since 1.7.5
	 *
	 * @var integer
	 */
	const MAX_GENERATE_KEY_ATTEMPTS = 20;

	/**
	 * Generate key attempt counter.
	 *
	 * @since 1.7.5
	 *
	 * @var string
	 */
	const GENERATE_KEY_ATTEMPT_COUNTER_OPTION = 'wpforms_lite_connect_generate_key_attempt_counter';

	/**
	 * Lite Connect API URL.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	protected $api_url;

	/**
	 * The site domain.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	protected $domain;

	/**
	 * The site ID.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	protected $site_id;

	/**
	 * API constructor.
	 *
	 * @since 1.7.4
	 */
	public function __construct() {

		// Get the domain name.
		// Strip protocol `http(s)://` and `www.` from the site URL.
		$this->domain = preg_replace( '/(https?:\/\/)?(www\.)?(.*)\/?/', '$3', home_url() );

		$this->api_url = self::API_URL;

		if ( defined( 'WPFORMS_LITE_CONNECT_STAGING' ) && WPFORMS_LITE_CONNECT_STAGING ) {
			$this->api_url = self::STAGING_API_URL;
		}

		$this->set_site_id();
	}

	/**
	 * Generate the site key.
	 *
	 * @since 1.7.4
	 *
	 * @return false
	 */
	protected function generate_site_key() {

		if ( $this->is_max_generate_key_attempts_reached() ) {
			return false;
		}

		if ( Transient::get( self::LITE_CONNECT_SITE_KEY_LOCK ) ) {
			return false;
		}

		Transient::set( self::LITE_CONNECT_SITE_KEY_LOCK, true, MINUTE_IN_SECONDS );

		$admin_email = Integration::get_enabled_email();
		$user        = get_user_by( 'email', $admin_email );
		$data        = [
			'domain'      => $this->domain,
			'admin_email' => $admin_email,
			'first_name'  => ! empty( $user->first_name ) ? $user->first_name : '',
			'last_name'   => ! empty( $user->last_name ) ? $user->last_name : '',
			'nonce'       => $this->create_not_logged_in_nonce(),
			'callback'    => add_query_arg( [ LiteConnect::AUTH_KEY_ARG => '' ], trailingslashit( home_url() ) ),
		];

		$response = $this->request(
			'/auth/key',
			$data
		);

		if ( $response !== false ) {
			Transient::delete( self::LITE_CONNECT_SITE_KEY_LOCK );
		}

		$this->update_generate_key_attempts_count();

		// At this point, we do not have the site key.
		// It will be sent to us in the 'wpforms/auth/key/nonce' callback.
		return false;
	}

	/**
	 * Generate the access token.
	 *
	 * @since 1.7.4
	 *
	 * @param string $site_key The site key.
	 *
	 * @return false|string
	 */
	protected function generate_access_token( $site_key ) {

		// Verify if an access token is already being generated.
		if ( Transient::get( self::LITE_CONNECT_ACCESS_TOKEN_LOCK ) ) {
			return false;
		}

		// Set a lock to avoid multiple requests to generate the access token.
		Transient::set( self::LITE_CONNECT_ACCESS_TOKEN_LOCK, true, MINUTE_IN_SECONDS );

		$response = $this->request(
			'/auth/access_token',
			[
				'domain'     => $this->domain,
				'site_id'    => $this->site_id,
				'wp_version' => get_bloginfo( 'version' ),
			],
			[
				'X-WPForms-Lite-Connect-Site-Key' => $site_key,
			]
		);

		if ( $response && strpos( $response, '{"error":' ) === false ) {
			// Delete lock.
			Transient::delete( self::LITE_CONNECT_ACCESS_TOKEN_LOCK );
		}

		return $response;
	}

	/**
	 * Add an entry to the Lite Connect API.
	 *
	 * @since 1.7.4
	 *
	 * @param string $access_token The access token.
	 * @param int    $form_id      The form ID.
	 * @param string $entry_data   The entry data.
	 *
	 * @return false|string
	 */
	public function add_form_entry( $access_token, $form_id, $entry_data ) {

		return $this->request(
			'/storage/entries',
			[
				'site_id' => $this->site_id,
				'form_id' => $form_id,
				'data'    => $entry_data,
			],
			[
				'X-WPForms-Lite-Connect-Access-Token' => $access_token,
			]
		);
	}

	/**
	 * Send a request to the Lite Connect API.
	 *
	 * @since 1.7.4
	 *
	 * @param string $uri     The request's URI.
	 * @param array  $body    The request's body.
	 * @param array  $headers The HTTP headers.
	 *
	 * @return false|string
	 */
	protected function request( $uri, $body, $headers = [] ) {

		$url        = $this->api_url . $uri;
		$user_agent = 'WPForms/' . WPFORMS_VERSION . '; ' . home_url();

		$response = wp_remote_post(
			$url,
			[
				'method'     => 'POST',
				'timeout'    => 15,
				'headers'    => $headers,
				'body'       => $body,
				'user-agent' => $user_agent,
			]
		);

		if (
			is_wp_error( $response ) ||
			(
				isset( $response['response']['code'] ) &&
				(int) $response['response']['code'] !== 200
			)
		) {
			if ( ! is_wp_error( $response ) ) {
				unset( $response['headers'], $response['http_response'], $response['cookies'], $response['filename'] );
			}

			$args = [
				'type' => [ 'error' ],
			];

			if ( isset( $body['form_id'] ) ) {
				$args['form_id'] = $body['form_id'];
			}

			wpforms_log(
				'Lite Connect: remote API request error',
				[
					'response' => $response,
					'request'  => [
						'url'        => $url,
						'body'       => $this->prepare_log_data( $body ),
						'headers'    => $this->prepare_log_data( $headers ),
						'user-agent' => $user_agent,
					],
				],
				$args
			);
		}

		if ( is_wp_error( $response ) ) {
			return false;
		}

		return wp_remote_retrieve_body( $response );
	}

	/**
	 * Prepare data for logging.
	 *
	 * @since 1.7.4
	 *
	 * @param mixed $data Data to log.
	 *
	 * @return mixed
	 */
	private function prepare_log_data( $data ) {

		$asterisks = '***';

		if ( ! empty( $data['X-WPForms-Lite-Connect-Access-Token'] ) ) {
			$data['X-WPForms-Lite-Connect-Access-Token'] = $asterisks;
		}

		if ( ! empty( $data['X-WPForms-Lite-Connect-Site-Key'] ) ) {
			$data['X-WPForms-Lite-Connect-Site-Key'] = $asterisks;
		}

		if ( ! empty( $data['nonce'] ) ) {
			$data['nonce'] = $asterisks;
		}

		return $data;
	}

	/**
	 * Get debug setting.
	 *
	 * @since 1.7.4
	 *
	 * @param string $name Setting name.
	 *
	 * @return false|mixed
	 */
	protected function get_debug_setting( $name ) {

		// To be defined in wp-config.php.
		if ( ! defined( 'WPFORMS_DEBUG_LITE_CONNECT' ) || ! is_array( WPFORMS_DEBUG_LITE_CONNECT ) ) {
			return false;
		}

		return ! empty( WPFORMS_DEBUG_LITE_CONNECT[ $name ] ) ? WPFORMS_DEBUG_LITE_CONNECT[ $name ] : false;
	}

	/**
	 * Create not logged in nonce.
	 * We need it, because callback from the server to the wpforms/auth/key/nonce will be processed as not logged in.
	 *
	 * @since 1.7.4
	 *
	 * @return string
	 */
	private function create_not_logged_in_nonce() {

		$user    = wp_get_current_user();
		$user_id = $user ? $user->ID : 0;

		wp_set_current_user( 0 );

		$saved_cookie = $_COOKIE;
		$_COOKIE      = [];
		$nonce        = wp_create_nonce( self::KEY_NONCE_ACTION );
		$_COOKIE      = $saved_cookie;

		wp_set_current_user( $user_id );

		return $nonce;
	}

	/**
	 * Set site ID.
	 *
	 * @since 1.7.4
	 *
	 * @return void
	 */
	private function set_site_id() {

		// At first, try to use the site ID from the wp-config.php file.
		$debug_site_id = $this->get_debug_setting( 'id' );

		if ( $debug_site_id !== false ) {
			$this->site_id = $debug_site_id;

			return;
		}

		// Otherwise, use the site ID generated and saved as setting.
		$site = wpforms_setting( 'site', false, Integration::get_option_name() );

		if ( ! isset( $site['id'] ) ) {
			return;
		}

		$this->site_id = $site['id'];
	}

	/**
	 * Check that we have not reached the max number of attempts to get keys from API using generate_keys().
	 *
	 * @since 1.7.5
	 *
	 * @return bool
	 */
	private function is_max_generate_key_attempts_reached() {

		$attempts_count = get_option( self::GENERATE_KEY_ATTEMPT_COUNTER_OPTION, 0 );

		return $attempts_count >= self::MAX_GENERATE_KEY_ATTEMPTS;
	}

	/**
	 * Update count of the attempts to get keys from API using generate_keys().
	 * It allows us to prevent sending requests to the API server infinitely.
	 *
	 * @since 1.7.5
	 */
	private function update_generate_key_attempts_count() {

		global $wpdb;

		$counter = get_option( self::GENERATE_KEY_ATTEMPT_COUNTER_OPTION, 0 );

		if ( $counter >= self::MAX_GENERATE_KEY_ATTEMPTS - 1 ) {
			// Disable Lite Connect.
			$wpforms_settings                               = get_option( 'wpforms_settings', [] );
			$wpforms_settings[ LiteConnect::SETTINGS_SLUG ] = 0;

			update_option( 'wpforms_settings',  $wpforms_settings );
		}

		// Store actual attempt counter value to the option.
		// We need here an atomic operation to avoid race conditions with getting site key via callback.
		// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO $wpdb->options
				(option_name, option_value, autoload)
                VALUES ( %s, 1, 'no' )
				ON DUPLICATE KEY UPDATE
					option_value = option_value + 1",
				self::GENERATE_KEY_ATTEMPT_COUNTER_OPTION
			)
		);
		// phpcs:enable WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize

		wp_cache_delete( self::GENERATE_KEY_ATTEMPT_COUNTER_OPTION, 'options' );
	}
}
