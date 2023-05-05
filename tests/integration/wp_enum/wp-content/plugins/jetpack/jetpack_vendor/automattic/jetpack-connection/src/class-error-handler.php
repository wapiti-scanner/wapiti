<?php
/**
 * The Jetpack Connection error class file.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

/**
 * The Jetpack Connection Errors that handles errors
 *
 * This class handles the following workflow:
 *
 * 1. A XML-RCP request with an invalid signature triggers a error
 * 2. Applies a gate to only process each error code once an hour to avoid overflow
 * 3. It stores the error on the database, but we don't know yet if this is a valid error, because
 *    we can't confirm it came from WP.com.
 * 4. It encrypts the error details and send it to thw wp.com server
 * 5. wp.com checks it and, if valid, sends a new request back to this site using the verify_xml_rpc_error REST endpoint
 * 6. This endpoint add this error to the Verified errors in the database
 * 7. Triggers a workflow depending on the error (display user an error message, do some self healing, etc.)
 *
 * Errors are stored in the database as options in the following format:
 *
 * [
 *   $error_code => [
 *     $user_id => [
 *       $error_details
 *     ]
 *   ]
 * ]
 *
 * For each error code we store a maximum of 5 errors for 5 different user ids.
 *
 * An user ID can be
 * * 0 for blog tokens
 * * positive integer for user tokens
 * * 'invalid' for malformed tokens
 *
 * @since 1.14.2
 */
class Error_Handler {

	/**
	 * The name of the option that stores the errors
	 *
	 * @since 1.14.2
	 *
	 * @var string
	 */
	const STORED_ERRORS_OPTION = 'jetpack_connection_xmlrpc_errors';

	/**
	 * The name of the option that stores the errors
	 *
	 * @since 1.14.2
	 *
	 * @var string
	 */
	const STORED_VERIFIED_ERRORS_OPTION = 'jetpack_connection_xmlrpc_verified_errors';

	/**
	 * The prefix of the transient that controls the gate for each error code
	 *
	 * @since 1.14.2
	 *
	 * @var string
	 */
	const ERROR_REPORTING_GATE = 'jetpack_connection_error_reporting_gate_';

	/**
	 * Time in seconds a test should live in the database before being discarded
	 *
	 * @since 1.14.2
	 */
	const ERROR_LIFE_TIME = DAY_IN_SECONDS;

	/**
	 * The error code for event tracking purposes.
	 * If there are many, only the first error code will be tracked.
	 *
	 * @var string
	 */
	private $error_code;

	/**
	 * List of known errors. Only error codes in this list will be handled
	 *
	 * @since 1.14.2
	 *
	 * @var array
	 */
	public $known_errors = array(
		'malformed_token',
		'malformed_user_id',
		'unknown_user',
		'no_user_tokens',
		'empty_master_user_option',
		'no_token_for_user',
		'token_malformed',
		'user_id_mismatch',
		'no_possible_tokens',
		'no_valid_user_token',
		'no_valid_blog_token',
		'unknown_token',
		'could_not_sign',
		'invalid_scheme',
		'invalid_secret',
		'invalid_token',
		'token_mismatch',
		'invalid_body',
		'invalid_signature',
		'invalid_body_hash',
		'invalid_nonce',
		'signature_mismatch',
	);

	/**
	 * Holds the instance of this singleton class
	 *
	 * @since 1.14.2
	 *
	 * @var Error_Handler $instance
	 */
	public static $instance = null;

	/**
	 * Initialize instance, hookds and load verified errors handlers
	 *
	 * @since 1.14.2
	 */
	private function __construct() {
		defined( 'JETPACK__ERRORS_PUBLIC_KEY' ) || define( 'JETPACK__ERRORS_PUBLIC_KEY', 'KdZY80axKX+nWzfrOcizf0jqiFHnrWCl9X8yuaClKgM=' );

		add_action( 'rest_api_init', array( $this, 'register_verify_error_endpoint' ) );

		$this->handle_verified_errors();

		// If the site gets reconnected, clear errors.
		add_action( 'jetpack_site_registered', array( $this, 'delete_all_errors' ) );
		add_action( 'jetpack_get_site_data_success', array( $this, 'delete_all_errors' ) );
		add_filter( 'jetpack_connection_disconnect_site_wpcom', array( $this, 'delete_all_errors_and_return_unfiltered_value' ) );
		add_filter( 'jetpack_connection_delete_all_tokens', array( $this, 'delete_all_errors_and_return_unfiltered_value' ) );
		add_action( 'jetpack_unlinked_user', array( $this, 'delete_all_errors' ) );
		add_action( 'jetpack_updated_user_token', array( $this, 'delete_all_errors' ) );
	}

	/**
	 * Gets the list of verified errors and act upon them
	 *
	 * @since 1.14.2
	 *
	 * @return void
	 */
	public function handle_verified_errors() {
		$verified_errors = $this->get_verified_errors();
		foreach ( array_keys( $verified_errors ) as $error_code ) {
			switch ( $error_code ) {
				case 'malformed_token':
				case 'token_malformed':
				case 'no_possible_tokens':
				case 'no_valid_user_token':
				case 'no_valid_blog_token':
				case 'unknown_token':
				case 'could_not_sign':
				case 'invalid_token':
				case 'token_mismatch':
				case 'invalid_signature':
				case 'signature_mismatch':
				case 'no_user_tokens':
				case 'no_token_for_user':
					add_action( 'admin_notices', array( $this, 'generic_admin_notice_error' ) );
					add_action( 'react_connection_errors_initial_state', array( $this, 'jetpack_react_dashboard_error' ) );
					$this->error_code = $error_code;

					// Since we are only generically handling errors, we don't need to trigger error messages for each one of them.
					break 2;
			}
		}
	}

	/**
	 * Gets the instance of this singleton class
	 *
	 * @since 1.14.2
	 *
	 * @return Error_Handler $instance
	 */
	public static function get_instance() {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Keep track of a connection error that was encountered
	 *
	 * @param \WP_Error $error  The error object.
	 * @param boolean   $force  Force the report, even if should_report_error is false.
	 * @param boolean   $skip_wpcom_verification Set to 'true' to verify the error locally and skip the WP.com verification.
	 *
	 * @return void
	 * @since 1.14.2
	 */
	public function report_error( \WP_Error $error, $force = false, $skip_wpcom_verification = false ) {
		if ( in_array( $error->get_error_code(), $this->known_errors, true ) && $this->should_report_error( $error ) || $force ) {
			$stored_error = $this->store_error( $error );
			if ( $stored_error ) {
				$skip_wpcom_verification ? $this->verify_error( $stored_error ) : $this->send_error_to_wpcom( $stored_error );
			}
		}
	}

	/**
	 * Checks the status of the gate
	 *
	 * This protects the site (and WPCOM) against over loads.
	 *
	 * @since 1.14.2
	 *
	 * @param \WP_Error $error the error object.
	 * @return boolean $should_report True if gate is open and the error should be reported.
	 */
	public function should_report_error( \WP_Error $error ) {
		if ( defined( 'JETPACK_DEV_DEBUG' ) && JETPACK_DEV_DEBUG ) {
			return true;
		}

		/**
		 * Whether to bypass the gate for the error handling
		 *
		 * By default, we only process errors once an hour for each error code.
		 * This is done to avoid overflows. If you need to disable this gate, you can set this variable to true.
		 *
		 * This filter is useful for unit testing
		 *
		 * @since 1.14.2
		 *
		 * @param boolean $bypass_gate whether to bypass the gate. Default is false, do not bypass.
		 */
		$bypass_gate = apply_filters( 'jetpack_connection_bypass_error_reporting_gate', false );
		if ( true === $bypass_gate ) {
			return true;
		}

		$transient = self::ERROR_REPORTING_GATE . $error->get_error_code();

		if ( get_transient( $transient ) ) {
			return false;
		}

		set_transient( $transient, true, HOUR_IN_SECONDS );
		return true;
	}

	/**
	 * Stores the error in the database so we know there is an issue and can inform the user
	 *
	 * @since 1.14.2
	 *
	 * @param \WP_Error $error the error object.
	 * @return boolean|array False if stored errors were not updated and the error array if it was successfully stored.
	 */
	public function store_error( \WP_Error $error ) {

		$stored_errors = $this->get_stored_errors();
		$error_array   = $this->wp_error_to_array( $error );
		$error_code    = $error->get_error_code();
		$user_id       = $error_array['user_id'];

		if ( ! isset( $stored_errors[ $error_code ] ) || ! is_array( $stored_errors[ $error_code ] ) ) {
			$stored_errors[ $error_code ] = array();
		}

		$stored_errors[ $error_code ][ $user_id ] = $error_array;

		// Let's store a maximum of 5 different user ids for each error code.
		if ( count( $stored_errors[ $error_code ] ) > 5 ) {
			// array_shift will destroy keys here because they are numeric, so manually remove first item.
			$keys = array_keys( $stored_errors[ $error_code ] );
			unset( $stored_errors[ $error_code ][ $keys[0] ] );
		}

		if ( update_option( self::STORED_ERRORS_OPTION, $stored_errors ) ) {
			return $error_array;
		}

		return false;
	}

	/**
	 * Converts a WP_Error object in the array representation we store in the database
	 *
	 * @since 1.14.2
	 *
	 * @param \WP_Error $error the error object.
	 * @return boolean|array False if error is invalid or the error array
	 */
	public function wp_error_to_array( \WP_Error $error ) {

		$data = $error->get_error_data();

		if ( ! isset( $data['signature_details'] ) || ! is_array( $data['signature_details'] ) ) {
			return false;
		}

		$signature_details = $data['signature_details'];

		if ( ! isset( $signature_details['token'] ) || empty( $signature_details['token'] ) ) {
			return false;
		}

		$user_id = $this->get_user_id_from_token( $signature_details['token'] );

		$error_array = array(
			'error_code'    => $error->get_error_code(),
			'user_id'       => $user_id,
			'error_message' => $error->get_error_message(),
			'error_data'    => $signature_details,
			'timestamp'     => time(),
			'nonce'         => wp_generate_password( 10, false ),
			'error_type'    => empty( $data['error_type'] ) ? '' : $data['error_type'],
		);

		return $error_array;
	}

	/**
	 * Sends the error to WP.com to be verified
	 *
	 * @since 1.14.2
	 *
	 * @param array $error_array The array representation of the error as it is stored in the database.
	 * @return bool
	 */
	public function send_error_to_wpcom( $error_array ) {

		$blog_id = \Jetpack_Options::get_option( 'id' );

		$encrypted_data = $this->encrypt_data_to_wpcom( $error_array );

		if ( false === $encrypted_data ) {
			return false;
		}

		$args = array(
			'body' => array(
				'error_data' => $encrypted_data,
			),
		);

		// send encrypted data to WP.com Public-API v2.
		wp_remote_post( "https://public-api.wordpress.com/wpcom/v2/sites/{$blog_id}/jetpack-report-error/", $args );
		return true;
	}

	/**
	 * Encrypt data to be sent over to WP.com
	 *
	 * @since 1.14.2
	 *
	 * @param array|string $data the data to be encoded.
	 * @return boolean|string The encoded string on success, false on failure
	 */
	public function encrypt_data_to_wpcom( $data ) {

		try {
			// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			$encrypted_data = base64_encode( sodium_crypto_box_seal( wp_json_encode( $data ), base64_decode( JETPACK__ERRORS_PUBLIC_KEY ) ) );
			// phpcs:enable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			// phpcs:enable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		} catch ( \SodiumException $e ) {
			// error encrypting data.
			return false;
		}

		return $encrypted_data;
	}

	/**
	 * Extracts the user ID from a token
	 *
	 * @since 1.14.2
	 *
	 * @param string $token the token used to make the request.
	 * @return string $the user id or `invalid` if user id not present.
	 */
	public function get_user_id_from_token( $token ) {
		$parsed_token = explode( ':', wp_unslash( $token ) );

		if ( isset( $parsed_token[2] ) && ctype_digit( $parsed_token[2] ) ) {
			$user_id = $parsed_token[2];
		} else {
			$user_id = 'invalid';
		}

		return $user_id;
	}

	/**
	 * Gets the reported errors stored in the database
	 *
	 * @since 1.14.2
	 *
	 * @return array $errors
	 */
	public function get_stored_errors() {

		$stored_errors = get_option( self::STORED_ERRORS_OPTION );

		if ( ! is_array( $stored_errors ) ) {
			$stored_errors = array();
		}

		$stored_errors = $this->garbage_collector( $stored_errors );

		return $stored_errors;
	}

	/**
	 * Gets the verified errors stored in the database
	 *
	 * @since 1.14.2
	 *
	 * @return array $errors
	 */
	public function get_verified_errors() {

		$verified_errors = get_option( self::STORED_VERIFIED_ERRORS_OPTION );

		if ( ! is_array( $verified_errors ) ) {
			$verified_errors = array();
		}

		$verified_errors = $this->garbage_collector( $verified_errors );

		return $verified_errors;
	}

	/**
	 * Removes expired errors from the array
	 *
	 * This method is called by get_stored_errors and get_verified errors and filters their result
	 * Whenever a new error is stored to the database or verified, this will be triggered and the
	 * expired error will be permantently removed from the database
	 *
	 * @since 1.14.2
	 *
	 * @param array $errors array of errors as stored in the database.
	 * @return array
	 */
	private function garbage_collector( $errors ) {
		foreach ( $errors as $error_code => $users ) {
			foreach ( $users as $user_id => $error ) {
				if ( self::ERROR_LIFE_TIME < time() - (int) $error['timestamp'] ) {
					unset( $errors[ $error_code ][ $user_id ] );
				}
			}
		}
		// Clear empty error codes.
		$errors = array_filter(
			$errors,
			function ( $user_errors ) {
				return ! empty( $user_errors );
			}
		);
		return $errors;
	}

	/**
	 * Delete all stored and verified errors from the database
	 *
	 * @since 1.14.2
	 *
	 * @return void
	 */
	public function delete_all_errors() {
		$this->delete_stored_errors();
		$this->delete_verified_errors();
	}

	/**
	 * Delete all stored and verified errors from the database and returns unfiltered value
	 *
	 * This is used to hook into a couple of filters that expect true to not short circuit the disconnection flow
	 *
	 * @since 8.9.0
	 *
	 * @param mixed $check The input sent by the filter.
	 * @return boolean
	 */
	public function delete_all_errors_and_return_unfiltered_value( $check ) {
		$this->delete_all_errors();
		return $check;
	}

	/**
	 * Delete the reported errors stored in the database
	 *
	 * @since 1.14.2
	 *
	 * @return boolean True, if option is successfully deleted. False on failure.
	 */
	public function delete_stored_errors() {
		return delete_option( self::STORED_ERRORS_OPTION );
	}

	/**
	 * Delete the verified errors stored in the database
	 *
	 * @since 1.14.2
	 *
	 * @return boolean True, if option is successfully deleted. False on failure.
	 */
	public function delete_verified_errors() {
		return delete_option( self::STORED_VERIFIED_ERRORS_OPTION );
	}

	/**
	 * Gets an error based on the nonce
	 *
	 * Receives a nonce and finds the related error.
	 *
	 * @since 1.14.2
	 *
	 * @param string $nonce The nonce created for the error we want to get.
	 * @return null|array Returns the error array representation or null if error not found.
	 */
	public function get_error_by_nonce( $nonce ) {
		$errors = $this->get_stored_errors();
		foreach ( $errors as $user_group ) {
			foreach ( $user_group as $error ) {
				if ( $error['nonce'] === $nonce ) {
					return $error;
				}
			}
		}
		return null;
	}

	/**
	 * Adds an error to the verified error list
	 *
	 * @since 1.14.2
	 *
	 * @param array $error The error array, as it was saved in the unverified errors list.
	 * @return void
	 */
	public function verify_error( $error ) {

		$verified_errors = $this->get_verified_errors();
		$error_code      = $error['error_code'];
		$user_id         = $error['user_id'];

		if ( ! isset( $verified_errors[ $error_code ] ) ) {
			$verified_errors[ $error_code ] = array();
		}

		$verified_errors[ $error_code ][ $user_id ] = $error;

		update_option( self::STORED_VERIFIED_ERRORS_OPTION, $verified_errors );
	}

	/**
	 * Register REST API end point for error hanlding.
	 *
	 * @since 1.14.2
	 *
	 * @return void
	 */
	public function register_verify_error_endpoint() {
		register_rest_route(
			'jetpack/v4',
			'/verify_xmlrpc_error',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'verify_xml_rpc_error' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'nonce' => array(
						'required' => true,
						'type'     => 'string',
					),
				),
			)
		);
	}

	/**
	 * Handles verification that a xml rpc error is legit and came from WordPres.com
	 *
	 * @since 1.14.2
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return boolean
	 */
	public function verify_xml_rpc_error( \WP_REST_Request $request ) {
		$error = $this->get_error_by_nonce( $request['nonce'] );

		if ( $error ) {
			$this->verify_error( $error );
			return new \WP_REST_Response( true, 200 );
		}

		return new \WP_REST_Response( false, 200 );
	}

	/**
	 * Prints a generic error notice for all connection errors
	 *
	 * @since 8.9.0
	 *
	 * @return void
	 */
	public function generic_admin_notice_error() {
		// do not add admin notice to the jetpack dashboard.
		global $pagenow;
		if ( 'admin.php' === $pagenow || isset( $_GET['page'] ) && 'jetpack' === $_GET['page'] ) { // phpcs:ignore
			return;
		}

		if ( ! current_user_can( 'jetpack_connect' ) ) {
			return;
		}

		/**
		 * Filters the message to be displayed in the admin notices area when there's a connection error.
		 *
		 * By default  we don't display any errors.
		 *
		 * Return an empty value to disable the message.
		 *
		 * @since 8.9.0
		 *
		 * @param string $message The error message.
		 * @param array  $errors The array of errors. See Automattic\Jetpack\Connection\Error_Handler for details on the array structure.
		 */
		$message = apply_filters( 'jetpack_connection_error_notice_message', '', $this->get_verified_errors() );

		/**
		 * Fires inside the admin_notices hook just before displaying the error message for a broken connection.
		 *
		 * If you want to disable the default message from being displayed, return an emtpy value in the jetpack_connection_error_notice_message filter.
		 *
		 * @since 8.9.0
		 *
		 * @param array $errors The array of errors. See Automattic\Jetpack\Connection\Error_Handler for details on the array structure.
		 */
		do_action( 'jetpack_connection_error_notice', $this->get_verified_errors() );

		if ( empty( $message ) ) {
			return;
		}

		?>
		<div class="notice notice-error is-dismissible jetpack-message jp-connect" style="display:block !important;">
			<p><?php echo esc_html( $message ); ?></p>
		</div>
		<?php
	}

	/**
	 * Adds the error message to the Jetpack React Dashboard
	 *
	 * @since 8.9.0
	 *
	 * @param array $errors The array of errors. See Automattic\Jetpack\Connection\Error_Handler for details on the array structure.
	 * @return array
	 */
	public function jetpack_react_dashboard_error( $errors ) {
		$errors[] = array(
			'code'    => 'connection_error',
			'message' => __( 'Your connection with WordPress.com seems to be broken. If you\'re experiencing issues, please try reconnecting.', 'jetpack-connection' ),
			'action'  => 'reconnect',
			'data'    => array( 'api_error_code' => $this->error_code ),
		);
		return $errors;
	}

	/**
	 * Check REST API response for errors, and report them to WP.com if needed.
	 *
	 * @see wp_remote_request() For more information on the $http_response array format.
	 * @param array|\WP_Error $http_response The response or WP_Error on failure.
	 * @param array           $auth_data Auth data, allowed keys: `token`, `timestamp`, `nonce`, `body-hash`.
	 * @param string          $url Request URL.
	 * @param string          $method Request method.
	 * @param string          $error_type The source of an error: 'xmlrpc' or 'rest'.
	 *
	 * @return void
	 */
	public function check_api_response_for_errors( $http_response, $auth_data, $url, $method, $error_type ) {
		if ( 200 === wp_remote_retrieve_response_code( $http_response ) || ! is_array( $auth_data ) || ! $url || ! $method ) {
			return;
		}

		$body_raw = wp_remote_retrieve_body( $http_response );
		if ( ! $body_raw ) {
			return;
		}

		$body = json_decode( $body_raw, true );
		if ( empty( $body['error'] ) || ( ! is_string( $body['error'] ) && ! is_int( $body['error'] ) ) ) {
			return;
		}

		$error = new \WP_Error(
			$body['error'],
			empty( $body['message'] ) ? '' : $body['message'],
			array(
				'signature_details' => array(
					'token'     => empty( $auth_data['token'] ) ? '' : $auth_data['token'],
					'timestamp' => empty( $auth_data['timestamp'] ) ? '' : $auth_data['timestamp'],
					'nonce'     => empty( $auth_data['nonce'] ) ? '' : $auth_data['nonce'],
					'body_hash' => empty( $auth_data['body_hash'] ) ? '' : $auth_data['body_hash'],
					'method'    => $method,
					'url'       => $url,
				),
				'error_type'        => in_array( $error_type, array( 'xmlrpc', 'rest' ), true ) ? $error_type : '',
			)
		);

		$this->report_error( $error, false, true );
	}

}
