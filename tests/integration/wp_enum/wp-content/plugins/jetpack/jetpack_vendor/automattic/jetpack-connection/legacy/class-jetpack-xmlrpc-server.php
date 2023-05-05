<?php
/**
 * Jetpack XMLRPC Server.
 *
 * @package automattic/jetpack-connection
 */

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Connection\Secrets;
use Automattic\Jetpack\Connection\Tokens;
use Automattic\Jetpack\Connection\Urls;
use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Roles;

/**
 * Just a sack of functions.  Not actually an IXR_Server
 */
class Jetpack_XMLRPC_Server {
	/**
	 * The current error object
	 *
	 * @var \WP_Error
	 */
	public $error = null;

	/**
	 * The current user
	 *
	 * @var \WP_User
	 */
	public $user = null;

	/**
	 * The connection manager object.
	 *
	 * @var Automattic\Jetpack\Connection\Manager
	 */
	private $connection;

	/**
	 * Creates a new XMLRPC server object.
	 */
	public function __construct() {
		$this->connection = new Connection_Manager();
	}

	/**
	 * Whitelist of the XML-RPC methods available to the Jetpack Server. If the
	 * user is not authenticated (->login()) then the methods are never added,
	 * so they will get a "does not exist" error.
	 *
	 * @param array $core_methods Core XMLRPC methods.
	 */
	public function xmlrpc_methods( $core_methods ) {
		$jetpack_methods = array(
			'jetpack.verifyAction'     => array( $this, 'verify_action' ),
			'jetpack.idcUrlValidation' => array( $this, 'validate_urls_for_idc_mitigation' ),
			'jetpack.unlinkUser'       => array( $this, 'unlink_user' ),
			'jetpack.testConnection'   => array( $this, 'test_connection' ),
		);

		$jetpack_methods = array_merge( $jetpack_methods, $this->provision_xmlrpc_methods() );

		$this->user = $this->login();

		if ( $this->user ) {
			$jetpack_methods = array_merge(
				$jetpack_methods,
				array(
					'jetpack.testAPIUserCode' => array( $this, 'test_api_user_code' ),
				)
			);

			if ( isset( $core_methods['metaWeblog.editPost'] ) ) {
				$jetpack_methods['metaWeblog.newMediaObject']      = $core_methods['metaWeblog.newMediaObject'];
				$jetpack_methods['jetpack.updateAttachmentParent'] = array( $this, 'update_attachment_parent' );
			}

			/**
			 * Filters the XML-RPC methods available to Jetpack for authenticated users.
			 *
			 * @since 1.7.0
			 * @since-jetpack 1.1.0
			 *
			 * @param array    $jetpack_methods XML-RPC methods available to the Jetpack Server.
			 * @param array    $core_methods    Available core XML-RPC methods.
			 * @param \WP_User $user            Information about the user authenticated in the request.
			 */
			$jetpack_methods = apply_filters( 'jetpack_xmlrpc_methods', $jetpack_methods, $core_methods, $this->user );
		}

		/**
		 * Filters the XML-RPC methods available to Jetpack for requests signed both with a blog token or a user token.
		 *
		 * @since 1.7.0
		 * @since 1.9.5 Introduced the $user parameter.
		 * @since-jetpack 3.0.0
		 *
		 * @param array         $jetpack_methods XML-RPC methods available to the Jetpack Server.
		 * @param array         $core_methods    Available core XML-RPC methods.
		 * @param \WP_User|bool $user            Information about the user authenticated in the request. False if authenticated with blog token.
		 */
		return apply_filters( 'jetpack_xmlrpc_unauthenticated_methods', $jetpack_methods, $core_methods, $this->user );
	}

	/**
	 * Whitelist of the bootstrap XML-RPC methods
	 */
	public function bootstrap_xmlrpc_methods() {
		return array(
			'jetpack.remoteAuthorize' => array( $this, 'remote_authorize' ),
			'jetpack.remoteRegister'  => array( $this, 'remote_register' ),
		);
	}

	/**
	 * Additional method needed for authorization calls.
	 */
	public function authorize_xmlrpc_methods() {
		return array(
			'jetpack.remoteAuthorize' => array( $this, 'remote_authorize' ),
			'jetpack.remoteRegister'  => array( $this, 'remote_already_registered' ),
		);
	}

	/**
	 * Remote provisioning methods.
	 */
	public function provision_xmlrpc_methods() {
		return array(
			'jetpack.remoteRegister'  => array( $this, 'remote_register' ),
			'jetpack.remoteProvision' => array( $this, 'remote_provision' ),
			'jetpack.remoteConnect'   => array( $this, 'remote_connect' ),
			'jetpack.getUser'         => array( $this, 'get_user' ),
		);
	}

	/**
	 * Used to verify whether a local user exists and what role they have.
	 *
	 * @param int|string|array $request One of:
	 *                         int|string The local User's ID, username, or email address.
	 *                         array      A request array containing:
	 *                                    0: int|string The local User's ID, username, or email address.
	 *
	 * @return array|\IXR_Error Information about the user, or error if no such user found:
	 *                          roles:     string[] The user's rols.
	 *                          login:     string   The user's username.
	 *                          email_hash string[] The MD5 hash of the user's normalized email address.
	 *                          caps       string[] The user's capabilities.
	 *                          allcaps    string[] The user's granular capabilities, merged from role capabilities.
	 *                          token_key  string   The Token Key of the user's Jetpack token. Empty string if none.
	 */
	public function get_user( $request ) {
		$user_id = is_array( $request ) ? $request[0] : $request;

		if ( ! $user_id ) {
			return $this->error(
				new \WP_Error(
					'invalid_user',
					__( 'Invalid user identifier.', 'jetpack-connection' ),
					400
				),
				'get_user'
			);
		}

		$user = $this->get_user_by_anything( $user_id );

		if ( ! $user ) {
			return $this->error(
				new \WP_Error(
					'user_unknown',
					__( 'User not found.', 'jetpack-connection' ),
					404
				),
				'get_user'
			);
		}

		$user_token = ( new Tokens() )->get_access_token( $user->ID );

		if ( $user_token ) {
			list( $user_token_key ) = explode( '.', $user_token->secret );
			if ( $user_token_key === $user_token->secret ) {
				$user_token_key = '';
			}
		} else {
			$user_token_key = '';
		}

		return array(
			'id'         => $user->ID,
			'login'      => $user->user_login,
			'email_hash' => md5( strtolower( trim( $user->user_email ) ) ),
			'roles'      => $user->roles,
			'caps'       => $user->caps,
			'allcaps'    => $user->allcaps,
			'token_key'  => $user_token_key,
		);
	}

	/**
	 * Remote authorization XMLRPC method handler.
	 *
	 * @param array $request the request.
	 */
	public function remote_authorize( $request ) {
		$user = get_user_by( 'id', $request['state'] );

		/**
		 * Happens on various request handling events in the Jetpack XMLRPC server.
		 * The action combines several types of events:
		 *    - remote_authorize
		 *    - remote_provision
		 *    - get_user.
		 *
		 * @since 1.7.0
		 * @since-jetpack 8.0.0
		 *
		 * @param String  $action the action name, i.e., 'remote_authorize'.
		 * @param String  $stage  the execution stage, can be 'begin', 'success', 'error', etc.
		 * @param array   $parameters extra parameters from the event.
		 * @param WP_User $user the acting user.
		 */
		do_action( 'jetpack_xmlrpc_server_event', 'remote_authorize', 'begin', array(), $user );

		foreach ( array( 'secret', 'state', 'redirect_uri', 'code' ) as $required ) {
			if ( ! isset( $request[ $required ] ) || empty( $request[ $required ] ) ) {
				return $this->error(
					new \WP_Error( 'missing_parameter', 'One or more parameters is missing from the request.', 400 ),
					'remote_authorize'
				);
			}
		}

		if ( ! $user ) {
			return $this->error( new \WP_Error( 'user_unknown', 'User not found.', 404 ), 'remote_authorize' );
		}

		if ( $this->connection->has_connected_owner() && $this->connection->is_user_connected( $request['state'] ) ) {
			return $this->error( new \WP_Error( 'already_connected', 'User already connected.', 400 ), 'remote_authorize' );
		}

		$verified = $this->verify_action( array( 'authorize', $request['secret'], $request['state'] ) );

		if ( is_a( $verified, 'IXR_Error' ) ) {
			return $this->error( $verified, 'remote_authorize' );
		}

		wp_set_current_user( $request['state'] );

		$result = $this->connection->authorize( $request );

		if ( is_wp_error( $result ) ) {
			return $this->error( $result, 'remote_authorize' );
		}

		// This action is documented in class.jetpack-xmlrpc-server.php.
		do_action( 'jetpack_xmlrpc_server_event', 'remote_authorize', 'success' );

		return array(
			'result' => $result,
		);
	}

	/**
	 * This XML-RPC method is called from the /jpphp/provision endpoint on WPCOM in order to
	 * register this site so that a plan can be provisioned.
	 *
	 * @param array $request An array containing at minimum nonce and local_user keys.
	 *
	 * @return \WP_Error|array
	 */
	public function remote_register( $request ) {
		// This action is documented in class.jetpack-xmlrpc-server.php.
		do_action( 'jetpack_xmlrpc_server_event', 'remote_register', 'begin', array() );

		$user = $this->fetch_and_verify_local_user( $request );

		if ( ! $user ) {
			return $this->error(
				new WP_Error( 'input_error', __( 'Valid user is required', 'jetpack-connection' ), 400 ),
				'remote_register'
			);
		}

		if ( is_wp_error( $user ) || is_a( $user, 'IXR_Error' ) ) {
			return $this->error( $user, 'remote_register' );
		}

		if ( empty( $request['nonce'] ) ) {
			return $this->error(
				new \WP_Error(
					'nonce_missing',
					__( 'The required "nonce" parameter is missing.', 'jetpack-connection' ),
					400
				),
				'remote_register'
			);
		}

		$nonce = sanitize_text_field( $request['nonce'] );
		unset( $request['nonce'] );

		$api_url  = $this->connection->api_url( 'partner_provision_nonce_check' );
		$response = Client::_wp_remote_request(
			esc_url_raw( add_query_arg( 'nonce', $nonce, $api_url ) ),
			array( 'method' => 'GET' ),
			true
		);

		if (
			200 !== wp_remote_retrieve_response_code( $response ) ||
			'OK' !== trim( wp_remote_retrieve_body( $response ) )
		) {
			return $this->error(
				new \WP_Error(
					'invalid_nonce',
					__( 'There was an issue validating this request.', 'jetpack-connection' ),
					400
				),
				'remote_register'
			);
		}

		if ( ! Jetpack_Options::get_option( 'id' ) || ! ( new Tokens() )->get_access_token() || ! empty( $request['force'] ) ) {
			wp_set_current_user( $user->ID );

			// This code mostly copied from Jetpack::admin_page_load.
			if ( isset( $request['from'] ) ) {
				$this->connection->add_register_request_param( 'from', (string) $request['from'] );
			}
			$registered = $this->connection->try_registration();
			if ( is_wp_error( $registered ) ) {
				return $this->error( $registered, 'remote_register' );
			} elseif ( ! $registered ) {
				return $this->error(
					new \WP_Error(
						'registration_error',
						__( 'There was an unspecified error registering the site', 'jetpack-connection' ),
						400
					),
					'remote_register'
				);
			}
		}

		// This action is documented in class.jetpack-xmlrpc-server.php.
		do_action( 'jetpack_xmlrpc_server_event', 'remote_register', 'success' );

		return array(
			'client_id' => Jetpack_Options::get_option( 'id' ),
		);
	}

	/**
	 * This is a substitute for remote_register() when the blog is already registered which returns an error code
	 * signifying that state.
	 * This is an unauthorized call and we should not be responding with any data other than the error code.
	 *
	 * @return \IXR_Error
	 */
	public function remote_already_registered() {
		return $this->error(
			new \WP_Error( 'already_registered', __( 'Blog is already registered', 'jetpack-connection' ), 400 ),
			'remote_register'
		);
	}

	/**
	 * This XML-RPC method is called from the /jpphp/provision endpoint on WPCOM in order to
	 * register this site so that a plan can be provisioned.
	 *
	 * @param array $request An array containing at minimum a nonce key and a local_username key.
	 *
	 * @return \WP_Error|array
	 */
	public function remote_provision( $request ) {
		$user = $this->fetch_and_verify_local_user( $request );

		if ( ! $user ) {
			return $this->error(
				new WP_Error( 'input_error', __( 'Valid user is required', 'jetpack-connection' ), 400 ),
				'remote_provision'
			);
		}

		if ( is_wp_error( $user ) || is_a( $user, 'IXR_Error' ) ) {
			return $this->error( $user, 'remote_provision' );
		}

		$site_icon = get_site_icon_url();

		/**
		 * Filters the Redirect URI returned by the remote_register XMLRPC method
		 *
		 * @param string $redirect_uri The Redirect URI
		 *
		 * @since 1.9.7
		 */
		$redirect_uri = apply_filters( 'jetpack_xmlrpc_remote_register_redirect_uri', admin_url() );

		// Generate secrets.
		$roles   = new Roles();
		$role    = $roles->translate_user_to_role( $user );
		$secrets = ( new Secrets() )->generate( 'authorize', $user->ID );

		$response = array(
			'jp_version'   => Constants::get_constant( 'JETPACK__VERSION' ),
			'redirect_uri' => $redirect_uri,
			'user_id'      => $user->ID,
			'user_email'   => $user->user_email,
			'user_login'   => $user->user_login,
			'scope'        => $this->connection->sign_role( $role, $user->ID ),
			'secret'       => $secrets['secret_1'],
			'is_active'    => $this->connection->has_connected_owner(),
		);

		if ( $site_icon ) {
			$response['site_icon'] = $site_icon;
		}

		/**
		 * Filters the response of the remote_provision XMLRPC method
		 *
		 * @param array    $response The response.
		 * @param array    $request An array containing at minimum a nonce key and a local_username key.
		 * @param \WP_User $user The local authenticated user.
		 *
		 * @since 1.9.7
		 */
		$response = apply_filters( 'jetpack_remote_xmlrpc_provision_response', $response, $request, $user );

		return $response;
	}

	/**
	 * Given an array containing a local user identifier and a nonce, will attempt to fetch and set
	 * an access token for the given user.
	 *
	 * @param array       $request    An array containing local_user and nonce keys at minimum.
	 * @param \IXR_Client $ixr_client The client object, optional.
	 * @return mixed
	 */
	public function remote_connect( $request, $ixr_client = false ) {
		if ( $this->connection->has_connected_owner() ) {
			return $this->error(
				new WP_Error(
					'already_connected',
					__( 'Jetpack is already connected.', 'jetpack-connection' ),
					400
				),
				'remote_connect'
			);
		}

		$user = $this->fetch_and_verify_local_user( $request );

		if ( ! $user || is_wp_error( $user ) || is_a( $user, 'IXR_Error' ) ) {
			return $this->error(
				new WP_Error(
					'input_error',
					__( 'Valid user is required.', 'jetpack-connection' ),
					400
				),
				'remote_connect'
			);
		}

		if ( empty( $request['nonce'] ) ) {
			return $this->error(
				new WP_Error(
					'input_error',
					__( 'A non-empty nonce must be supplied.', 'jetpack-connection' ),
					400
				),
				'remote_connect'
			);
		}

		if ( ! $ixr_client ) {
			$ixr_client = new Jetpack_IXR_Client();
		}
		// TODO: move this query into the Tokens class?
		$ixr_client->query(
			'jetpack.getUserAccessToken',
			array(
				'nonce'            => sanitize_text_field( $request['nonce'] ),
				'external_user_id' => $user->ID,
			)
		);

		$token = $ixr_client->isError() ? false : $ixr_client->getResponse();
		if ( empty( $token ) ) {
			return $this->error(
				new WP_Error(
					'token_fetch_failed',
					__( 'Failed to fetch user token from WordPress.com.', 'jetpack-connection' ),
					400
				),
				'remote_connect'
			);
		}
		$token = sanitize_text_field( $token );

		( new Tokens() )->update_user_token( $user->ID, sprintf( '%s.%d', $token, $user->ID ), true );

		/**
		 * Hook fired at the end of the jetpack.remoteConnect XML-RPC callback
		 *
		 * @since 1.9.7
		 */
		do_action( 'jetpack_remote_connect_end' );

		return $this->connection->has_connected_owner();
	}

	/**
	 * Getter for the local user to act as.
	 *
	 * @param array $request the current request data.
	 */
	private function fetch_and_verify_local_user( $request ) {
		if ( empty( $request['local_user'] ) ) {
			return $this->error(
				new \WP_Error(
					'local_user_missing',
					__( 'The required "local_user" parameter is missing.', 'jetpack-connection' ),
					400
				),
				'remote_provision'
			);
		}

		// Local user is used to look up by login, email or ID.
		$local_user_info = $request['local_user'];

		return $this->get_user_by_anything( $local_user_info );
	}

	/**
	 * Gets the user object by its data.
	 *
	 * @param string $user_id can be any identifying user data.
	 */
	private function get_user_by_anything( $user_id ) {
		$user = get_user_by( 'login', $user_id );

		if ( ! $user ) {
			$user = get_user_by( 'email', $user_id );
		}

		if ( ! $user ) {
			$user = get_user_by( 'ID', $user_id );
		}

		return $user;
	}

	/**
	 * Possible error_codes:
	 *
	 * - verify_secret_1_missing
	 * - verify_secret_1_malformed
	 * - verify_secrets_missing: verification secrets are not found in database
	 * - verify_secrets_incomplete: verification secrets are only partially found in database
	 * - verify_secrets_expired: verification secrets have expired
	 * - verify_secrets_mismatch: stored secret_1 does not match secret_1 sent by Jetpack.WordPress.com
	 * - state_missing: required parameter of state not found
	 * - state_malformed: state is not a digit
	 * - invalid_state: state in request does not match the stored state
	 *
	 * The 'authorize' and 'register' actions have additional error codes
	 *
	 * state_missing: a state ( user id ) was not supplied
	 * state_malformed: state is not the correct data type
	 * invalid_state: supplied state does not match the stored state
	 *
	 * @param array $params action An array of 3 parameters:
	 *     [0]: string action. Possible values are `authorize`, `publicize` and `register`.
	 *     [1]: string secret_1.
	 *     [2]: int state.
	 * @return \IXR_Error|string IXR_Error on failure, secret_2 on success.
	 */
	public function verify_action( $params ) {
		$action        = isset( $params[0] ) ? $params[0] : '';
		$verify_secret = isset( $params[1] ) ? $params[1] : '';
		$state         = isset( $params[2] ) ? $params[2] : '';

		$result = ( new Secrets() )->verify( $action, $verify_secret, $state );

		if ( is_wp_error( $result ) ) {
			return $this->error( $result );
		}

		return $result;
	}

	/**
	 * Wrapper for wp_authenticate( $username, $password );
	 *
	 * @return \WP_User|bool
	 */
	public function login() {
		$this->connection->require_jetpack_authentication();
		$user = wp_authenticate( 'username', 'password' );
		if ( is_wp_error( $user ) ) {
			if ( 'authentication_failed' === $user->get_error_code() ) { // Generic error could mean most anything.
				$this->error = new \WP_Error( 'invalid_request', 'Invalid Request', 403 );
			} else {
				$this->error = $user;
			}
			return false;
		} elseif ( ! $user ) { // Shouldn't happen.
			$this->error = new \WP_Error( 'invalid_request', 'Invalid Request', 403 );
			return false;
		}

		wp_set_current_user( $user->ID );

		return $user;
	}

	/**
	 * Returns the current error as an \IXR_Error
	 *
	 * @param \WP_Error|\IXR_Error $error             The error object, optional.
	 * @param string               $event_name The event name.
	 * @param \WP_User             $user              The user object.
	 * @return bool|\IXR_Error
	 */
	public function error( $error = null, $event_name = null, $user = null ) {
		if ( null !== $event_name ) {
			// This action is documented in class.jetpack-xmlrpc-server.php.
			do_action( 'jetpack_xmlrpc_server_event', $event_name, 'fail', $error, $user );
		}

		if ( $error !== null ) {
			$this->error = $error;
		}

		if ( is_wp_error( $this->error ) ) {
			$code = $this->error->get_error_data();
			if ( ! $code ) {
				$code = -10520;
			}
			$message = sprintf( 'Jetpack: [%s] %s', $this->error->get_error_code(), $this->error->get_error_message() );
			if ( ! class_exists( \IXR_Error::class ) ) {
				require_once ABSPATH . WPINC . '/class-IXR.php';
			}
			return new \IXR_Error( $code, $message );
		} elseif ( is_a( $this->error, 'IXR_Error' ) ) {
			return $this->error;
		}

		return false;
	}

	/* API Methods */

	/**
	 * Just authenticates with the given Jetpack credentials.
	 *
	 * @return string A success string. The Jetpack plugin filters it and make it return the Jetpack plugin version.
	 */
	public function test_connection() {
		/**
		 * Filters the successful response of the XMLRPC test_connection method
		 *
		 * @param string $response The response string.
		 */
		return apply_filters( 'jetpack_xmlrpc_test_connection_response', 'success' );
	}

	/**
	 * Test the API user code.
	 *
	 * @param array $args arguments identifying the test site.
	 */
	public function test_api_user_code( $args ) {
		$client_id = (int) $args[0];
		$user_id   = (int) $args[1];
		$nonce     = (string) $args[2];
		$verify    = (string) $args[3];

		if ( ! $client_id || ! $user_id || ! strlen( $nonce ) || 32 !== strlen( $verify ) ) {
			return false;
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $user || is_wp_error( $user ) ) {
			return false;
		}

		/* phpcs:ignore
		 debugging
		error_log( "CLIENT: $client_id" );
		error_log( "USER:   $user_id" );
		error_log( "NONCE:  $nonce" );
		error_log( "VERIFY: $verify" );
		*/

		$jetpack_token = ( new Tokens() )->get_access_token( $user_id );

		$api_user_code = get_user_meta( $user_id, "jetpack_json_api_$client_id", true );
		if ( ! $api_user_code ) {
			return false;
		}

		$hmac = hash_hmac(
			'md5',
			json_encode( // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
				(object) array(
					'client_id' => (int) $client_id,
					'user_id'   => (int) $user_id,
					'nonce'     => (string) $nonce,
					'code'      => (string) $api_user_code,
				)
			),
			$jetpack_token->secret
		);

		if ( ! hash_equals( $hmac, $verify ) ) {
			return false;
		}

		return $user_id;
	}

	/**
	 * Unlink a user from WordPress.com
	 *
	 * When the request is done without any parameter, this XMLRPC callback gets an empty array as input.
	 *
	 * If $user_id is not provided, it will try to disconnect the current logged in user. This will fail if called by the Master User.
	 *
	 * If $user_id is is provided, it will try to disconnect the informed user, even if it's the Master User.
	 *
	 * @param mixed $user_id The user ID to disconnect from this site.
	 */
	public function unlink_user( $user_id = array() ) {
		$user_id = (int) $user_id;
		if ( $user_id < 1 ) {
			$user_id = null;
		}
		/**
		 * Fired when we want to log an event to the Jetpack event log.
		 *
		 * @since 1.7.0
		 * @since-jetpack 7.7.0
		 *
		 * @param string $code Unique name for the event.
		 * @param string $data Optional data about the event.
		 */
		do_action( 'jetpack_event_log', 'unlink' );
		return $this->connection->disconnect_user(
			$user_id,
			(bool) $user_id
		);
	}

	/**
	 * Returns the home URL and site URL for the current site which can be used on the WPCOM side for
	 * IDC mitigation to decide whether sync should be allowed if the home and siteurl values differ between WPCOM
	 * and the remote Jetpack site.
	 *
	 * @return array
	 */
	public function validate_urls_for_idc_mitigation() {
		return array(
			'home'    => Urls::home_url(),
			'siteurl' => Urls::site_url(),
		);
	}

	/**
	 * Updates the attachment parent object.
	 *
	 * @param array $args attachment and parent identifiers.
	 */
	public function update_attachment_parent( $args ) {
		$attachment_id = (int) $args[0];
		$parent_id     = (int) $args[1];

		return wp_update_post(
			array(
				'ID'          => $attachment_id,
				'post_parent' => $parent_id,
			)
		);
	}

	/**
	 * Deprecated: This method is no longer part of the Connection package and now lives on the Jetpack plugin.
	 *
	 * Disconnect this blog from the connected wordpress.com account
	 *
	 * @deprecated since 1.25.0
	 * @see Jetpack_XMLRPC_Methods::disconnect_blog() in the Jetpack plugin
	 *
	 * @return boolean
	 */
	public function disconnect_blog() {
		_deprecated_function( __METHOD__, '1.25.0', 'Jetpack_XMLRPC_Methods::disconnect_blog()' );
		if ( class_exists( 'Jetpack_XMLRPC_Methods' ) ) {
			return Jetpack_XMLRPC_Methods::disconnect_blog();
		}
		return false;
	}

	/**
	 * Deprecated: This method is no longer part of the Connection package and now lives on the Jetpack plugin.
	 *
	 * Returns what features are available. Uses the slug of the module files.
	 *
	 * @deprecated since 1.25.0
	 * @see Jetpack_XMLRPC_Methods::features_available() in the Jetpack plugin
	 *
	 * @return array
	 */
	public function features_available() {
		_deprecated_function( __METHOD__, '1.25.0', 'Jetpack_XMLRPC_Methods::features_available()' );
		if ( class_exists( 'Jetpack_XMLRPC_Methods' ) ) {
			return Jetpack_XMLRPC_Methods::features_available();
		}
		return array();
	}

	/**
	 * Deprecated: This method is no longer part of the Connection package and now lives on the Jetpack plugin.
	 *
	 * Returns what features are enabled. Uses the slug of the modules files.
	 *
	 * @deprecated since 1.25.0
	 * @see Jetpack_XMLRPC_Methods::features_enabled() in the Jetpack plugin
	 *
	 * @return array
	 */
	public function features_enabled() {
		_deprecated_function( __METHOD__, '1.25.0', 'Jetpack_XMLRPC_Methods::features_enabled()' );
		if ( class_exists( 'Jetpack_XMLRPC_Methods' ) ) {
			return Jetpack_XMLRPC_Methods::features_enabled();
		}
		return array();
	}

	/**
	 * Deprecated: This method is no longer part of the Connection package and now lives on the Jetpack plugin.
	 *
	 * Serve a JSON API request.
	 *
	 * @deprecated since 1.25.0
	 * @see Jetpack_XMLRPC_Methods::json_api() in the Jetpack plugin
	 *
	 * @param array $args request arguments.
	 */
	public function json_api( $args = array() ) {
		_deprecated_function( __METHOD__, '1.25.0', 'Jetpack_XMLRPC_Methods::json_api()' );
		if ( class_exists( 'Jetpack_XMLRPC_Methods' ) ) {
			return Jetpack_XMLRPC_Methods::json_api( $args );
		}
		return array();
	}

}
