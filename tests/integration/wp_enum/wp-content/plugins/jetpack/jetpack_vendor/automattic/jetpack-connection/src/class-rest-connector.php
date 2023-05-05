<?php
/**
 * Sets up the Connection REST API endpoints.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Status;
use Jetpack_XMLRPC_Server;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

/**
 * Registers the REST routes for Connections.
 */
class REST_Connector {
	/**
	 * The Connection Manager.
	 *
	 * @var Manager
	 */
	private $connection;

	/**
	 * This property stores the localized "Insufficient Permissions" error message.
	 *
	 * @var string Generic error message when user is not allowed to perform an action.
	 */
	private static $user_permissions_error_msg;

	const JETPACK__DEBUGGER_PUBLIC_KEY = "\r\n" . '-----BEGIN PUBLIC KEY-----' . "\r\n"
	. 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm+uLLVoxGCY71LS6KFc6' . "\r\n"
	. '1UnF6QGBAsi5XF8ty9kR3/voqfOkpW+gRerM2Kyjy6DPCOmzhZj7BFGtxSV2ZoMX' . "\r\n"
	. '9ZwWxzXhl/Q/6k8jg8BoY1QL6L2K76icXJu80b+RDIqvOfJruaAeBg1Q9NyeYqLY' . "\r\n"
	. 'lEVzN2vIwcFYl+MrP/g6Bc2co7Jcbli+tpNIxg4Z+Hnhbs7OJ3STQLmEryLpAxQO' . "\r\n"
	. 'q8cbhQkMx+FyQhxzSwtXYI/ClCUmTnzcKk7SgGvEjoKGAmngILiVuEJ4bm7Q1yok' . "\r\n"
	. 'xl9+wcfW6JAituNhml9dlHCWnn9D3+j8pxStHihKy2gVMwiFRjLEeD8K/7JVGkb/' . "\r\n"
	. 'EwIDAQAB' . "\r\n"
	. '-----END PUBLIC KEY-----' . "\r\n";

	/**
	 * Constructor.
	 *
	 * @param Manager $connection The Connection Manager.
	 */
	public function __construct( Manager $connection ) {
		$this->connection = $connection;

		self::$user_permissions_error_msg = esc_html__(
			'You do not have the correct user permissions to perform this action.
			Please contact your site admin if you think this is a mistake.',
			'jetpack-connection'
		);

		$jp_version = Constants::get_constant( 'JETPACK__VERSION' );

		if ( ! $this->connection->has_connected_owner() ) {
			// Register a site.
			register_rest_route(
				'jetpack/v4',
				'/verify_registration',
				array(
					'methods'             => WP_REST_Server::EDITABLE,
					'callback'            => array( $this, 'verify_registration' ),
					'permission_callback' => '__return_true',
				)
			);
		}

		// Authorize a remote user.
		register_rest_route(
			'jetpack/v4',
			'/remote_authorize',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::remote_authorize',
				'permission_callback' => '__return_true',
			)
		);

		// Get current connection status of Jetpack.
		register_rest_route(
			'jetpack/v4',
			'/connection',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::connection_status',
				'permission_callback' => '__return_true',
			)
		);

		// Disconnect site.
		register_rest_route(
			'jetpack/v4',
			'/connection',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::disconnect_site',
				'permission_callback' => __CLASS__ . '::disconnect_site_permission_check',
				'args'                => array(
					'isActive' => array(
						'description'       => __( 'Set to false will trigger the site to disconnect.', 'jetpack-connection' ),
						'validate_callback' => function ( $value ) {
							if ( false !== $value ) {
								return new WP_Error(
									'rest_invalid_param',
									__( 'The isActive argument should be set to false.', 'jetpack-connection' ),
									array( 'status' => 400 )
								);
							}

							return true;
						},
						'required'          => true,
					),
				),
			)
		);

		// We are only registering this route if Jetpack-the-plugin is not active or it's version is ge 10.0-alpha.
		// The reason for doing so is to avoid conflicts between the Connection package and
		// older versions of Jetpack, registering the same route twice.
		if ( empty( $jp_version ) || version_compare( $jp_version, '10.0-alpha', '>=' ) ) {
			// Get current user connection data.
			register_rest_route(
				'jetpack/v4',
				'/connection/data',
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => __CLASS__ . '::get_user_connection_data',
					'permission_callback' => __CLASS__ . '::user_connection_data_permission_check',
				)
			);
		}

		// Get list of plugins that use the Jetpack connection.
		register_rest_route(
			'jetpack/v4',
			'/connection/plugins',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_connection_plugins' ),
				'permission_callback' => __CLASS__ . '::connection_plugins_permission_check',
			)
		);

		// Full or partial reconnect in case of connection issues.
		register_rest_route(
			'jetpack/v4',
			'/connection/reconnect',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( $this, 'connection_reconnect' ),
				'permission_callback' => __CLASS__ . '::jetpack_reconnect_permission_check',
			)
		);

		// Register the site (get `blog_token`).
		register_rest_route(
			'jetpack/v4',
			'/connection/register',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( $this, 'connection_register' ),
				'permission_callback' => __CLASS__ . '::jetpack_register_permission_check',
				'args'                => array(
					'from'               => array(
						'description' => __( 'Indicates where the registration action was triggered for tracking/segmentation purposes', 'jetpack-connection' ),
						'type'        => 'string',
					),
					'registration_nonce' => array(
						'description' => __( 'The registration nonce', 'jetpack-connection' ),
						'type'        => 'string',
						'required'    => true,
					),
					'redirect_uri'       => array(
						'description' => __( 'URI of the admin page where the user should be redirected after connection flow', 'jetpack-connection' ),
						'type'        => 'string',
					),
					'plugin_slug'        => array(
						'description' => __( 'Indicates from what plugin the request is coming from', 'jetpack-connection' ),
						'type'        => 'string',
					),
				),
			)
		);

		// Get authorization URL.
		register_rest_route(
			'jetpack/v4',
			'/connection/authorize_url',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'connection_authorize_url' ),
				'permission_callback' => __CLASS__ . '::user_connection_data_permission_check',
				'args'                => array(
					'redirect_uri' => array(
						'description' => __( 'URI of the admin page where the user should be redirected after connection flow', 'jetpack-connection' ),
						'type'        => 'string',
					),
				),
			)
		);

		register_rest_route(
			'jetpack/v4',
			'/user-token',
			array(
				array(
					'methods'             => WP_REST_Server::EDITABLE,
					'callback'            => array( static::class, 'update_user_token' ),
					'permission_callback' => array( static::class, 'update_user_token_permission_check' ),
					'args'                => array(
						'user_token'          => array(
							'description' => __( 'New user token', 'jetpack-connection' ),
							'type'        => 'string',
							'required'    => true,
						),
						'is_connection_owner' => array(
							'description' => __( 'Is connection owner', 'jetpack-connection' ),
							'type'        => 'boolean',
						),
					),
				),
			)
		);

		// Set the connection owner.
		register_rest_route(
			'jetpack/v4',
			'/connection/owner',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( static::class, 'set_connection_owner' ),
				'permission_callback' => array( static::class, 'set_connection_owner_permission_check' ),
				'args'                => array(
					'owner' => array(
						'description' => __( 'New owner', 'jetpack-connection' ),
						'type'        => 'integer',
						'required'    => true,
					),
				),
			)
		);
	}

	/**
	 * Handles verification that a site is registered.
	 *
	 * @since 1.7.0
	 * @since-jetpack 5.4.0
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return string|WP_Error
	 */
	public function verify_registration( WP_REST_Request $request ) {
		$registration_data = array( $request['secret_1'], $request['state'] );

		return $this->connection->handle_registration( $registration_data );
	}

	/**
	 * Handles verification that a site is registered
	 *
	 * @since 1.7.0
	 * @since-jetpack 5.4.0
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return array|wp-error
	 */
	public static function remote_authorize( $request ) {
		$xmlrpc_server = new Jetpack_XMLRPC_Server();
		$result        = $xmlrpc_server->remote_authorize( $request );

		if ( is_a( $result, 'IXR_Error' ) ) {
			$result = new WP_Error( $result->code, $result->message );
		}

		return $result;
	}

	/**
	 * Get connection status for this Jetpack site.
	 *
	 * @since 1.7.0
	 * @since-jetpack 4.3.0
	 *
	 * @param bool $rest_response Should we return a rest response or a simple array. Default to rest response.
	 *
	 * @return WP_REST_Response|array Connection information.
	 */
	public static function connection_status( $rest_response = true ) {
		$status     = new Status();
		$connection = new Manager();

		$connection_status = array(
			'isActive'          => $connection->has_connected_owner(), // TODO deprecate this.
			'isStaging'         => $status->is_staging_site(),
			'isRegistered'      => $connection->is_connected(),
			'isUserConnected'   => $connection->is_user_connected(),
			'hasConnectedOwner' => $connection->has_connected_owner(),
			'offlineMode'       => array(
				'isActive'        => $status->is_offline_mode(),
				'constant'        => defined( 'JETPACK_DEV_DEBUG' ) && JETPACK_DEV_DEBUG,
				'url'             => $status->is_local_site(),
				/** This filter is documented in packages/status/src/class-status.php */
				'filter'          => ( apply_filters( 'jetpack_development_mode', false ) || apply_filters( 'jetpack_offline_mode', false ) ), // jetpack_development_mode is deprecated.
				'wpLocalConstant' => defined( 'WP_LOCAL_DEV' ) && WP_LOCAL_DEV,
			),
			'isPublic'          => '1' == get_option( 'blog_public' ), // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
		);

		/**
		 * Filters the connection status data.
		 *
		 * @since 1.25.0
		 *
		 * @param array An array containing the connection status data.
		 */
		$connection_status = apply_filters( 'jetpack_connection_status', $connection_status );

		if ( $rest_response ) {
			return rest_ensure_response(
				$connection_status
			);
		} else {
			return $connection_status;
		}
	}

	/**
	 * Get plugins connected to the Jetpack.
	 *
	 * @param bool $rest_response Should we return a rest response or a simple array. Default to rest response.
	 *
	 * @since 1.13.1
	 * @since 1.38.0 Added $rest_response param.
	 *
	 * @return WP_REST_Response|WP_Error Response or error object, depending on the request result.
	 */
	public static function get_connection_plugins( $rest_response = true ) {
		$plugins = ( new Manager() )->get_connected_plugins();

		if ( is_wp_error( $plugins ) ) {
			return $plugins;
		}

		array_walk(
			$plugins,
			function ( &$data, $slug ) {
				$data['slug'] = $slug;
			}
		);

		if ( $rest_response ) {
			return rest_ensure_response( array_values( $plugins ) );
		}

		return array_values( $plugins );
	}

	/**
	 * Verify that user can view Jetpack admin page and can activate plugins.
	 *
	 * @since 1.15.0
	 *
	 * @return bool|WP_Error Whether user has the capability 'activate_plugins'.
	 */
	public static function activate_plugins_permission_check() {
		if ( current_user_can( 'activate_plugins' ) ) {
			return true;
		}

		return new WP_Error( 'invalid_user_permission_activate_plugins', self::get_user_permissions_error_msg(), array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Permission check for the connection_plugins endpoint
	 *
	 * @return bool|WP_Error
	 */
	public static function connection_plugins_permission_check() {
		if ( true === static::activate_plugins_permission_check() ) {
			return true;
		}

		if ( true === static::is_request_signed_by_jetpack_debugger() ) {
			return true;
		}

		return new WP_Error( 'invalid_user_permission_activate_plugins', self::get_user_permissions_error_msg(), array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Permission check for the disconnect site endpoint.
	 *
	 * @since 1.30.1
	 *
	 * @return bool|WP_Error True if user is able to disconnect the site.
	 */
	public static function disconnect_site_permission_check() {
		if ( current_user_can( 'jetpack_disconnect' ) ) {
			return true;
		}

		return new WP_Error(
			'invalid_user_permission_jetpack_disconnect',
			self::get_user_permissions_error_msg(),
			array( 'status' => rest_authorization_required_code() )
		);
	}

	/**
	 * Get miscellaneous user data related to the connection. Similar data available in old "My Jetpack".
	 * Information about the master/primary user.
	 * Information about the current user.
	 *
	 * @param bool $rest_response Should we return a rest response or a simple array. Default to rest response.
	 *
	 * @since 1.30.1
	 *
	 * @return \WP_REST_Response|array
	 */
	public static function get_user_connection_data( $rest_response = true ) {
		$blog_id = \Jetpack_Options::get_option( 'id' );

		$connection = new Manager();

		$current_user     = wp_get_current_user();
		$connection_owner = $connection->get_connection_owner();

		$owner_display_name = false === $connection_owner ? null : $connection_owner->display_name;

		$is_user_connected = $connection->is_user_connected();
		$is_master_user    = false === $connection_owner ? false : ( $current_user->ID === $connection_owner->ID );
		$wpcom_user_data   = $connection->get_connected_user_data();

		// Add connected user gravatar to the returned wpcom_user_data.
		// Probably we shouldn't do this when $wpcom_user_data is false, but we have been since 2016 so
		// clients probably expect that by now.
		if ( false === $wpcom_user_data ) {
			$wpcom_user_data = array();
		}
		$wpcom_user_data['avatar'] = ( ! empty( $wpcom_user_data['email'] ) ?
		get_avatar_url(
			$wpcom_user_data['email'],
			array(
				'size'    => 64,
				'default' => 'mysteryman',
			)
		)
		: false );

		$current_user_connection_data = array(
			'isConnected' => $is_user_connected,
			'isMaster'    => $is_master_user,
			'username'    => $current_user->user_login,
			'id'          => $current_user->ID,
			'blogId'      => $blog_id,
			'wpcomUser'   => $wpcom_user_data,
			'gravatar'    => get_avatar_url( $current_user->ID, 64, 'mm', '', array( 'force_display' => true ) ),
			'permissions' => array(
				'connect'      => current_user_can( 'jetpack_connect' ),
				'connect_user' => current_user_can( 'jetpack_connect_user' ),
				'disconnect'   => current_user_can( 'jetpack_disconnect' ),
			),
		);

		/**
		 * Filters the current user connection data.
		 *
		 * @since 1.30.1
		 *
		 * @param array An array containing the current user connection data.
		 */
		$current_user_connection_data = apply_filters( 'jetpack_current_user_connection_data', $current_user_connection_data );

		$response = array(
			'currentUser'     => $current_user_connection_data,
			'connectionOwner' => $owner_display_name,
		);

		if ( $rest_response ) {
			return rest_ensure_response( $response );
		}

		return $response;
	}

	/**
	 * Permission check for the connection/data endpoint
	 *
	 * @return bool|WP_Error
	 */
	public static function user_connection_data_permission_check() {
		if ( current_user_can( 'jetpack_connect_user' ) ) {
			return true;
		}

		return new WP_Error(
			'invalid_user_permission_user_connection_data',
			self::get_user_permissions_error_msg(),
			array( 'status' => rest_authorization_required_code() )
		);
	}

	/**
	 * Verifies if the request was signed with the Jetpack Debugger key
	 *
	 * @param string|null $pub_key The public key used to verify the signature. Default is the Jetpack Debugger key. This is used for testing purposes.
	 *
	 * @return bool
	 */
	public static function is_request_signed_by_jetpack_debugger( $pub_key = null ) {
		 // phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['signature'], $_GET['timestamp'], $_GET['url'], $_GET['rest_route'] ) ) {
			return false;
		}

		// signature timestamp must be within 5min of current time.
		if ( abs( time() - (int) $_GET['timestamp'] ) > 300 ) {
			return false;
		}

		$signature = base64_decode( filter_var( wp_unslash( $_GET['signature'] ) ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode

		$signature_data = wp_json_encode(
			array(
				'rest_route' => filter_var( wp_unslash( $_GET['rest_route'] ) ),
				'timestamp'  => (int) $_GET['timestamp'],
				'url'        => filter_var( wp_unslash( $_GET['url'] ) ),
			)
		);

		if (
			! function_exists( 'openssl_verify' )
			|| 1 !== openssl_verify(
				$signature_data,
				$signature,
				$pub_key ? $pub_key : static::JETPACK__DEBUGGER_PUBLIC_KEY
			)
		) {
			return false;
		}

		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		return true;
	}

	/**
	 * Verify that user is allowed to disconnect Jetpack.
	 *
	 * @since 1.15.0
	 *
	 * @return bool|WP_Error Whether user has the capability 'jetpack_disconnect'.
	 */
	public static function jetpack_reconnect_permission_check() {
		if ( current_user_can( 'jetpack_reconnect' ) ) {
			return true;
		}

		return new WP_Error( 'invalid_user_permission_jetpack_disconnect', self::get_user_permissions_error_msg(), array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Returns generic error message when user is not allowed to perform an action.
	 *
	 * @return string The error message.
	 */
	public static function get_user_permissions_error_msg() {
		return self::$user_permissions_error_msg;
	}

	/**
	 * The endpoint tried to partially or fully reconnect the website to WP.com.
	 *
	 * @since 1.15.0
	 *
	 * @return \WP_REST_Response|WP_Error
	 */
	public function connection_reconnect() {
		$response = array();

		$next = null;

		$result = $this->connection->restore();

		if ( is_wp_error( $result ) ) {
			$response = $result;
		} elseif ( is_string( $result ) ) {
			$next = $result;
		} else {
			$next = true === $result ? 'completed' : 'failed';
		}

		switch ( $next ) {
			case 'authorize':
				$response['status']       = 'in_progress';
				$response['authorizeUrl'] = $this->connection->get_authorization_url();
				break;
			case 'completed':
				$response['status'] = 'completed';
				/**
				 * Action fired when reconnection has completed successfully.
				 *
				 * @since 1.18.1
				 */
				do_action( 'jetpack_reconnection_completed' );
				break;
			case 'failed':
				$response = new WP_Error( 'Reconnect failed' );
				break;
		}

		return rest_ensure_response( $response );
	}

	/**
	 * Verify that user is allowed to connect Jetpack.
	 *
	 * @since 1.26.0
	 *
	 * @return bool|WP_Error Whether user has the capability 'jetpack_connect'.
	 */
	public static function jetpack_register_permission_check() {
		if ( current_user_can( 'jetpack_connect' ) ) {
			return true;
		}

		return new WP_Error( 'invalid_user_permission_jetpack_connect', self::get_user_permissions_error_msg(), array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * The endpoint tried to partially or fully reconnect the website to WP.com.
	 *
	 * @since 1.7.0
	 * @since-jetpack 7.7.0
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response|WP_Error
	 */
	public function connection_register( $request ) {
		if ( ! wp_verify_nonce( $request->get_param( 'registration_nonce' ), 'jetpack-registration-nonce' ) ) {
			return new WP_Error( 'invalid_nonce', __( 'Unable to verify your request.', 'jetpack-connection' ), array( 'status' => 403 ) );
		}

		if ( isset( $request['from'] ) ) {
			$this->connection->add_register_request_param( 'from', (string) $request['from'] );
		}

		if ( ! empty( $request['plugin_slug'] ) ) {
			// If `plugin_slug` matches a plugin using the connection, let's inform the plugin that is establishing the connection.
			$connected_plugin = Plugin_Storage::get_one( (string) $request['plugin_slug'] );
			if ( ! is_wp_error( $connected_plugin ) && ! empty( $connected_plugin ) ) {
				$this->connection->set_plugin_instance( new Plugin( (string) $request['plugin_slug'] ) );
			}
		}

		$result = $this->connection->try_registration();

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$redirect_uri = $request->get_param( 'redirect_uri' ) ? admin_url( $request->get_param( 'redirect_uri' ) ) : null;

		if ( class_exists( 'Jetpack' ) ) {
			$authorize_url = \Jetpack::build_authorize_url( $redirect_uri );
		} else {
			$authorize_url = $this->connection->get_authorization_url( null, $redirect_uri );
		}

		/**
		 * Filters the response of jetpack/v4/connection/register endpoint
		 *
		 * @param array $response Array response
		 * @since 1.27.0
		 */
		$response_body = apply_filters(
			'jetpack_register_site_rest_response',
			array()
		);

		// We manipulate the alternate URLs after the filter is applied, so they can not be overwritten.
		$response_body['authorizeUrl'] = $authorize_url;
		if ( ! empty( $response_body['alternateAuthorizeUrl'] ) ) {
			$response_body['alternateAuthorizeUrl'] = Redirect::get_url( $response_body['alternateAuthorizeUrl'] );
		}

		return rest_ensure_response( $response_body );
	}

	/**
	 * Get the authorization URL.
	 *
	 * @since 1.27.0
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response|WP_Error
	 */
	public function connection_authorize_url( $request ) {
		$redirect_uri  = $request->get_param( 'redirect_uri' ) ? admin_url( $request->get_param( 'redirect_uri' ) ) : null;
		$authorize_url = $this->connection->get_authorization_url( null, $redirect_uri );

		return rest_ensure_response(
			array(
				'authorizeUrl' => $authorize_url,
			)
		);
	}

	/**
	 * The endpoint tried to partially or fully reconnect the website to WP.com.
	 *
	 * @since 1.29.0
	 *
	 * @param \WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response|WP_Error
	 */
	public static function update_user_token( $request ) {
		$token_parts = explode( '.', $request['user_token'] );

		if ( count( $token_parts ) !== 3 || ! (int) $token_parts[2] || ! ctype_digit( $token_parts[2] ) ) {
			return new WP_Error( 'invalid_argument_user_token', esc_html__( 'Invalid user token is provided', 'jetpack-connection' ) );
		}

		$user_id = (int) $token_parts[2];

		if ( false === get_userdata( $user_id ) ) {
			return new WP_Error( 'invalid_argument_user_id', esc_html__( 'Invalid user id is provided', 'jetpack-connection' ) );
		}

		$connection = new Manager();

		if ( ! $connection->is_connected() ) {
			return new WP_Error( 'site_not_connected', esc_html__( 'Site is not connected', 'jetpack-connection' ) );
		}

		$is_connection_owner = isset( $request['is_connection_owner'] )
			? (bool) $request['is_connection_owner']
			: ( new Manager() )->get_connection_owner_id() === $user_id;

		( new Tokens() )->update_user_token( $user_id, $request['user_token'], $is_connection_owner );

		/**
		 * Fires when the user token gets successfully replaced.
		 *
		 * @since 1.29.0
		 *
		 * @param int $user_id User ID.
		 * @param string $token New user token.
		 */
		do_action( 'jetpack_updated_user_token', $user_id, $request['user_token'] );

		return rest_ensure_response(
			array(
				'success' => true,
			)
		);
	}

	/**
	 * Disconnects Jetpack from the WordPress.com Servers
	 *
	 * @since 1.30.1
	 *
	 * @return bool|WP_Error True if Jetpack successfully disconnected.
	 */
	public static function disconnect_site() {
		$connection = new Manager();

		if ( $connection->is_connected() ) {
			$connection->disconnect_site();
			return rest_ensure_response( array( 'code' => 'success' ) );
		}

		return new WP_Error(
			'disconnect_failed',
			esc_html__( 'Failed to disconnect the site as it appears already disconnected.', 'jetpack-connection' ),
			array( 'status' => 400 )
		);
	}

	/**
	 * Verify that the API client is allowed to replace user token.
	 *
	 * @since 1.29.0
	 *
	 * @return bool|WP_Error.
	 */
	public static function update_user_token_permission_check() {
		return Rest_Authentication::is_signed_with_blog_token()
			? true
			: new WP_Error( 'invalid_permission_update_user_token', self::get_user_permissions_error_msg(), array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Change the connection owner.
	 *
	 * @since 1.29.0
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return \WP_REST_Response|WP_Error
	 */
	public static function set_connection_owner( $request ) {
		$new_owner_id = $request['owner'];

		$owner_set = ( new Manager() )->update_connection_owner( $new_owner_id );

		if ( is_wp_error( $owner_set ) ) {
			return $owner_set;
		}

		return rest_ensure_response(
			array(
				'code' => 'success',
			)
		);
	}

	/**
	 * Check that user has permission to change the master user.
	 *
	 * @since 1.7.0
	 * @since-jetpack 6.2.0
	 * @since-jetpack 7.7.0 Update so that any user with jetpack_disconnect privs can set owner.
	 *
	 * @return bool|WP_Error True if user is able to change master user.
	 */
	public static function set_connection_owner_permission_check() {
		if ( current_user_can( 'jetpack_disconnect' ) ) {
			return true;
		}

		return new WP_Error( 'invalid_user_permission_set_connection_owner', self::get_user_permissions_error_msg(), array( 'status' => rest_authorization_required_code() ) );
	}
}
