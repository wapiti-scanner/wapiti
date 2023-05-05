<?php
/**
 * The Jetpack Connection manager class file.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

use Automattic\Jetpack\A8c_Mc_Stats as A8c_Mc_Stats;
use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Heartbeat;
use Automattic\Jetpack\Roles;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Terms_Of_Service;
use Automattic\Jetpack\Tracking;
use Jetpack_IXR_Client;
use Jetpack_Options;
use WP_Error;
use WP_User;

/**
 * The Jetpack Connection Manager class that is used as a single gateway between WordPress.com
 * and Jetpack.
 */
class Manager {
	/**
	 * A copy of the raw POST data for signature verification purposes.
	 *
	 * @var String
	 */
	protected $raw_post_data;

	/**
	 * Verification data needs to be stored to properly verify everything.
	 *
	 * @var Object
	 */
	private $xmlrpc_verification = null;

	/**
	 * Plugin management object.
	 *
	 * @var Plugin
	 */
	private $plugin = null;

	/**
	 * Error handler object.
	 *
	 * @var Error_Handler
	 */
	public $error_handler = null;

	/**
	 * Jetpack_XMLRPC_Server object
	 *
	 * @var Jetpack_XMLRPC_Server
	 */
	public $xmlrpc_server = null;

	/**
	 * Holds extra parameters that will be sent along in the register request body.
	 *
	 * Use Manager::add_register_request_param to add values to this array.
	 *
	 * @since 1.26.0
	 * @var array
	 */
	private static $extra_register_params = array();

	/**
	 * Initialize the object.
	 * Make sure to call the "Configure" first.
	 *
	 * @param string $plugin_slug Slug of the plugin using the connection (optional, but encouraged).
	 *
	 * @see \Automattic\Jetpack\Config
	 */
	public function __construct( $plugin_slug = null ) {
		if ( $plugin_slug && is_string( $plugin_slug ) ) {
			$this->set_plugin_instance( new Plugin( $plugin_slug ) );
		}
	}

	/**
	 * Initializes required listeners. This is done separately from the constructors
	 * because some objects sometimes need to instantiate separate objects of this class.
	 *
	 * @todo Implement a proper nonce verification.
	 */
	public static function configure() {
		$manager = new self();

		add_filter(
			'jetpack_constant_default_value',
			__NAMESPACE__ . '\Utils::jetpack_api_constant_filter',
			10,
			2
		);

		$manager->setup_xmlrpc_handlers(
			$_GET, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$manager->has_connected_owner(),
			$manager->verify_xml_rpc_signature()
		);

		$manager->error_handler = Error_Handler::get_instance();

		if ( $manager->is_connected() ) {
			add_filter( 'xmlrpc_methods', array( $manager, 'public_xmlrpc_methods' ) );
			add_filter( 'shutdown', array( new Package_Version_Tracker(), 'maybe_update_package_versions' ) );
		}

		add_action( 'rest_api_init', array( $manager, 'initialize_rest_api_registration_connector' ) );

		( new Nonce_Handler() )->init_schedule();

		add_action( 'plugins_loaded', __NAMESPACE__ . '\Plugin_Storage::configure', 100 );

		add_filter( 'map_meta_cap', array( $manager, 'jetpack_connection_custom_caps' ), 1, 4 );

		Heartbeat::init();
		add_filter( 'jetpack_heartbeat_stats_array', array( $manager, 'add_stats_to_heartbeat' ) );

		Webhooks::init( $manager );

		// Set up package version hook.
		add_filter( 'jetpack_package_versions', __NAMESPACE__ . '\Package_Version::send_package_version_to_tracker' );

		if ( defined( 'JETPACK__SANDBOX_DOMAIN' ) && JETPACK__SANDBOX_DOMAIN ) {
			( new Server_Sandbox() )->init();
		}

		// Initialize connection notices.
		new Connection_Notice();
	}

	/**
	 * Sets up the XMLRPC request handlers.
	 *
	 * @since 1.25.0 Deprecate $is_active param.
	 *
	 * @param array                  $request_params incoming request parameters.
	 * @param bool                   $has_connected_owner Whether the site has a connected owner.
	 * @param bool                   $is_signed whether the signature check has been successful.
	 * @param \Jetpack_XMLRPC_Server $xmlrpc_server (optional) an instance of the server to use instead of instantiating a new one.
	 */
	public function setup_xmlrpc_handlers(
		$request_params,
		$has_connected_owner,
		$is_signed,
		\Jetpack_XMLRPC_Server $xmlrpc_server = null
	) {
		add_filter( 'xmlrpc_blog_options', array( $this, 'xmlrpc_options' ), 1000, 2 );

		if (
			! isset( $request_params['for'] )
			|| 'jetpack' !== $request_params['for']
		) {
			return false;
		}

		// Alternate XML-RPC, via ?for=jetpack&jetpack=comms.
		if (
			isset( $request_params['jetpack'] )
			&& 'comms' === $request_params['jetpack']
		) {
			if ( ! Constants::is_defined( 'XMLRPC_REQUEST' ) ) {
				// Use the real constant here for WordPress' sake.
				define( 'XMLRPC_REQUEST', true );
			}

			add_action( 'template_redirect', array( $this, 'alternate_xmlrpc' ) );

			add_filter( 'xmlrpc_methods', array( $this, 'remove_non_jetpack_xmlrpc_methods' ), 1000 );
		}

		if ( ! Constants::get_constant( 'XMLRPC_REQUEST' ) ) {
			return false;
		}
		// Display errors can cause the XML to be not well formed.
		@ini_set( 'display_errors', false ); // phpcs:ignore

		if ( $xmlrpc_server ) {
			$this->xmlrpc_server = $xmlrpc_server;
		} else {
			$this->xmlrpc_server = new \Jetpack_XMLRPC_Server();
		}

		$this->require_jetpack_authentication();

		if ( $is_signed ) {
			// If the site is connected either at a site or user level and the request is signed, expose the methods.
			// The callback is responsible to determine whether the request is signed with blog or user token and act accordingly.
			// The actual API methods.
			$callback = array( $this->xmlrpc_server, 'xmlrpc_methods' );

			// Hack to preserve $HTTP_RAW_POST_DATA.
			add_filter( 'xmlrpc_methods', array( $this, 'xmlrpc_methods' ) );

		} elseif ( $has_connected_owner && ! $is_signed ) {
			// The jetpack.authorize method should be available for unauthenticated users on a site with an
			// active Jetpack connection, so that additional users can link their account.
			$callback = array( $this->xmlrpc_server, 'authorize_xmlrpc_methods' );

		} else {
			// Any other unsigned request should expose the bootstrap methods.
			$callback = array( $this->xmlrpc_server, 'bootstrap_xmlrpc_methods' );
			new XMLRPC_Connector( $this );
		}

		add_filter( 'xmlrpc_methods', $callback );

		// Now that no one can authenticate, and we're whitelisting all XML-RPC methods, force enable_xmlrpc on.
		add_filter( 'pre_option_enable_xmlrpc', '__return_true' );
		return true;
	}

	/**
	 * Initializes the REST API connector on the init hook.
	 */
	public function initialize_rest_api_registration_connector() {
		new REST_Connector( $this );
	}

	/**
	 * Since a lot of hosts use a hammer approach to "protecting" WordPress sites,
	 * and just blanket block all requests to /xmlrpc.php, or apply other overly-sensitive
	 * security/firewall policies, we provide our own alternate XML RPC API endpoint
	 * which is accessible via a different URI. Most of the below is copied directly
	 * from /xmlrpc.php so that we're replicating it as closely as possible.
	 *
	 * @todo Tighten $wp_xmlrpc_server_class a bit to make sure it doesn't do bad things.
	 */
	public function alternate_xmlrpc() {
		// Some browser-embedded clients send cookies. We don't want them.
		$_COOKIE = array();

		include_once ABSPATH . 'wp-admin/includes/admin.php';
		include_once ABSPATH . WPINC . '/class-IXR.php';
		include_once ABSPATH . WPINC . '/class-wp-xmlrpc-server.php';

		/**
		 * Filters the class used for handling XML-RPC requests.
		 *
		 * @since 1.7.0
		 * @since-jetpack 3.1.0
		 *
		 * @param string $class The name of the XML-RPC server class.
		 */
		$wp_xmlrpc_server_class = apply_filters( 'wp_xmlrpc_server_class', 'wp_xmlrpc_server' );
		$wp_xmlrpc_server       = new $wp_xmlrpc_server_class();

		// Fire off the request.
		nocache_headers();
		$wp_xmlrpc_server->serve_request();

		exit;
	}

	/**
	 * Removes all XML-RPC methods that are not `jetpack.*`.
	 * Only used in our alternate XML-RPC endpoint, where we want to
	 * ensure that Core and other plugins' methods are not exposed.
	 *
	 * @param array $methods a list of registered WordPress XMLRPC methods.
	 * @return array filtered $methods
	 */
	public function remove_non_jetpack_xmlrpc_methods( $methods ) {
		$jetpack_methods = array();

		foreach ( $methods as $method => $callback ) {
			if ( 0 === strpos( $method, 'jetpack.' ) ) {
				$jetpack_methods[ $method ] = $callback;
			}
		}

		return $jetpack_methods;
	}

	/**
	 * Removes all other authentication methods not to allow other
	 * methods to validate unauthenticated requests.
	 */
	public function require_jetpack_authentication() {
		// Don't let anyone authenticate.
		$_COOKIE = array();
		remove_all_filters( 'authenticate' );
		remove_all_actions( 'wp_login_failed' );

		if ( $this->is_connected() ) {
			// Allow Jetpack authentication.
			add_filter( 'authenticate', array( $this, 'authenticate_jetpack' ), 10, 3 );
		}
	}

	/**
	 * Authenticates XML-RPC and other requests from the Jetpack Server
	 *
	 * @param WP_User|Mixed $user user object if authenticated.
	 * @param String        $username username.
	 * @param String        $password password string.
	 * @return WP_User|Mixed authenticated user or error.
	 */
	public function authenticate_jetpack( $user, $username, $password ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( is_a( $user, '\\WP_User' ) ) {
			return $user;
		}

		$token_details = $this->verify_xml_rpc_signature();

		if ( ! $token_details ) {
			return $user;
		}

		if ( 'user' !== $token_details['type'] ) {
			return $user;
		}

		if ( ! $token_details['user_id'] ) {
			return $user;
		}

		nocache_headers();

		return new \WP_User( $token_details['user_id'] );
	}

	/**
	 * Verifies the signature of the current request.
	 *
	 * @return false|array
	 */
	public function verify_xml_rpc_signature() {
		if ( $this->xmlrpc_verification === null ) {
			$this->xmlrpc_verification = $this->internal_verify_xml_rpc_signature();

			if ( is_wp_error( $this->xmlrpc_verification ) ) {
				/**
				 * Action for logging XMLRPC signature verification errors. This data is sensitive.
				 *
				 * @since 1.7.0
				 * @since-jetpack 7.5.0
				 *
				 * @param WP_Error $signature_verification_error The verification error
				 */
				do_action( 'jetpack_verify_signature_error', $this->xmlrpc_verification );

				Error_Handler::get_instance()->report_error( $this->xmlrpc_verification );

			}
		}

		return is_wp_error( $this->xmlrpc_verification ) ? false : $this->xmlrpc_verification;
	}

	/**
	 * Verifies the signature of the current request.
	 *
	 * This function has side effects and should not be used. Instead,
	 * use the memoized version `->verify_xml_rpc_signature()`.
	 *
	 * @internal
	 * @todo Refactor to use proper nonce verification.
	 */
	private function internal_verify_xml_rpc_signature() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		// It's not for us.
		if ( ! isset( $_GET['token'] ) || empty( $_GET['signature'] ) ) {
			return false;
		}

		$signature_details = array(
			'token'     => isset( $_GET['token'] ) ? wp_unslash( $_GET['token'] ) : '',
			'timestamp' => isset( $_GET['timestamp'] ) ? wp_unslash( $_GET['timestamp'] ) : '',
			'nonce'     => isset( $_GET['nonce'] ) ? wp_unslash( $_GET['nonce'] ) : '',
			'body_hash' => isset( $_GET['body-hash'] ) ? wp_unslash( $_GET['body-hash'] ) : '',
			'method'    => isset( $_SERVER['REQUEST_METHOD'] ) ? wp_unslash( $_SERVER['REQUEST_METHOD'] ) : null,
			'url'       => wp_unslash( ( isset( $_SERVER['HTTP_HOST'] ) ? $_SERVER['HTTP_HOST'] : null ) . ( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : null ) ), // Temp - will get real signature URL later.
			'signature' => isset( $_GET['signature'] ) ? wp_unslash( $_GET['signature'] ) : '',
		);

		$error_type = 'xmlrpc';

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		@list( $token_key, $version, $user_id ) = explode( ':', wp_unslash( $_GET['token'] ) );
		// phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		$jetpack_api_version = Constants::get_constant( 'JETPACK__API_VERSION' );

		if (
			empty( $token_key )
		||
			empty( $version ) || (string) $jetpack_api_version !== $version ) {
			return new \WP_Error( 'malformed_token', 'Malformed token in request', compact( 'signature_details', 'error_type' ) );
		}

		if ( '0' === $user_id ) {
			$token_type = 'blog';
			$user_id    = 0;
		} else {
			$token_type = 'user';
			if ( empty( $user_id ) || ! ctype_digit( $user_id ) ) {
				return new \WP_Error(
					'malformed_user_id',
					'Malformed user_id in request',
					compact( 'signature_details', 'error_type' )
				);
			}
			$user_id = (int) $user_id;

			$user = new \WP_User( $user_id );
			if ( ! $user || ! $user->exists() ) {
				return new \WP_Error(
					'unknown_user',
					sprintf( 'User %d does not exist', $user_id ),
					compact( 'signature_details', 'error_type' )
				);
			}
		}

		$token = $this->get_tokens()->get_access_token( $user_id, $token_key, false );
		if ( is_wp_error( $token ) ) {
			$token->add_data( compact( 'signature_details', 'error_type' ) );
			return $token;
		} elseif ( ! $token ) {
			return new \WP_Error(
				'unknown_token',
				sprintf( 'Token %s:%s:%d does not exist', $token_key, $version, $user_id ),
				compact( 'signature_details', 'error_type' )
			);
		}

		$jetpack_signature = new \Jetpack_Signature( $token->secret, (int) \Jetpack_Options::get_option( 'time_diff' ) );
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['_jetpack_is_multipart'] ) ) {
			$post_data   = $_POST;
			$file_hashes = array();
			foreach ( $post_data as $post_data_key => $post_data_value ) {
				if ( 0 !== strpos( $post_data_key, '_jetpack_file_hmac_' ) ) {
					continue;
				}
				$post_data_key                 = substr( $post_data_key, strlen( '_jetpack_file_hmac_' ) );
				$file_hashes[ $post_data_key ] = $post_data_value;
			}

			foreach ( $file_hashes as $post_data_key => $post_data_value ) {
				unset( $post_data[ "_jetpack_file_hmac_{$post_data_key}" ] );
				$post_data[ $post_data_key ] = $post_data_value;
			}

			ksort( $post_data );

			$body = http_build_query( stripslashes_deep( $post_data ) );
		} elseif ( $this->raw_post_data === null ) {
			$body = file_get_contents( 'php://input' );
		} else {
			$body = null;
		}
		// phpcs:enable

		$signature = $jetpack_signature->sign_current_request(
			array( 'body' => $body === null ? $this->raw_post_data : $body )
		);

		$signature_details['url'] = $jetpack_signature->current_request_url;

		if ( ! $signature ) {
			return new \WP_Error(
				'could_not_sign',
				'Unknown signature error',
				compact( 'signature_details', 'error_type' )
			);
		} elseif ( is_wp_error( $signature ) ) {
			return $signature;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$timestamp = (int) $_GET['timestamp'];
		$nonce     = wp_unslash( (string) $_GET['nonce'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WP Core doesn't sanitize nonces either.
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		// Use up the nonce regardless of whether the signature matches.
		if ( ! ( new Nonce_Handler() )->add( $timestamp, $nonce ) ) {
			return new \WP_Error(
				'invalid_nonce',
				'Could not add nonce',
				compact( 'signature_details', 'error_type' )
			);
		}

		// Be careful about what you do with this debugging data.
		// If a malicious requester has access to the expected signature,
		// bad things might be possible.
		$signature_details['expected'] = $signature;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! hash_equals( $signature, wp_unslash( $_GET['signature'] ) ) ) {
			return new \WP_Error(
				'signature_mismatch',
				'Signature mismatch',
				compact( 'signature_details', 'error_type' )
			);
		}

		/**
		 * Action for additional token checking.
		 *
		 * @since 1.7.0
		 * @since-jetpack 7.7.0
		 *
		 * @param array $post_data request data.
		 * @param array $token_data token data.
		 */
		return apply_filters(
			'jetpack_signature_check_token',
			array(
				'type'      => $token_type,
				'token_key' => $token_key,
				'user_id'   => $token->external_user_id,
			),
			$token,
			$this->raw_post_data
		);
	}

	/**
	 * Returns true if the current site is connected to WordPress.com and has the minimum requirements to enable Jetpack UI.
	 *
	 * This method is deprecated since version 1.25.0 of this package. Please use has_connected_owner instead.
	 *
	 * Since this method has a wide spread use, we decided not to throw any deprecation warnings for now.
	 *
	 * @deprecated 1.25.0
	 * @see Manager::has_connected_owner
	 * @return Boolean is the site connected?
	 */
	public function is_active() {
		return (bool) $this->get_tokens()->get_access_token( true );
	}

	/**
	 * Obtains an instance of the Tokens class.
	 *
	 * @return Tokens the Tokens object
	 */
	public function get_tokens() {
		return new Tokens();
	}

	/**
	 * Returns true if the site has both a token and a blog id, which indicates a site has been registered.
	 *
	 * @access public
	 * @deprecated 1.12.1 Use is_connected instead
	 * @see Manager::is_connected
	 *
	 * @return bool
	 */
	public function is_registered() {
		_deprecated_function( __METHOD__, '1.12.1' );
		return $this->is_connected();
	}

	/**
	 * Returns true if the site has both a token and a blog id, which indicates a site has been connected.
	 *
	 * @access public
	 * @since 1.21.1
	 *
	 * @return bool
	 */
	public function is_connected() {
		$has_blog_id    = (bool) \Jetpack_Options::get_option( 'id' );
		$has_blog_token = (bool) $this->get_tokens()->get_access_token();
		return $has_blog_id && $has_blog_token;
	}

	/**
	 * Returns true if the site has at least one connected administrator.
	 *
	 * @access public
	 * @since 1.21.1
	 *
	 * @return bool
	 */
	public function has_connected_admin() {
		return (bool) count( $this->get_connected_users( 'manage_options' ) );
	}

	/**
	 * Returns true if the site has any connected user.
	 *
	 * @access public
	 * @since 1.21.1
	 *
	 * @return bool
	 */
	public function has_connected_user() {
		return (bool) count( $this->get_connected_users( 'any', 1 ) );
	}

	/**
	 * Returns an array of users that have user tokens for communicating with wpcom.
	 * Able to select by specific capability.
	 *
	 * @since 9.9.1 Added $limit parameter.
	 *
	 * @param string   $capability The capability of the user.
	 * @param int|null $limit How many connected users to get before returning.
	 * @return WP_User[] Array of WP_User objects if found.
	 */
	public function get_connected_users( $capability = 'any', $limit = null ) {
		$connected_users = array();
		$user_tokens     = $this->get_tokens()->get_user_tokens();

		if ( ! is_array( $user_tokens ) || empty( $user_tokens ) ) {
			return $connected_users;
		}
		$connected_user_ids = array_keys( $user_tokens );

		if ( ! empty( $connected_user_ids ) ) {
			foreach ( $connected_user_ids as $id ) {
				// Check for capability.
				if ( 'any' !== $capability && ! user_can( $id, $capability ) ) {
					continue;
				}

				$user_data = get_userdata( $id );
				if ( $user_data instanceof \WP_User ) {
					$connected_users[] = $user_data;
					if ( $limit && count( $connected_users ) >= $limit ) {
						return $connected_users;
					}
				}
			}
		}

		return $connected_users;
	}

	/**
	 * Returns true if the site has a connected Blog owner (master_user).
	 *
	 * @access public
	 * @since 1.21.1
	 *
	 * @return bool
	 */
	public function has_connected_owner() {
		return (bool) $this->get_connection_owner_id();
	}

	/**
	 * Returns true if the site is connected only at a site level.
	 *
	 * Note that we are explicitly checking for the existence of the master_user option in order to account for cases where we don't have any user tokens (user-level connection) but the master_user option is set, which could be the result of a problematic user connection.
	 *
	 * @access public
	 * @since 1.25.0
	 * @deprecated 1.27.0
	 *
	 * @return bool
	 */
	public function is_userless() {
		_deprecated_function( __METHOD__, '1.27.0', 'Automattic\\Jetpack\\Connection\\Manager::is_site_connection' );
		return $this->is_site_connection();
	}

	/**
	 * Returns true if the site is connected only at a site level.
	 *
	 * Note that we are explicitly checking for the existence of the master_user option in order to account for cases where we don't have any user tokens (user-level connection) but the master_user option is set, which could be the result of a problematic user connection.
	 *
	 * @access public
	 * @since 1.27.0
	 *
	 * @return bool
	 */
	public function is_site_connection() {
		return $this->is_connected() && ! $this->has_connected_user() && ! \Jetpack_Options::get_option( 'master_user' );
	}

	/**
	 * Checks to see if the connection owner of the site is missing.
	 *
	 * @return bool
	 */
	public function is_missing_connection_owner() {
		$connection_owner = $this->get_connection_owner_id();
		if ( ! get_user_by( 'id', $connection_owner ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Returns true if the user with the specified identifier is connected to
	 * WordPress.com.
	 *
	 * @param int $user_id the user identifier. Default is the current user.
	 * @return bool Boolean is the user connected?
	 */
	public function is_user_connected( $user_id = false ) {
		$user_id = false === $user_id ? get_current_user_id() : absint( $user_id );
		if ( ! $user_id ) {
			return false;
		}

		return (bool) $this->get_tokens()->get_access_token( $user_id );
	}

	/**
	 * Returns the local user ID of the connection owner.
	 *
	 * @return bool|int Returns the ID of the connection owner or False if no connection owner found.
	 */
	public function get_connection_owner_id() {
		$owner = $this->get_connection_owner();
		return $owner instanceof \WP_User ? $owner->ID : false;
	}

	/**
	 * Get the wpcom user data of the current|specified connected user.
	 *
	 * @todo Refactor to properly load the XMLRPC client independently.
	 *
	 * @param Integer $user_id the user identifier.
	 * @return bool|array An array with the WPCOM user data on success, false otherwise.
	 */
	public function get_connected_user_data( $user_id = null ) {
		if ( ! $user_id ) {
			$user_id = get_current_user_id();
		}

		// Check if the user is connected and return false otherwise.
		if ( ! $this->is_user_connected( $user_id ) ) {
			return false;
		}

		$transient_key    = "jetpack_connected_user_data_$user_id";
		$cached_user_data = get_transient( $transient_key );

		if ( $cached_user_data ) {
			return $cached_user_data;
		}

		$xml = new Jetpack_IXR_Client(
			array(
				'user_id' => $user_id,
			)
		);
		$xml->query( 'wpcom.getUser' );

		if ( ! $xml->isError() ) {
			$user_data = $xml->getResponse();
			set_transient( $transient_key, $xml->getResponse(), DAY_IN_SECONDS );
			return $user_data;
		}

		return false;
	}

	/**
	 * Returns a user object of the connection owner.
	 *
	 * @return WP_User|false False if no connection owner found.
	 */
	public function get_connection_owner() {

		$user_id = \Jetpack_Options::get_option( 'master_user' );

		if ( ! $user_id ) {
			return false;
		}

		// Make sure user is connected.
		$user_token = $this->get_tokens()->get_access_token( $user_id );

		$connection_owner = false;

		if ( $user_token && is_object( $user_token ) && isset( $user_token->external_user_id ) ) {
			$connection_owner = get_userdata( $user_token->external_user_id );
		}

		return $connection_owner;
	}

	/**
	 * Returns true if the provided user is the Jetpack connection owner.
	 * If user ID is not specified, the current user will be used.
	 *
	 * @param Integer|Boolean $user_id the user identifier. False for current user.
	 * @return Boolean True the user the connection owner, false otherwise.
	 */
	public function is_connection_owner( $user_id = false ) {
		if ( ! $user_id ) {
			$user_id = get_current_user_id();
		}

		return ( (int) $user_id ) === $this->get_connection_owner_id();
	}

	/**
	 * Connects the user with a specified ID to a WordPress.com user using the
	 * remote login flow.
	 *
	 * @access public
	 *
	 * @param Integer $user_id (optional) the user identifier, defaults to current user.
	 * @param String  $redirect_url the URL to redirect the user to for processing, defaults to
	 *                              admin_url().
	 * @return WP_Error only in case of a failed user lookup.
	 */
	public function connect_user( $user_id = null, $redirect_url = null ) {
		$user = null;
		if ( null === $user_id ) {
			$user = wp_get_current_user();
		} else {
			$user = get_user_by( 'ID', $user_id );
		}

		if ( empty( $user ) ) {
			return new \WP_Error( 'user_not_found', 'Attempting to connect a non-existent user.' );
		}

		if ( null === $redirect_url ) {
			$redirect_url = admin_url();
		}

		// Using wp_redirect intentionally because we're redirecting outside.
		wp_redirect( $this->get_authorization_url( $user, $redirect_url ) ); // phpcs:ignore WordPress.Security.SafeRedirect
		exit();
	}

	/**
	 * Unlinks the current user from the linked WordPress.com user.
	 *
	 * @access public
	 * @static
	 *
	 * @todo Refactor to properly load the XMLRPC client independently.
	 *
	 * @param Integer $user_id the user identifier.
	 * @param bool    $can_overwrite_primary_user Allow for the primary user to be disconnected.
	 * @param bool    $force_disconnect_locally Disconnect user locally even if we were unable to disconnect them from WP.com.
	 * @return Boolean Whether the disconnection of the user was successful.
	 */
	public function disconnect_user( $user_id = null, $can_overwrite_primary_user = false, $force_disconnect_locally = false ) {
		$user_id         = empty( $user_id ) ? get_current_user_id() : (int) $user_id;
		$is_primary_user = Jetpack_Options::get_option( 'master_user' ) === $user_id;

		if ( $is_primary_user && ! $can_overwrite_primary_user ) {
			return false;
		}

		// Attempt to disconnect the user from WordPress.com.
		$is_disconnected_from_wpcom = $this->unlink_user_from_wpcom( $user_id );

		$is_disconnected_locally = false;
		if ( $is_disconnected_from_wpcom || $force_disconnect_locally ) {
			// Disconnect the user locally.
			$is_disconnected_locally = $this->get_tokens()->disconnect_user( $user_id );

			if ( $is_disconnected_locally ) {
				// Delete cached connected user data.
				$transient_key = "jetpack_connected_user_data_$user_id";
				delete_transient( $transient_key );

				/**
				 * Fires after the current user has been unlinked from WordPress.com.
				 *
				 * @since 1.7.0
				 * @since-jetpack 4.1.0
				 *
				 * @param int $user_id The current user's ID.
				 */
				do_action( 'jetpack_unlinked_user', $user_id );

				if ( $is_primary_user ) {
					Jetpack_Options::delete_option( 'master_user' );
				}
			}
		}

		return $is_disconnected_from_wpcom && $is_disconnected_locally;
	}

	/**
	 * Request to wpcom for a user to be unlinked from their WordPress.com account
	 *
	 * @param int $user_id The user identifier.
	 *
	 * @return bool Whether the disconnection of the user was successful.
	 */
	public function unlink_user_from_wpcom( $user_id ) {
		// Attempt to disconnect the user from WordPress.com.
		$xml = new Jetpack_IXR_Client();

		$xml->query( 'jetpack.unlink_user', $user_id );
		if ( $xml->isError() ) {
			return false;
		}

		return (bool) $xml->getResponse();
	}

	/**
	 * Update the connection owner.
	 *
	 * @since 1.29.0
	 *
	 * @param Integer $new_owner_id The ID of the user to become the connection owner.
	 *
	 * @return true|WP_Error True if owner successfully changed, WP_Error otherwise.
	 */
	public function update_connection_owner( $new_owner_id ) {
		$roles = new Roles();
		if ( ! user_can( $new_owner_id, $roles->translate_role_to_cap( 'administrator' ) ) ) {
			return new WP_Error(
				'new_owner_not_admin',
				__( 'New owner is not admin', 'jetpack-connection' ),
				array( 'status' => 400 )
			);
		}

		$old_owner_id = $this->get_connection_owner_id();

		if ( $old_owner_id === $new_owner_id ) {
			return new WP_Error(
				'new_owner_is_existing_owner',
				__( 'New owner is same as existing owner', 'jetpack-connection' ),
				array( 'status' => 400 )
			);
		}

		if ( ! $this->is_user_connected( $new_owner_id ) ) {
			return new WP_Error(
				'new_owner_not_connected',
				__( 'New owner is not connected', 'jetpack-connection' ),
				array( 'status' => 400 )
			);
		}

		// Notify WPCOM about the connection owner change.
		$owner_updated_wpcom = $this->update_connection_owner_wpcom( $new_owner_id );

		if ( $owner_updated_wpcom ) {
			// Update the connection owner in Jetpack only if they were successfully updated on WPCOM.
			// This will ensure consistency with WPCOM.
			\Jetpack_Options::update_option( 'master_user', $new_owner_id );

			// Track it.
			( new Tracking() )->record_user_event( 'set_connection_owner_success' );

			return true;
		}
		return new WP_Error(
			'error_setting_new_owner',
			__( 'Could not confirm new owner.', 'jetpack-connection' ),
			array( 'status' => 500 )
		);
	}

	/**
	 * Request to WPCOM to update the connection owner.
	 *
	 * @since 1.29.0
	 *
	 * @param Integer $new_owner_id The ID of the user to become the connection owner.
	 *
	 * @return Boolean Whether the ownership transfer was successful.
	 */
	public function update_connection_owner_wpcom( $new_owner_id ) {
		// Notify WPCOM about the connection owner change.
		$xml = new Jetpack_IXR_Client(
			array(
				'user_id' => get_current_user_id(),
			)
		);
		$xml->query(
			'jetpack.switchBlogOwner',
			array(
				'new_blog_owner' => $new_owner_id,
			)
		);
		if ( $xml->isError() ) {
			return false;
		}

		return (bool) $xml->getResponse();
	}

	/**
	 * Returns the requested Jetpack API URL.
	 *
	 * @param String $relative_url the relative API path.
	 * @return String API URL.
	 */
	public function api_url( $relative_url ) {
		$api_base    = Constants::get_constant( 'JETPACK__API_BASE' );
		$api_version = '/' . Constants::get_constant( 'JETPACK__API_VERSION' ) . '/';

		/**
		 * Filters the API URL that Jetpack uses for server communication.
		 *
		 * @since 1.7.0
		 * @since-jetpack 8.0.0
		 *
		 * @param String $url the generated URL.
		 * @param String $relative_url the relative URL that was passed as an argument.
		 * @param String $api_base the API base string that is being used.
		 * @param String $api_version the API version string that is being used.
		 */
		return apply_filters(
			'jetpack_api_url',
			rtrim( $api_base . $relative_url, '/\\' ) . $api_version,
			$relative_url,
			$api_base,
			$api_version
		);
	}

	/**
	 * Returns the Jetpack XMLRPC WordPress.com API endpoint URL.
	 *
	 * @return String XMLRPC API URL.
	 */
	public function xmlrpc_api_url() {
		$base = preg_replace(
			'#(https?://[^?/]+)(/?.*)?$#',
			'\\1',
			Constants::get_constant( 'JETPACK__API_BASE' )
		);
		return untrailingslashit( $base ) . '/xmlrpc.php';
	}

	/**
	 * Attempts Jetpack registration which sets up the site for connection. Should
	 * remain public because the call to action comes from the current site, not from
	 * WordPress.com.
	 *
	 * @param String $api_endpoint (optional) an API endpoint to use, defaults to 'register'.
	 * @return true|WP_Error The error object.
	 */
	public function register( $api_endpoint = 'register' ) {
		add_action( 'pre_update_jetpack_option_register', array( '\\Jetpack_Options', 'delete_option' ) );
		$secrets = ( new Secrets() )->generate( 'register', get_current_user_id(), 600 );

		if ( false === $secrets ) {
			return new WP_Error( 'cannot_save_secrets', __( 'Jetpack experienced an issue trying to save options (cannot_save_secrets). We suggest that you contact your hosting provider, and ask them for help checking that the options table is writable on your site.', 'jetpack-connection' ) );
		}

		if (
			empty( $secrets['secret_1'] ) ||
			empty( $secrets['secret_2'] ) ||
			empty( $secrets['exp'] )
		) {
			return new \WP_Error( 'missing_secrets' );
		}

		// Better to try (and fail) to set a higher timeout than this system
		// supports than to have register fail for more users than it should.
		$timeout = $this->set_min_time_limit( 60 ) / 2;

		$gmt_offset = get_option( 'gmt_offset' );
		if ( ! $gmt_offset ) {
			$gmt_offset = 0;
		}

		$stats_options = get_option( 'stats_options' );
		$stats_id      = isset( $stats_options['blog_id'] )
			? $stats_options['blog_id']
			: null;

		/* This action is documented in src/class-package-version-tracker.php */
		$package_versions = apply_filters( 'jetpack_package_versions', array() );

		$active_plugins_using_connection = Plugin_Storage::get_all();

		/**
		 * Filters the request body for additional property addition.
		 *
		 * @since 1.7.0
		 * @since-jetpack 7.7.0
		 *
		 * @param array $post_data request data.
		 * @param Array $token_data token data.
		 */
		$body = apply_filters(
			'jetpack_register_request_body',
			array_merge(
				array(
					'siteurl'                  => Urls::site_url(),
					'home'                     => Urls::home_url(),
					'gmt_offset'               => $gmt_offset,
					'timezone_string'          => (string) get_option( 'timezone_string' ),
					'site_name'                => (string) get_option( 'blogname' ),
					'secret_1'                 => $secrets['secret_1'],
					'secret_2'                 => $secrets['secret_2'],
					'site_lang'                => get_locale(),
					'timeout'                  => $timeout,
					'stats_id'                 => $stats_id,
					'state'                    => get_current_user_id(),
					'site_created'             => $this->get_assumed_site_creation_date(),
					'jetpack_version'          => Constants::get_constant( 'JETPACK__VERSION' ),
					'ABSPATH'                  => Constants::get_constant( 'ABSPATH' ),
					'current_user_email'       => wp_get_current_user()->user_email,
					'connect_plugin'           => $this->get_plugin() ? $this->get_plugin()->get_slug() : null,
					'package_versions'         => $package_versions,
					'active_connected_plugins' => $active_plugins_using_connection,
				),
				self::$extra_register_params
			)
		);

		$args = array(
			'method'  => 'POST',
			'body'    => $body,
			'headers' => array(
				'Accept' => 'application/json',
			),
			'timeout' => $timeout,
		);

		$args['body'] = $this->apply_activation_source_to_args( $args['body'] );

		// TODO: fix URLs for bad hosts.
		$response = Client::_wp_remote_request(
			$this->api_url( $api_endpoint ),
			$args,
			true
		);

		// Make sure the response is valid and does not contain any Jetpack errors.
		$registration_details = $this->validate_remote_register_response( $response );

		if ( is_wp_error( $registration_details ) ) {
			return $registration_details;
		} elseif ( ! $registration_details ) {
			return new \WP_Error(
				'unknown_error',
				'Unknown error registering your Jetpack site.',
				wp_remote_retrieve_response_code( $response )
			);
		}

		if ( empty( $registration_details->jetpack_secret ) || ! is_string( $registration_details->jetpack_secret ) ) {
			return new \WP_Error(
				'jetpack_secret',
				'Unable to validate registration of your Jetpack site.',
				wp_remote_retrieve_response_code( $response )
			);
		}

		if ( isset( $registration_details->jetpack_public ) ) {
			$jetpack_public = (int) $registration_details->jetpack_public;
		} else {
			$jetpack_public = false;
		}

		\Jetpack_Options::update_options(
			array(
				'id'     => (int) $registration_details->jetpack_id,
				'public' => $jetpack_public,
			)
		);

		update_option( Package_Version_Tracker::PACKAGE_VERSION_OPTION, $package_versions );

		$this->get_tokens()->update_blog_token( (string) $registration_details->jetpack_secret );

		$alternate_authorization_url = isset( $registration_details->alternate_authorization_url ) ? $registration_details->alternate_authorization_url : '';

		add_filter(
			'jetpack_register_site_rest_response',
			function ( $response ) use ( $alternate_authorization_url ) {
				$response['alternateAuthorizeUrl'] = $alternate_authorization_url;
				return $response;
			}
		);

		/**
		 * Fires when a site is registered on WordPress.com.
		 *
		 * @since 1.7.0
		 * @since-jetpack 3.7.0
		 *
		 * @param int $json->jetpack_id Jetpack Blog ID.
		 * @param string $json->jetpack_secret Jetpack Blog Token.
		 * @param int|bool $jetpack_public Is the site public.
		 */
		do_action(
			'jetpack_site_registered',
			$registration_details->jetpack_id,
			$registration_details->jetpack_secret,
			$jetpack_public
		);

		if ( isset( $registration_details->token ) ) {
			/**
			 * Fires when a user token is sent along with the registration data.
			 *
			 * @since 1.7.0
			 * @since-jetpack 7.6.0
			 *
			 * @param object $token the administrator token for the newly registered site.
			 */
			do_action( 'jetpack_site_registered_user_token', $registration_details->token );
		}

		return true;
	}

	/**
	 * Attempts Jetpack registration.
	 *
	 * @param bool $tos_agree Whether the user agreed to TOS.
	 *
	 * @return bool|WP_Error
	 */
	public function try_registration( $tos_agree = true ) {
		if ( $tos_agree ) {
			$terms_of_service = new Terms_Of_Service();
			$terms_of_service->agree();
		}

		/**
		 * Action fired when the user attempts the registration.
		 *
		 * @since 1.26.0
		 */
		$pre_register = apply_filters( 'jetpack_pre_register', null );

		if ( is_wp_error( $pre_register ) ) {
			return $pre_register;
		}

		$tracking_data = array();

		if ( null !== $this->get_plugin() ) {
			$tracking_data['plugin_slug'] = $this->get_plugin()->get_slug();
		}

		$tracking = new Tracking();
		$tracking->record_user_event( 'jpc_register_begin', $tracking_data );

		add_filter( 'jetpack_register_request_body', array( Utils::class, 'filter_register_request_body' ) );

		$result = $this->register();

		remove_filter( 'jetpack_register_request_body', array( Utils::class, 'filter_register_request_body' ) );

		// If there was an error with registration and the site was not registered, record this so we can show a message.
		if ( ! $result || is_wp_error( $result ) ) {
			return $result;
		}

		return true;
	}

	/**
	 * Adds a parameter to the register request body
	 *
	 * @since 1.26.0
	 *
	 * @param string $name The name of the parameter to be added.
	 * @param string $value The value of the parameter to be added.
	 *
	 * @throws \InvalidArgumentException If supplied arguments are not strings.
	 * @return void
	 */
	public function add_register_request_param( $name, $value ) {
		if ( ! is_string( $name ) || ! is_string( $value ) ) {
			throw new \InvalidArgumentException( 'name and value must be strings' );
		}
		self::$extra_register_params[ $name ] = $value;
	}

	/**
	 * Takes the response from the Jetpack register new site endpoint and
	 * verifies it worked properly.
	 *
	 * @since 1.7.0
	 * @since-jetpack 2.6.0
	 *
	 * @param Mixed $response the response object, or the error object.
	 * @return string|WP_Error A JSON object on success or WP_Error on failures
	 **/
	protected function validate_remote_register_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return new \WP_Error(
				'register_http_request_failed',
				$response->get_error_message()
			);
		}

		$code   = wp_remote_retrieve_response_code( $response );
		$entity = wp_remote_retrieve_body( $response );

		if ( $entity ) {
			$registration_response = json_decode( $entity );
		} else {
			$registration_response = false;
		}

		$code_type = (int) ( $code / 100 );
		if ( 5 === $code_type ) {
			return new \WP_Error( 'wpcom_5??', $code );
		} elseif ( 408 === $code ) {
			return new \WP_Error( 'wpcom_408', $code );
		} elseif ( ! empty( $registration_response->error ) ) {
			if (
				'xml_rpc-32700' === $registration_response->error
				&& ! function_exists( 'xml_parser_create' )
			) {
				$error_description = __( "PHP's XML extension is not available. Jetpack requires the XML extension to communicate with WordPress.com. Please contact your hosting provider to enable PHP's XML extension.", 'jetpack-connection' );
			} else {
				$error_description = isset( $registration_response->error_description )
					? (string) $registration_response->error_description
					: '';
			}

			return new \WP_Error(
				(string) $registration_response->error,
				$error_description,
				$code
			);
		} elseif ( 200 !== $code ) {
			return new \WP_Error( 'wpcom_bad_response', $code );
		}

		// Jetpack ID error block.
		if ( empty( $registration_response->jetpack_id ) ) {
			return new \WP_Error(
				'jetpack_id',
				/* translators: %s is an error message string */
				sprintf( __( 'Error Details: Jetpack ID is empty. Do not publicly post this error message! %s', 'jetpack-connection' ), $entity ),
				$entity
			);
		} elseif ( ! is_scalar( $registration_response->jetpack_id ) ) {
			return new \WP_Error(
				'jetpack_id',
				/* translators: %s is an error message string */
				sprintf( __( 'Error Details: Jetpack ID is not a scalar. Do not publicly post this error message! %s', 'jetpack-connection' ), $entity ),
				$entity
			);
		} elseif ( preg_match( '/[^0-9]/', $registration_response->jetpack_id ) ) {
			return new \WP_Error(
				'jetpack_id',
				/* translators: %s is an error message string */
				sprintf( __( 'Error Details: Jetpack ID begins with a numeral. Do not publicly post this error message! %s', 'jetpack-connection' ), $entity ),
				$entity
			);
		}

		return $registration_response;
	}

	/**
	 * Adds a used nonce to a list of known nonces.
	 *
	 * @param int    $timestamp the current request timestamp.
	 * @param string $nonce the nonce value.
	 * @return bool whether the nonce is unique or not.
	 *
	 * @deprecated since 1.24.0
	 * @see Nonce_Handler::add()
	 */
	public function add_nonce( $timestamp, $nonce ) {
		_deprecated_function( __METHOD__, '1.24.0', 'Automattic\\Jetpack\\Connection\\Nonce_Handler::add' );
		return ( new Nonce_Handler() )->add( $timestamp, $nonce );
	}

	/**
	 * Cleans nonces that were saved when calling ::add_nonce.
	 *
	 * @todo Properly prepare the query before executing it.
	 *
	 * @param bool $all whether to clean even non-expired nonces.
	 *
	 * @deprecated since 1.24.0
	 * @see Nonce_Handler::clean_all()
	 */
	public function clean_nonces( $all = false ) {
		_deprecated_function( __METHOD__, '1.24.0', 'Automattic\\Jetpack\\Connection\\Nonce_Handler::clean_all' );
		( new Nonce_Handler() )->clean_all( $all ? PHP_INT_MAX : ( time() - Nonce_Handler::LIFETIME ) );
	}

	/**
	 * Sets the Connection custom capabilities.
	 *
	 * @param string[] $caps    Array of the user's capabilities.
	 * @param string   $cap     Capability name.
	 * @param int      $user_id The user ID.
	 * @param array    $args    Adds the context to the cap. Typically the object ID.
	 */
	public function jetpack_connection_custom_caps( $caps, $cap, $user_id, $args ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		switch ( $cap ) {
			case 'jetpack_connect':
			case 'jetpack_reconnect':
				$is_offline_mode = ( new Status() )->is_offline_mode();
				if ( $is_offline_mode ) {
					$caps = array( 'do_not_allow' );
					break;
				}
				// Pass through. If it's not offline mode, these should match disconnect.
				// Let users disconnect if it's offline mode, just in case things glitch.
			case 'jetpack_disconnect':
				/**
				 * Filters the jetpack_disconnect capability.
				 *
				 * @since 1.14.2
				 *
				 * @param array An array containing the capability name.
				 */
				$caps = apply_filters( 'jetpack_disconnect_cap', array( 'manage_options' ) );
				break;
			case 'jetpack_connect_user':
				$is_offline_mode = ( new Status() )->is_offline_mode();
				if ( $is_offline_mode ) {
					$caps = array( 'do_not_allow' );
					break;
				}
				// With site connections in mind, non-admin users can connect their account only if a connection owner exists.
				$caps = $this->has_connected_owner() ? array( 'read' ) : array( 'manage_options' );
				break;
		}
		return $caps;
	}

	/**
	 * Builds the timeout limit for queries talking with the wpcom servers.
	 *
	 * Based on local php max_execution_time in php.ini
	 *
	 * @since 1.7.0
	 * @since-jetpack 5.4.0
	 * @return int
	 **/
	public function get_max_execution_time() {
		$timeout = (int) ini_get( 'max_execution_time' );

		// Ensure exec time set in php.ini.
		if ( ! $timeout ) {
			$timeout = 30;
		}
		return $timeout;
	}

	/**
	 * Sets a minimum request timeout, and returns the current timeout
	 *
	 * @since 1.7.0
	 * @since-jetpack 5.4.0
	 * @param Integer $min_timeout the minimum timeout value.
	 **/
	public function set_min_time_limit( $min_timeout ) {
		$timeout = $this->get_max_execution_time();
		if ( $timeout < $min_timeout ) {
			$timeout = $min_timeout;
			set_time_limit( $timeout );
		}
		return $timeout;
	}

	/**
	 * Get our assumed site creation date.
	 * Calculated based on the earlier date of either:
	 * - Earliest admin user registration date.
	 * - Earliest date of post of any post type.
	 *
	 * @since 1.7.0
	 * @since-jetpack 7.2.0
	 *
	 * @return string Assumed site creation date and time.
	 */
	public function get_assumed_site_creation_date() {
		$cached_date = get_transient( 'jetpack_assumed_site_creation_date' );
		if ( ! empty( $cached_date ) ) {
			return $cached_date;
		}

		$earliest_registered_users  = get_users(
			array(
				'role'    => 'administrator',
				'orderby' => 'user_registered',
				'order'   => 'ASC',
				'fields'  => array( 'user_registered' ),
				'number'  => 1,
			)
		);
		$earliest_registration_date = $earliest_registered_users[0]->user_registered;

		$earliest_posts = get_posts(
			array(
				'posts_per_page' => 1,
				'post_type'      => 'any',
				'post_status'    => 'any',
				'orderby'        => 'date',
				'order'          => 'ASC',
			)
		);

		// If there are no posts at all, we'll count only on user registration date.
		if ( $earliest_posts ) {
			$earliest_post_date = $earliest_posts[0]->post_date;
		} else {
			$earliest_post_date = PHP_INT_MAX;
		}

		$assumed_date = min( $earliest_registration_date, $earliest_post_date );
		set_transient( 'jetpack_assumed_site_creation_date', $assumed_date );

		return $assumed_date;
	}

	/**
	 * Adds the activation source string as a parameter to passed arguments.
	 *
	 * @todo Refactor to use rawurlencode() instead of urlencode().
	 *
	 * @param array $args arguments that need to have the source added.
	 * @return array $amended arguments.
	 */
	public static function apply_activation_source_to_args( $args ) {
		list( $activation_source_name, $activation_source_keyword ) = get_option( 'jetpack_activation_source' );

		if ( $activation_source_name ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.urlencode_urlencode
			$args['_as'] = urlencode( $activation_source_name );
		}

		if ( $activation_source_keyword ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.urlencode_urlencode
			$args['_ak'] = urlencode( $activation_source_keyword );
		}

		return $args;
	}

	/**
	 * Generates two secret tokens and the end of life timestamp for them.
	 *
	 * @param String  $action  The action name.
	 * @param Integer $user_id The user identifier.
	 * @param Integer $exp     Expiration time in seconds.
	 */
	public function generate_secrets( $action, $user_id = false, $exp = 600 ) {
		return ( new Secrets() )->generate( $action, $user_id, $exp );
	}

	/**
	 * Returns two secret tokens and the end of life timestamp for them.
	 *
	 * @deprecated 1.24.0 Use Automattic\Jetpack\Connection\Secrets->get() instead.
	 *
	 * @param String  $action  The action name.
	 * @param Integer $user_id The user identifier.
	 * @return string|array an array of secrets or an error string.
	 */
	public function get_secrets( $action, $user_id ) {
		_deprecated_function( __METHOD__, '1.24.0', 'Automattic\\Jetpack\\Connection\\Secrets->get' );
		return ( new Secrets() )->get( $action, $user_id );
	}

	/**
	 * Deletes secret tokens in case they, for example, have expired.
	 *
	 * @deprecated 1.24.0 Use Automattic\Jetpack\Connection\Secrets->delete() instead.
	 *
	 * @param String  $action  The action name.
	 * @param Integer $user_id The user identifier.
	 */
	public function delete_secrets( $action, $user_id ) {
		_deprecated_function( __METHOD__, '1.24.0', 'Automattic\\Jetpack\\Connection\\Secrets->delete' );
		( new Secrets() )->delete( $action, $user_id );
	}

	/**
	 * Deletes all connection tokens and transients from the local Jetpack site.
	 * If the plugin object has been provided in the constructor, the function first checks
	 * whether it's the only active connection.
	 * If there are any other connections, the function will do nothing and return `false`
	 * (unless `$ignore_connected_plugins` is set to `true`).
	 *
	 * @param bool $ignore_connected_plugins Delete the tokens even if there are other connected plugins.
	 *
	 * @return bool True if disconnected successfully, false otherwise.
	 */
	public function delete_all_connection_tokens( $ignore_connected_plugins = false ) {
		// refuse to delete if we're not the last Jetpack plugin installed.
		if ( ! $ignore_connected_plugins && null !== $this->plugin && ! $this->plugin->is_only() ) {
			return false;
		}

		/**
		 * Fires upon the disconnect attempt.
		 * Return `false` to prevent the disconnect.
		 *
		 * @since 1.14.2
		 */
		if ( ! apply_filters( 'jetpack_connection_delete_all_tokens', true ) ) {
			return false;
		}

		\Jetpack_Options::delete_option(
			array(
				'master_user',
				'time_diff',
				'fallback_no_verify_ssl_certs',
			)
		);

		( new Secrets() )->delete_all();
		$this->get_tokens()->delete_all();

		// Delete cached connected user data.
		$transient_key = 'jetpack_connected_user_data_' . get_current_user_id();
		delete_transient( $transient_key );

		// Delete all XML-RPC errors.
		Error_Handler::get_instance()->delete_all_errors();

		return true;
	}

	/**
	 * Tells WordPress.com to disconnect the site and clear all tokens from cached site.
	 * If the plugin object has been provided in the constructor, the function first check
	 * whether it's the only active connection.
	 * If there are any other connections, the function will do nothing and return `false`
	 * (unless `$ignore_connected_plugins` is set to `true`).
	 *
	 * @param bool $ignore_connected_plugins Delete the tokens even if there are other connected plugins.
	 *
	 * @return bool True if disconnected successfully, false otherwise.
	 */
	public function disconnect_site_wpcom( $ignore_connected_plugins = false ) {
		if ( ! $ignore_connected_plugins && null !== $this->plugin && ! $this->plugin->is_only() ) {
			return false;
		}

		/**
		 * Fires upon the disconnect attempt.
		 * Return `false` to prevent the disconnect.
		 *
		 * @since 1.14.2
		 */
		if ( ! apply_filters( 'jetpack_connection_disconnect_site_wpcom', true, $this ) ) {
			return false;
		}

		$xml = new Jetpack_IXR_Client();
		$xml->query( 'jetpack.deregister', get_current_user_id() );

		return true;
	}

	/**
	 * Disconnect the plugin and remove the tokens.
	 * This function will automatically perform "soft" or "hard" disconnect depending on whether other plugins are using the connection.
	 * This is a proxy method to simplify the Connection package API.
	 *
	 * @see Manager::disconnect_site()
	 *
	 * @param boolean $disconnect_wpcom Should disconnect_site_wpcom be called.
	 * @param bool    $ignore_connected_plugins Delete the tokens even if there are other connected plugins.
	 * @return bool
	 */
	public function remove_connection( $disconnect_wpcom = true, $ignore_connected_plugins = false ) {

		$this->disconnect_site( $disconnect_wpcom, $ignore_connected_plugins );

		return true;
	}

	/**
	 * Completely clearing up the connection, and initiating reconnect.
	 *
	 * @return true|WP_Error True if reconnected successfully, a `WP_Error` object otherwise.
	 */
	public function reconnect() {
		( new Tracking() )->record_user_event( 'restore_connection_reconnect' );

		$this->disconnect_site_wpcom( true );
		$this->delete_all_connection_tokens( true );

		return $this->register();
	}

	/**
	 * Validate the tokens, and refresh the invalid ones.
	 *
	 * @return string|bool|WP_Error True if connection restored or string indicating what's to be done next. A `WP_Error` object or false otherwise.
	 */
	public function restore() {
		// If this is a site connection we need to trigger a full reconnection as our only secure means of
		// communication with WPCOM, aka the blog token, is compromised.
		if ( $this->is_site_connection() ) {
			return $this->reconnect();
		}

		$validate_tokens_response = $this->get_tokens()->validate();

		// If token validation failed, trigger a full reconnection.
		if ( is_array( $validate_tokens_response ) &&
			isset( $validate_tokens_response['blog_token']['is_healthy'] ) &&
			isset( $validate_tokens_response['user_token']['is_healthy'] ) ) {
			$blog_token_healthy = $validate_tokens_response['blog_token']['is_healthy'];
			$user_token_healthy = $validate_tokens_response['user_token']['is_healthy'];
		} else {
			$blog_token_healthy = false;
			$user_token_healthy = false;
		}

		// Tokens are both valid, or both invalid. We can't fix the problem we don't see, so the full reconnection is needed.
		if ( $blog_token_healthy === $user_token_healthy ) {
			$result = $this->reconnect();
			return ( true === $result ) ? 'authorize' : $result;
		}

		if ( ! $blog_token_healthy ) {
			return $this->refresh_blog_token();
		}

		if ( ! $user_token_healthy ) {
			return ( true === $this->refresh_user_token() ) ? 'authorize' : false;
		}

		return false;
	}

	/**
	 * Responds to a WordPress.com call to register the current site.
	 * Should be changed to protected.
	 *
	 * @param array $registration_data Array of [ secret_1, user_id ].
	 */
	public function handle_registration( array $registration_data ) {
		list( $registration_secret_1, $registration_user_id ) = $registration_data;
		if ( empty( $registration_user_id ) ) {
			return new \WP_Error( 'registration_state_invalid', __( 'Invalid Registration State', 'jetpack-connection' ), 400 );
		}

		return ( new Secrets() )->verify( 'register', $registration_secret_1, (int) $registration_user_id );
	}

	/**
	 * Perform the API request to validate the blog and user tokens.
	 *
	 * @deprecated 1.24.0 Use Automattic\Jetpack\Connection\Tokens->validate_tokens() instead.
	 *
	 * @param int|null $user_id ID of the user we need to validate token for. Current user's ID by default.
	 *
	 * @return array|false|WP_Error The API response: `array( 'blog_token_is_healthy' => true|false, 'user_token_is_healthy' => true|false )`.
	 */
	public function validate_tokens( $user_id = null ) {
		_deprecated_function( __METHOD__, '1.24.0', 'Automattic\\Jetpack\\Connection\\Tokens->validate' );
		return $this->get_tokens()->validate( $user_id );
	}

	/**
	 * Verify a Previously Generated Secret.
	 *
	 * @deprecated 1.24.0 Use Automattic\Jetpack\Connection\Secrets->verify() instead.
	 *
	 * @param string $action   The type of secret to verify.
	 * @param string $secret_1 The secret string to compare to what is stored.
	 * @param int    $user_id  The user ID of the owner of the secret.
	 * @return \WP_Error|string WP_Error on failure, secret_2 on success.
	 */
	public function verify_secrets( $action, $secret_1, $user_id ) {
		_deprecated_function( __METHOD__, '1.24.0', 'Automattic\\Jetpack\\Connection\\Secrets->verify' );
		return ( new Secrets() )->verify( $action, $secret_1, $user_id );
	}

	/**
	 * Responds to a WordPress.com call to authorize the current user.
	 * Should be changed to protected.
	 */
	public function handle_authorization() {
	}

	/**
	 * Obtains the auth token.
	 *
	 * @param array $data The request data.
	 * @return object|\WP_Error Returns the auth token on success.
	 *                          Returns a \WP_Error on failure.
	 */
	public function get_token( $data ) {
		return $this->get_tokens()->get( $data, $this->api_url( 'token' ) );
	}

	/**
	 * Builds a URL to the Jetpack connection auth page.
	 *
	 * @param WP_User $user (optional) defaults to the current logged in user.
	 * @param String  $redirect (optional) a redirect URL to use instead of the default.
	 * @return string Connect URL.
	 */
	public function get_authorization_url( $user = null, $redirect = null ) {
		if ( empty( $user ) ) {
			$user = wp_get_current_user();
		}

		$roles       = new Roles();
		$role        = $roles->translate_user_to_role( $user );
		$signed_role = $this->get_tokens()->sign_role( $role );

		/**
		 * Filter the URL of the first time the user gets redirected back to your site for connection
		 * data processing.
		 *
		 * @since 1.7.0
		 * @since-jetpack 8.0.0
		 *
		 * @param string $redirect_url Defaults to the site admin URL.
		 */
		$processing_url = apply_filters( 'jetpack_connect_processing_url', admin_url( 'admin.php' ) );

		/**
		 * Filter the URL to redirect the user back to when the authorization process
		 * is complete.
		 *
		 * @since 1.7.0
		 * @since-jetpack 8.0.0
		 *
		 * @param string $redirect_url Defaults to the site URL.
		 */
		$redirect = apply_filters( 'jetpack_connect_redirect_url', $redirect );

		$secrets = ( new Secrets() )->generate( 'authorize', $user->ID, 2 * HOUR_IN_SECONDS );

		/**
		 * Filter the type of authorization.
		 * 'calypso' completes authorization on wordpress.com/jetpack/connect
		 * while 'jetpack' ( or any other value ) completes the authorization at jetpack.wordpress.com.
		 *
		 * @since 1.7.0
		 * @since-jetpack 4.3.3
		 *
		 * @param string $auth_type Defaults to 'calypso', can also be 'jetpack'.
		 */
		$auth_type = apply_filters( 'jetpack_auth_type', 'calypso' );

		/**
		 * Filters the user connection request data for additional property addition.
		 *
		 * @since 1.7.0
		 * @since-jetpack 8.0.0
		 *
		 * @param array $request_data request data.
		 */
		$body = apply_filters(
			'jetpack_connect_request_body',
			array(
				'response_type'         => 'code',
				'client_id'             => \Jetpack_Options::get_option( 'id' ),
				'redirect_uri'          => add_query_arg(
					array(
						'handler'  => 'jetpack-connection-webhooks',
						'action'   => 'authorize',
						'_wpnonce' => wp_create_nonce( "jetpack-authorize_{$role}_{$redirect}" ),
						'redirect' => $redirect ? rawurlencode( $redirect ) : false,
					),
					esc_url( $processing_url )
				),
				'state'                 => $user->ID,
				'scope'                 => $signed_role,
				'user_email'            => $user->user_email,
				'user_login'            => $user->user_login,
				'is_active'             => $this->has_connected_owner(), // TODO Deprecate this.
				'jp_version'            => (string) Constants::get_constant( 'JETPACK__VERSION' ),
				'auth_type'             => $auth_type,
				'secret'                => $secrets['secret_1'],
				'blogname'              => get_option( 'blogname' ),
				'site_url'              => Urls::site_url(),
				'home_url'              => Urls::home_url(),
				'site_icon'             => get_site_icon_url(),
				'site_lang'             => get_locale(),
				'site_created'          => $this->get_assumed_site_creation_date(),
				'allow_site_connection' => ! $this->has_connected_owner(),
			)
		);

		$body = $this->apply_activation_source_to_args( urlencode_deep( $body ) );

		$api_url = $this->api_url( 'authorize' );

		return add_query_arg( $body, $api_url );
	}

	/**
	 * Authorizes the user by obtaining and storing the user token.
	 *
	 * @param array $data The request data.
	 * @return string|\WP_Error Returns a string on success.
	 *                          Returns a \WP_Error on failure.
	 */
	public function authorize( $data = array() ) {
		/**
		 * Action fired when user authorization starts.
		 *
		 * @since 1.7.0
		 * @since-jetpack 8.0.0
		 */
		do_action( 'jetpack_authorize_starting' );

		$roles = new Roles();
		$role  = $roles->translate_current_user_to_role();

		if ( ! $role ) {
			return new \WP_Error( 'no_role', 'Invalid request.', 400 );
		}

		$cap = $roles->translate_role_to_cap( $role );
		if ( ! $cap ) {
			return new \WP_Error( 'no_cap', 'Invalid request.', 400 );
		}

		if ( ! empty( $data['error'] ) ) {
			return new \WP_Error( $data['error'], 'Error included in the request.', 400 );
		}

		if ( ! isset( $data['state'] ) ) {
			return new \WP_Error( 'no_state', 'Request must include state.', 400 );
		}

		if ( ! ctype_digit( $data['state'] ) ) {
			return new \WP_Error( $data['error'], 'State must be an integer.', 400 );
		}

		$current_user_id = get_current_user_id();
		if ( $current_user_id !== (int) $data['state'] ) {
			return new \WP_Error( 'wrong_state', 'State does not match current user.', 400 );
		}

		if ( empty( $data['code'] ) ) {
			return new \WP_Error( 'no_code', 'Request must include an authorization code.', 400 );
		}

		$token = $this->get_tokens()->get( $data, $this->api_url( 'token' ) );

		if ( is_wp_error( $token ) ) {
			$code = $token->get_error_code();
			if ( empty( $code ) ) {
				$code = 'invalid_token';
			}
			return new \WP_Error( $code, $token->get_error_message(), 400 );
		}

		if ( ! $token ) {
			return new \WP_Error( 'no_token', 'Error generating token.', 400 );
		}

		$is_connection_owner = ! $this->has_connected_owner();

		$this->get_tokens()->update_user_token( $current_user_id, sprintf( '%s.%d', $token, $current_user_id ), $is_connection_owner );

		/**
		 * Fires after user has successfully received an auth token.
		 *
		 * @since 1.7.0
		 * @since-jetpack 3.9.0
		 */
		do_action( 'jetpack_user_authorized' );

		if ( ! $is_connection_owner ) {
			/**
			 * Action fired when a secondary user has been authorized.
			 *
			 * @since 1.7.0
			 * @since-jetpack 8.0.0
			 */
			do_action( 'jetpack_authorize_ending_linked' );
			return 'linked';
		}

		/**
		 * Action fired when the master user has been authorized.
		 *
		 * @since 1.7.0
		 * @since-jetpack 8.0.0
		 *
		 * @param array $data The request data.
		 */
		do_action( 'jetpack_authorize_ending_authorized', $data );

		\Jetpack_Options::delete_raw_option( 'jetpack_last_connect_url_check' );

		( new Nonce_Handler() )->reschedule();

		return 'authorized';
	}

	/**
	 * Disconnects from the Jetpack servers.
	 * Forgets all connection details and tells the Jetpack servers to do the same.
	 *
	 * @param boolean $disconnect_wpcom Should disconnect_site_wpcom be called.
	 * @param bool    $ignore_connected_plugins Delete the tokens even if there are other connected plugins.
	 */
	public function disconnect_site( $disconnect_wpcom = true, $ignore_connected_plugins = true ) {
		if ( ! $ignore_connected_plugins && null !== $this->plugin && ! $this->plugin->is_only() ) {
			return false;
		}

		wp_clear_scheduled_hook( 'jetpack_clean_nonces' );

		( new Nonce_Handler() )->clean_all();

		/**
		 * Fires when a site is disconnected.
		 *
		 * @since 1.36.3
		 */
		do_action( 'jetpack_site_before_disconnected' );

		// If the site is in an IDC because sync is not allowed,
		// let's make sure to not disconnect the production site.
		if ( $disconnect_wpcom ) {
			$tracking = new Tracking();
			$tracking->record_user_event( 'disconnect_site', array() );

			$this->disconnect_site_wpcom( $ignore_connected_plugins );
		}

		$this->delete_all_connection_tokens( $ignore_connected_plugins );

		// Remove tracked package versions, since they depend on the Jetpack Connection.
		delete_option( Package_Version_Tracker::PACKAGE_VERSION_OPTION );

		$jetpack_unique_connection = \Jetpack_Options::get_option( 'unique_connection' );
		if ( $jetpack_unique_connection ) {
			// Check then record unique disconnection if site has never been disconnected previously.
			if ( - 1 === $jetpack_unique_connection['disconnected'] ) {
				$jetpack_unique_connection['disconnected'] = 1;
			} else {
				if ( 0 === $jetpack_unique_connection['disconnected'] ) {
					$a8c_mc_stats_instance = new A8c_Mc_Stats();
					$a8c_mc_stats_instance->add( 'connections', 'unique-disconnect' );
					$a8c_mc_stats_instance->do_server_side_stats();
				}
				// increment number of times disconnected.
				$jetpack_unique_connection['disconnected'] += 1;
			}

			\Jetpack_Options::update_option( 'unique_connection', $jetpack_unique_connection );
		}

		/**
		 * Fires when a site is disconnected.
		 *
		 * @since 1.30.1
		 */
		do_action( 'jetpack_site_disconnected' );
	}

	/**
	 * The Base64 Encoding of the SHA1 Hash of the Input.
	 *
	 * @param string $text The string to hash.
	 * @return string
	 */
	public function sha1_base64( $text ) {
		return base64_encode( sha1( $text, true ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * This function mirrors Jetpack_Data::is_usable_domain() in the WPCOM codebase.
	 *
	 * @param string $domain The domain to check.
	 *
	 * @return bool|WP_Error
	 */
	public function is_usable_domain( $domain ) {

		// If it's empty, just fail out.
		if ( ! $domain ) {
			return new \WP_Error(
				'fail_domain_empty',
				/* translators: %1$s is a domain name. */
				sprintf( __( 'Domain `%1$s` just failed is_usable_domain check as it is empty.', 'jetpack-connection' ), $domain )
			);
		}

		/**
		 * Skips the usuable domain check when connecting a site.
		 *
		 * Allows site administrators with domains that fail gethostname-based checks to pass the request to WP.com
		 *
		 * @since 1.7.0
		 * @since-jetpack 4.1.0
		 *
		 * @param bool If the check should be skipped. Default false.
		 */
		if ( apply_filters( 'jetpack_skip_usuable_domain_check', false ) ) {
			return true;
		}

		// None of the explicit localhosts.
		$forbidden_domains = array(
			'wordpress.com',
			'localhost',
			'localhost.localdomain',
			'127.0.0.1',
			'local.wordpress.test',         // VVV pattern.
			'local.wordpress-trunk.test',   // VVV pattern.
			'src.wordpress-develop.test',   // VVV pattern.
			'build.wordpress-develop.test', // VVV pattern.
		);
		if ( in_array( $domain, $forbidden_domains, true ) ) {
			return new \WP_Error(
				'fail_domain_forbidden',
				sprintf(
					/* translators: %1$s is a domain name. */
					__(
						'Domain `%1$s` just failed is_usable_domain check as it is in the forbidden array.',
						'jetpack-connection'
					),
					$domain
				)
			);
		}

		// No .test or .local domains.
		if ( preg_match( '#\.(test|local)$#i', $domain ) ) {
			return new \WP_Error(
				'fail_domain_tld',
				sprintf(
					/* translators: %1$s is a domain name. */
					__(
						'Domain `%1$s` just failed is_usable_domain check as it uses an invalid top level domain.',
						'jetpack-connection'
					),
					$domain
				)
			);
		}

		// No WPCOM subdomains.
		if ( preg_match( '#\.WordPress\.com$#i', $domain ) ) {
			return new \WP_Error(
				'fail_subdomain_wpcom',
				sprintf(
					/* translators: %1$s is a domain name. */
					__(
						'Domain `%1$s` just failed is_usable_domain check as it is a subdomain of WordPress.com.',
						'jetpack-connection'
					),
					$domain
				)
			);
		}

		// If PHP was compiled without support for the Filter module (very edge case).
		if ( ! function_exists( 'filter_var' ) ) {
			// Just pass back true for now, and let wpcom sort it out.
			return true;
		}

		return true;
	}

	/**
	 * Gets the requested token.
	 *
	 * @deprecated 1.24.0 Use Automattic\Jetpack\Connection\Tokens->get_access_token() instead.
	 *
	 * @param int|false    $user_id   false: Return the Blog Token. int: Return that user's User Token.
	 * @param string|false $token_key If provided, check that the token matches the provided input.
	 * @param bool|true    $suppress_errors If true, return a falsy value when the token isn't found; When false, return a descriptive WP_Error when the token isn't found.
	 *
	 * @return object|false
	 *
	 * @see $this->get_tokens()->get_access_token()
	 */
	public function get_access_token( $user_id = false, $token_key = false, $suppress_errors = true ) {
		_deprecated_function( __METHOD__, '1.24.0', 'Automattic\\Jetpack\\Connection\\Tokens->get_access_token' );
		return $this->get_tokens()->get_access_token( $user_id, $token_key, $suppress_errors );
	}

	/**
	 * In some setups, $HTTP_RAW_POST_DATA can be emptied during some IXR_Server paths
	 * since it is passed by reference to various methods.
	 * Capture it here so we can verify the signature later.
	 *
	 * @param array $methods an array of available XMLRPC methods.
	 * @return array the same array, since this method doesn't add or remove anything.
	 */
	public function xmlrpc_methods( $methods ) {
		$this->raw_post_data = isset( $GLOBALS['HTTP_RAW_POST_DATA'] ) ? $GLOBALS['HTTP_RAW_POST_DATA'] : null;
		return $methods;
	}

	/**
	 * Resets the raw post data parameter for testing purposes.
	 */
	public function reset_raw_post_data() {
		$this->raw_post_data = null;
	}

	/**
	 * Registering an additional method.
	 *
	 * @param array $methods an array of available XMLRPC methods.
	 * @return array the amended array in case the method is added.
	 */
	public function public_xmlrpc_methods( $methods ) {
		if ( array_key_exists( 'wp.getOptions', $methods ) ) {
			$methods['wp.getOptions'] = array( $this, 'jetpack_get_options' );
		}
		return $methods;
	}

	/**
	 * Handles a getOptions XMLRPC method call.
	 *
	 * @param array $args method call arguments.
	 * @return an amended XMLRPC server options array.
	 */
	public function jetpack_get_options( $args ) {
		global $wp_xmlrpc_server;

		$wp_xmlrpc_server->escape( $args );

		$username = $args[1];
		$password = $args[2];

		$user = $wp_xmlrpc_server->login( $username, $password );
		if ( ! $user ) {
			return $wp_xmlrpc_server->error;
		}

		$options   = array();
		$user_data = $this->get_connected_user_data();
		if ( is_array( $user_data ) ) {
			$options['jetpack_user_id']         = array(
				'desc'     => __( 'The WP.com user ID of the connected user', 'jetpack-connection' ),
				'readonly' => true,
				'value'    => $user_data['ID'],
			);
			$options['jetpack_user_login']      = array(
				'desc'     => __( 'The WP.com username of the connected user', 'jetpack-connection' ),
				'readonly' => true,
				'value'    => $user_data['login'],
			);
			$options['jetpack_user_email']      = array(
				'desc'     => __( 'The WP.com user email of the connected user', 'jetpack-connection' ),
				'readonly' => true,
				'value'    => $user_data['email'],
			);
			$options['jetpack_user_site_count'] = array(
				'desc'     => __( 'The number of sites of the connected WP.com user', 'jetpack-connection' ),
				'readonly' => true,
				'value'    => $user_data['site_count'],
			);
		}
		$wp_xmlrpc_server->blog_options = array_merge( $wp_xmlrpc_server->blog_options, $options );
		$args                           = stripslashes_deep( $args );
		return $wp_xmlrpc_server->wp_getOptions( $args );
	}

	/**
	 * Adds Jetpack-specific options to the output of the XMLRPC options method.
	 *
	 * @param array $options standard Core options.
	 * @return array amended options.
	 */
	public function xmlrpc_options( $options ) {
		$jetpack_client_id = false;
		if ( $this->is_connected() ) {
			$jetpack_client_id = \Jetpack_Options::get_option( 'id' );
		}
		$options['jetpack_version'] = array(
			'desc'     => __( 'Jetpack Plugin Version', 'jetpack-connection' ),
			'readonly' => true,
			'value'    => Constants::get_constant( 'JETPACK__VERSION' ),
		);

		$options['jetpack_client_id'] = array(
			'desc'     => __( 'The Client ID/WP.com Blog ID of this site', 'jetpack-connection' ),
			'readonly' => true,
			'value'    => $jetpack_client_id,
		);
		return $options;
	}

	/**
	 * Resets the saved authentication state in between testing requests.
	 */
	public function reset_saved_auth_state() {
		$this->xmlrpc_verification = null;
	}

	/**
	 * Sign a user role with the master access token.
	 * If not specified, will default to the current user.
	 *
	 * @access public
	 *
	 * @param string $role    User role.
	 * @param int    $user_id ID of the user.
	 * @return string Signed user role.
	 */
	public function sign_role( $role, $user_id = null ) {
		return $this->get_tokens()->sign_role( $role, $user_id );
	}

	/**
	 * Set the plugin instance.
	 *
	 * @param Plugin $plugin_instance The plugin instance.
	 *
	 * @return $this
	 */
	public function set_plugin_instance( Plugin $plugin_instance ) {
		$this->plugin = $plugin_instance;

		return $this;
	}

	/**
	 * Retrieve the plugin management object.
	 *
	 * @return Plugin|null
	 */
	public function get_plugin() {
		return $this->plugin;
	}

	/**
	 * Get all connected plugins information, excluding those disconnected by user.
	 * WARNING: the method cannot be called until Plugin_Storage::configure is called, which happens on plugins_loaded
	 * Even if you don't use Jetpack Config, it may be introduced later by other plugins,
	 * so please make sure not to run the method too early in the code.
	 *
	 * @return array|WP_Error
	 */
	public function get_connected_plugins() {
		$maybe_plugins = Plugin_Storage::get_all();

		if ( $maybe_plugins instanceof WP_Error ) {
			return $maybe_plugins;
		}

		return $maybe_plugins;
	}

	/**
	 * Force plugin disconnect. After its called, the plugin will not be allowed to use the connection.
	 * Note: this method does not remove any access tokens.
	 *
	 * @deprecated since 1.39.0
	 * @return bool
	 */
	public function disable_plugin() {
		return null;
	}

	/**
	 * Force plugin reconnect after user-initiated disconnect.
	 * After its called, the plugin will be allowed to use the connection again.
	 * Note: this method does not initialize access tokens.
	 *
	 * @deprecated since 1.39.0.
	 * @return bool
	 */
	public function enable_plugin() {
		return null;
	}

	/**
	 * Whether the plugin is allowed to use the connection, or it's been disconnected by user.
	 * If no plugin slug was passed into the constructor, always returns true.
	 *
	 * @deprecated 1.42.0 This method no longer has a purpose after the removal of the soft disconnect feature.
	 *
	 * @return bool
	 */
	public function is_plugin_enabled() {
		return true;
	}

	/**
	 * Perform the API request to refresh the blog token.
	 * Note that we are making this request on behalf of the Jetpack master user,
	 * given they were (most probably) the ones that registered the site at the first place.
	 *
	 * @return WP_Error|bool The result of updating the blog_token option.
	 */
	public function refresh_blog_token() {
		( new Tracking() )->record_user_event( 'restore_connection_refresh_blog_token' );

		$blog_id = \Jetpack_Options::get_option( 'id' );
		if ( ! $blog_id ) {
			return new WP_Error( 'site_not_registered', 'Site not registered.' );
		}

		$url     = sprintf(
			'%s/%s/v%s/%s',
			Constants::get_constant( 'JETPACK__WPCOM_JSON_API_BASE' ),
			'wpcom',
			'2',
			'sites/' . $blog_id . '/jetpack-refresh-blog-token'
		);
		$method  = 'POST';
		$user_id = get_current_user_id();

		$response = Client::remote_request( compact( 'url', 'method', 'user_id' ) );

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'refresh_blog_token_http_request_failed', $response->get_error_message() );
		}

		$code   = wp_remote_retrieve_response_code( $response );
		$entity = wp_remote_retrieve_body( $response );

		if ( $entity ) {
			$json = json_decode( $entity );
		} else {
			$json = false;
		}

		if ( 200 !== $code ) {
			if ( empty( $json->code ) ) {
				return new WP_Error( 'unknown', '', $code );
			}

			/* translators: Error description string. */
			$error_description = isset( $json->message ) ? sprintf( __( 'Error Details: %s', 'jetpack-connection' ), (string) $json->message ) : '';

			return new WP_Error( (string) $json->code, $error_description, $code );
		}

		if ( empty( $json->jetpack_secret ) || ! is_scalar( $json->jetpack_secret ) ) {
			return new WP_Error( 'jetpack_secret', '', $code );
		}

		Error_Handler::get_instance()->delete_all_errors();

		return $this->get_tokens()->update_blog_token( (string) $json->jetpack_secret );
	}

	/**
	 * Disconnect the user from WP.com, and initiate the reconnect process.
	 *
	 * @return bool
	 */
	public function refresh_user_token() {
		( new Tracking() )->record_user_event( 'restore_connection_refresh_user_token' );
		$this->disconnect_user( null, true, true );
		return true;
	}

	/**
	 * Fetches a signed token.
	 *
	 * @deprecated 1.24.0 Use Automattic\Jetpack\Connection\Tokens->get_signed_token() instead.
	 *
	 * @param object $token the token.
	 * @return WP_Error|string a signed token
	 */
	public function get_signed_token( $token ) {
		_deprecated_function( __METHOD__, '1.24.0', 'Automattic\\Jetpack\\Connection\\Tokens->get_signed_token' );
		return $this->get_tokens()->get_signed_token( $token );
	}

	/**
	 * If the site-level connection is active, add the list of plugins using connection to the heartbeat (except Jetpack itself)
	 *
	 * @param array $stats The Heartbeat stats array.
	 * @return array $stats
	 */
	public function add_stats_to_heartbeat( $stats ) {

		if ( ! $this->is_connected() ) {
			return $stats;
		}

		$active_plugins_using_connection = Plugin_Storage::get_all();
		foreach ( array_keys( $active_plugins_using_connection ) as $plugin_slug ) {
			if ( 'jetpack' !== $plugin_slug ) {
				$stats_group             = isset( $active_plugins_using_connection['jetpack'] ) ? 'combined-connection' : 'standalone-connection';
				$stats[ $stats_group ][] = $plugin_slug;
			}
		}
		return $stats;
	}

	/**
	 * Get the WPCOM or self-hosted site ID.
	 *
	 * @return int|WP_Error
	 */
	public static function get_site_id() {
		$is_wpcom = ( defined( 'IS_WPCOM' ) && IS_WPCOM );
		$site_id  = $is_wpcom ? get_current_blog_id() : \Jetpack_Options::get_option( 'id' );
		if ( ! $site_id ) {
			return new \WP_Error(
				'unavailable_site_id',
				__( 'Sorry, something is wrong with your Jetpack connection.', 'jetpack-connection' ),
				403
			);
		}
		return (int) $site_id;
	}
}
