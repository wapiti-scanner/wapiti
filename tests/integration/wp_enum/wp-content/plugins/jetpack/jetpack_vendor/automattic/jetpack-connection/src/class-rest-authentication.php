<?php
/**
 * The Jetpack Connection Rest Authentication file.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

/**
 * The Jetpack Connection Rest Authentication class.
 */
class Rest_Authentication {

	/**
	 * The rest authentication status.
	 *
	 * @since 1.17.0
	 * @var boolean
	 */
	private $rest_authentication_status = null;

	/**
	 * The rest authentication type.
	 * Can be either 'user' or 'blog' depending on whether the request
	 * is signed with a user or a blog token.
	 *
	 * @since 1.29.0
	 * @var string
	 */
	private $rest_authentication_type = null;

	/**
	 * The Manager object.
	 *
	 * @since 1.17.0
	 * @var Object
	 */
	private $connection_manager = null;

	/**
	 * Holds the singleton instance of this class
	 *
	 * @since 1.17.0
	 * @var Object
	 */
	private static $instance = false;

	/**
	 * Flag used to avoid determine_current_user filter to enter an infinite loop
	 *
	 * @since 1.26.0
	 * @var boolean
	 */
	private $doing_determine_current_user_filter = false;

	/**
	 * The constructor.
	 */
	private function __construct() {
		$this->connection_manager = new Manager();
	}

	/**
	 * Controls the single instance of this class.
	 *
	 * @static
	 */
	public static function init() {
		if ( ! self::$instance ) {
			self::$instance = new self();

			add_filter( 'determine_current_user', array( self::$instance, 'wp_rest_authenticate' ) );
			add_filter( 'rest_authentication_errors', array( self::$instance, 'wp_rest_authentication_errors' ) );
		}

		return self::$instance;
	}

	/**
	 * Authenticates requests from Jetpack server to WP REST API endpoints.
	 * Uses the existing XMLRPC request signing implementation.
	 *
	 * @param int|bool $user User ID if one has been determined, false otherwise.
	 *
	 * @return int|null The user id or null if the request was authenticated via blog token, or not authenticated at all.
	 */
	public function wp_rest_authenticate( $user ) {
		if ( $this->doing_determine_current_user_filter ) {
			return $user;
		}

		$this->doing_determine_current_user_filter = true;

		try {
			if ( ! empty( $user ) ) {
				// Another authentication method is in effect.
				return $user;
			}

			add_filter(
				'jetpack_constant_default_value',
				__NAMESPACE__ . '\Utils::jetpack_api_constant_filter',
				10,
				2
			);

			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( ! isset( $_GET['_for'] ) || 'jetpack' !== $_GET['_for'] ) {
				// Nothing to do for this authentication method.
				return null;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( ! isset( $_GET['token'] ) && ! isset( $_GET['signature'] ) ) {
				// Nothing to do for this authentication method.
				return null;
			}

			if ( ! isset( $_SERVER['REQUEST_METHOD'] ) ) {
				$this->rest_authentication_status = new \WP_Error(
					'rest_invalid_request',
					__( 'The request method is missing.', 'jetpack-connection' ),
					array( 'status' => 400 )
				);
				return null;
			}

			// Only support specific request parameters that have been tested and
			// are known to work with signature verification.  A different method
			// can be passed to the WP REST API via the '?_method=' parameter if
			// needed.
			if ( 'GET' !== $_SERVER['REQUEST_METHOD'] && 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
				$this->rest_authentication_status = new \WP_Error(
					'rest_invalid_request',
					__( 'This request method is not supported.', 'jetpack-connection' ),
					array( 'status' => 400 )
				);
				return null;
			}
			if ( 'POST' !== $_SERVER['REQUEST_METHOD'] && ! empty( file_get_contents( 'php://input' ) ) ) {
				$this->rest_authentication_status = new \WP_Error(
					'rest_invalid_request',
					__( 'This request method does not support body parameters.', 'jetpack-connection' ),
					array( 'status' => 400 )
				);
				return null;
			}

			$verified = $this->connection_manager->verify_xml_rpc_signature();

			if (
				$verified &&
				isset( $verified['type'] ) &&
				'blog' === $verified['type']
			) {
				// Site-level authentication successful.
				$this->rest_authentication_status = true;
				$this->rest_authentication_type   = 'blog';
				return null;
			}

			if (
				$verified &&
				isset( $verified['type'] ) &&
				'user' === $verified['type'] &&
				! empty( $verified['user_id'] )
			) {
				// User-level authentication successful.
				$this->rest_authentication_status = true;
				$this->rest_authentication_type   = 'user';
				return $verified['user_id'];
			}

			// Something else went wrong.  Probably a signature error.
			$this->rest_authentication_status = new \WP_Error(
				'rest_invalid_signature',
				__( 'The request is not signed correctly.', 'jetpack-connection' ),
				array( 'status' => 400 )
			);
			return null;
		} finally {
			$this->doing_determine_current_user_filter = false;
		}
	}

	/**
	 * Report authentication status to the WP REST API.
	 *
	 * @param  WP_Error|mixed $value Error from another authentication handler, null if we should handle it, or another value if not.
	 * @return WP_Error|boolean|null {@see WP_JSON_Server::check_authentication}
	 */
	public function wp_rest_authentication_errors( $value ) {
		if ( null !== $value ) {
			return $value;
		}
		return $this->rest_authentication_status;
	}

	/**
	 * Resets the saved authentication state in between testing requests.
	 */
	public function reset_saved_auth_state() {
		$this->rest_authentication_status = null;
		$this->connection_manager->reset_saved_auth_state();
	}

	/**
	 * Whether the request was signed with a blog token.
	 *
	 * @since 1.29.0
	 *
	 * @return bool True if the request was signed with a valid blog token, false otherwise.
	 */
	public static function is_signed_with_blog_token() {
		$instance = self::init();

		return true === $instance->rest_authentication_status && 'blog' === $instance->rest_authentication_type;
	}
}
