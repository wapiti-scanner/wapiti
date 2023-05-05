<?php
/**
 * The Publicize Rest Controller class.
 * Registers the REST routes for Publicize.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize;

use Automattic\Jetpack\Connection\Client;
use Jetpack_Options;
use WP_Error;
use WP_REST_Server;

/**
 * Registers the REST routes for Search.
 */
class REST_Controller {
	/**
	 * Whether it's run on WPCOM.
	 *
	 * @var bool
	 */
	protected $is_wpcom;

	/**
	 * Social Product Slugs
	 *
	 * @var string
	 */
	const JETPACK_SOCIAL_BASIC_YEARLY    = 'jetpack_social_basic_yearly';
	const JETPACK_SOCIAL_ADVANCED_YEARLY = 'jetpack_social_advanced_yearly';

	/**
	 * Constructor
	 *
	 * @param bool $is_wpcom - Whether it's run on WPCOM.
	 */
	public function __construct( $is_wpcom = false ) {
		$this->is_wpcom = $is_wpcom;
	}

	/**
	 * Registers the REST routes for Search.
	 *
	 * @access public
	 * @static
	 */
	public function register_rest_routes() {
		register_rest_route(
			'jetpack/v4',
			'/publicize/connection-test-results',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_publicize_connection_test_results' ),
				'permission_callback' => array( $this, 'require_admin_privilege_callback' ),
			)
		);

		register_rest_route(
			'jetpack/v4',
			'/publicize/connections',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_publicize_connections' ),
				'permission_callback' => array( $this, 'require_admin_privilege_callback' ),
			)
		);

		register_rest_route(
			'jetpack/v4',
			'/publicize/shares-count',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_publicize_shares_count' ),
				'permission_callback' => array( $this, 'require_admin_privilege_callback' ),
			)
		);

		// Get current social product from the product's endpoint.
		register_rest_route(
			'jetpack/v4',
			'/social-product-info',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_social_product_info' ),
				'permission_callback' => array( $this, 'require_admin_privilege_callback' ),
			)
		);

		register_rest_route(
			'jetpack/v4',
			'/publicize/(?P<postId>\d+)',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'share_post' ),
				'permission_callback' => array( $this, 'require_admin_privilege_callback' ),
				'args'                => array(
					'message'             => array(
						'description'       => __( 'The message to share.', 'jetpack-publicize-pkg' ),
						'type'              => 'string',
						'required'          => true,
						'validate_callback' => function ( $param ) {
							return is_string( $param );
						},
						'sanitize_callback' => 'sanitize_textarea_field',
					),
					'skipped_connections' => array(
						'description'       => __( 'Array of external connection IDs to skip sharing.', 'jetpack-publicize-pkg' ),
						'type'              => 'array',
						'required'          => false,
						'validate_callback' => function ( $param ) {
							return is_array( $param );
						},
						'sanitize_callback' => function ( $param ) {
							return array_map( 'absint', $param );
						},
					),
				),
			)
		);
	}

	/**
	 * Only administrators can access the API.
	 *
	 * @return bool|WP_Error True if a blog token was used to sign the request, WP_Error otherwise.
	 */
	public function require_admin_privilege_callback() {
		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		$error_msg = esc_html__(
			'You are not allowed to perform this action.',
			'jetpack-publicize-pkg'
		);

		return new WP_Error( 'rest_forbidden', $error_msg, array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Gets the current Publicize connections, with the resolt of testing them, for the site.
	 *
	 * GET `jetpack/v4/publicize/connection-test-results`
	 */
	public function get_publicize_connection_test_results() {
		$blog_id  = $this->get_blog_id();
		$path     = sprintf( '/sites/%d/publicize/connection-test-results', absint( $blog_id ) );
		$response = Client::wpcom_json_api_request_as_user( $path, '2', array(), null, 'wpcom' );
		return rest_ensure_response( $this->make_proper_response( $response ) );
	}

	/**
	 * Gets the current Publicize connections for the site.
	 *
	 * GET `jetpack/v4/publicize/connections`
	 */
	public function get_publicize_connections() {
		$blog_id  = $this->get_blog_id();
		$path     = sprintf( '/sites/%d/publicize/connections', absint( $blog_id ) );
		$response = Client::wpcom_json_api_request_as_user( $path, '2', array(), null, 'wpcom' );
		return rest_ensure_response( $this->make_proper_response( $response ) );
	}

	/**
	 * Gets the publicize shares count for the site.
	 *
	 * GET `jetpack/v4/publicize/shares-count`
	 */
	public function get_publicize_shares_count() {
		global $publicize;
		$response = $publicize->get_publicize_shares_count( $this->get_blog_id() );
		return rest_ensure_response( $response );
	}

	/**
	 * Gets information about the current social product plans.
	 *
	 * @return string|WP_Error A JSON object of the current social product being if the request was successful, or a WP_Error otherwise.
	 */
	public static function get_social_product_info() {
		$request_url   = 'https://public-api.wordpress.com/rest/v1.1/products?locale=' . get_user_locale() . '&type=jetpack';
		$wpcom_request = wp_remote_get( esc_url_raw( $request_url ) );
		$response_code = wp_remote_retrieve_response_code( $wpcom_request );

		if ( 200 !== $response_code ) {
			// Something went wrong so we'll just return the response without caching.
			return new WP_Error(
				'failed_to_fetch_data',
				esc_html__( 'Unable to fetch the requested data.', 'jetpack-publicize-pkg' ),
				array(
					'status'  => $response_code,
					'request' => $wpcom_request,
				)
			);
		}

		$products = json_decode( wp_remote_retrieve_body( $wpcom_request ) );
		return array(
			'advanced' => $products->{self::JETPACK_SOCIAL_ADVANCED_YEARLY},
			'basic'    => $products->{self::JETPACK_SOCIAL_BASIC_YEARLY},
		);
	}

	/**
	 * Calls the WPCOM endpoint to reshare the post.
	 *
	 * POST jetpack/v4/publicize/(?P<postId>\d+)
	 *
	 * @param WP_Request $request The request object, which includes the parameters.
	 */
	public function share_post( $request ) {
		$post_id             = $request->get_param( 'postId' );
		$message             = trim( $request->get_param( 'message' ) );
		$skip_connection_ids = $request->get_param( 'skipped_connections' );

		/*
		 * Publicize endpoint on WPCOM:
		 * [POST] wpcom/v2/sites/{$siteId}/posts/{$postId}/publicize
		 * body:
		 *   - message: string
		 *   - skipped_connections: array of connection ids to skip
		 */
		$url = sprintf(
			'/sites/%d/posts/%d/publicize',
			$this->get_blog_id(),
			$post_id
		);

		$response = Client::wpcom_json_api_request_as_user(
			$url,
			'v2',
			array(
				'method' => 'POST',
			),
			array(
				'message'             => $message,
				'skipped_connections' => $skip_connection_ids,
			)
		);

		return rest_ensure_response( $this->make_proper_response( $response ) );
	}

	/**
	 * Forward remote response to client with error handling.
	 *
	 * @param array|WP_Error $response - Response from WPCOM.
	 */
	public function make_proper_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$body        = json_decode( wp_remote_retrieve_body( $response ), true );
		$status_code = wp_remote_retrieve_response_code( $response );

		if ( 200 === $status_code ) {
			return $body;
		}

		return new WP_Error(
			isset( $body['error'] ) ? 'remote-error-' . $body['error'] : 'remote-error',
			isset( $body['message'] ) ? $body['message'] : 'unknown remote error',
			array( 'status' => $status_code )
		);
	}

	/**
	 * Get blog id
	 */
	protected function get_blog_id() {
		return $this->is_wpcom ? get_current_blog_id() : Jetpack_Options::get_option( 'id' );
	}
}
