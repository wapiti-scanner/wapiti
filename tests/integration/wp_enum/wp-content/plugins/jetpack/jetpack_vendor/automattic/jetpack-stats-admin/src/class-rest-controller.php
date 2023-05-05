<?php
/**
 * The Stats Rest Controller class.
 * Registers the REST routes for Odyssey Stats.
 *
 * @package automattic/jetpack-stats-admin
 */

namespace Automattic\Jetpack\Stats_Admin;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Stats\WPCOM_Stats;
use Jetpack_Options;
use WP_Error;
use WP_REST_Server;

/**
 * Registers the REST routes for Stats.
 * It bascially forwards the requests to the WordPress.com REST API.
 */
class REST_Controller {
	/**
	 * Namespace for the REST API.
	 *
	 * @var string
	 */
	public static $namespace = 'jetpack/v4/stats-app';

	/**
	 * Hold an instance of WPCOM_Stats.
	 *
	 * @var WPCOM_Stats
	 */
	protected $wpcom_stats;

	/**
	 * Constructor
	 */
	public function __construct() {
		$this->wpcom_stats = new WPCOM_Stats();
	}

	/**
	 * Registers the REST routes for Odyssey Stats.
	 *
	 * Odyssey Stats is built from `wp-calypso`, which leverages the `public-api.wordpress.com` API.
	 * The current Site ID is added as part of the route, so that the front end doesn't have to handle the differences.
	 *
	 * @access public
	 * @static
	 */
	public function register_rest_routes() {
		// Stats for single resource type.
		register_rest_route(
			static::$namespace,
			sprintf( '/sites/%d/stats/(?P<resource>[\-\w]+)/(?P<resource_id>[\d]+)', Jetpack_Options::get_option( 'id' ) ),
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_single_resource_stats' ),
				'permission_callback' => array( $this, 'can_user_view_general_stats_callback' ),
			)
		);

		// Stats for a resource type.
		register_rest_route(
			static::$namespace,
			sprintf( '/sites/%d/stats/(?P<resource>[\-\w]+)', Jetpack_Options::get_option( 'id' ) ),
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_stats_resource' ),
				'permission_callback' => array( $this, 'can_user_view_general_stats_callback' ),
			)
		);

		// Single post info.
		register_rest_route(
			static::$namespace,
			sprintf( '/sites/%d/posts/(?P<resource_id>[\d]+)', Jetpack_Options::get_option( 'id' ) ),
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_single_post' ),
				'permission_callback' => array( $this, 'can_user_view_general_stats_callback' ),
			)
		);

		// Single post likes.
		register_rest_route(
			static::$namespace,
			sprintf( '/sites/%d/posts/(?P<resource_id>[\d]+)/likes', Jetpack_Options::get_option( 'id' ) ),
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_single_post_likes' ),
				'permission_callback' => array( $this, 'can_user_view_general_stats_callback' ),
			)
		);

		// General stats for the site.
		register_rest_route(
			static::$namespace,
			sprintf( '/sites/%d/stats', Jetpack_Options::get_option( 'id' ) ),
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_site_stats' ),
				'permission_callback' => array( $this, 'can_user_view_general_stats_callback' ),
			)
		);

		// Whether site has never published post / page.
		register_rest_route(
			static::$namespace,
			sprintf( '/sites/%d/site-has-never-published-post', Jetpack_Options::get_option( 'id' ) ),
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'site_has_never_published_post' ),
				'permission_callback' => array( $this, 'can_user_view_general_stats_callback' ),
			)
		);

		// List posts.
		register_rest_route(
			static::$namespace,
			sprintf( '/sites/%d/posts', Jetpack_Options::get_option( 'id' ) ),
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_site_posts' ),
				'permission_callback' => array( $this, 'can_user_view_general_stats_callback' ),
			)
		);

		// WordAds Earnings.
		register_rest_route(
			static::$namespace,
			sprintf( '/sites/%d/wordads/earnings', Jetpack_Options::get_option( 'id' ) ),
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_wordads_earnings' ),
				'permission_callback' => array( $this, 'can_user_view_wordads_stats_callback' ),
			)
		);

		// WordAds Stats.
		register_rest_route(
			static::$namespace,
			sprintf( '/sites/%d/wordads/stats', Jetpack_Options::get_option( 'id' ) ),
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_wordads_stats' ),
				'permission_callback' => array( $this, 'can_user_view_wordads_stats_callback' ),
			)
		);

		// Stats notices.
		register_rest_route(
			static::$namespace,
			'/stats/notices',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( $this, 'update_notice_status' ),
				'permission_callback' => array( $this, 'can_user_view_general_stats_callback' ),
				'args'                => array(
					'id'            => array(
						'required'    => true,
						'type'        => 'string',
						'description' => 'ID of the notice',
						'enum'        => array(
							Notices::OPT_IN_NEW_STATS_NOTICE_ID,
							Notices::OPT_OUT_NEW_STATS_NOTICE_ID,
							Notices::NEW_STATS_FEEDBACK_NOTICE_ID,
						),
					),
					'status'        => array(
						'required'    => true,
						'type'        => 'string',
						'description' => 'Status of the notice',
						'enum'        => array(
							Notices::NOTICE_STATUS_DISMISSED,
							Notices::NOTICE_STATUS_POSTPONED,
						),
					),
					'postponed_for' => array(
						'type'        => 'number',
						'default'     => null,
						'description' => 'Postponed for (in seconds)',
						'minimum'     => 0,
					),
				),
			)
		);
	}

	/**
	 * Only administrators or users with capability `view_stats` can access the API.
	 *
	 * @return bool|WP_Error True if a blog token was used to sign the request, WP_Error otherwise.
	 */
	public function can_user_view_general_stats_callback() {
		if ( current_user_can( 'manage_options' ) || current_user_can( 'view_stats' ) ) {
			return true;
		}

		return $this->get_forbidden_error();
	}

	/**
	 * Only administrators or users with capability `activate_wordads` can access the API.
	 */
	public function can_user_view_wordads_stats_callback() {
		// phpcs:ignore WordPress.WP.Capabilities.Unknown
		if ( current_user_can( 'manage_options' ) || current_user_can( 'activate_wordads' ) ) {
			return true;
		}

		return $this->get_forbidden_error();
	}

	/**
	 * Stats resource endpoint.
	 *
	 * @param WP_REST_Request $req The request object.
	 * @return array
	 */
	public function get_stats_resource( $req ) {
		switch ( $req->get_param( 'resource' ) ) {
			case 'file-downloads':
				return $this->wpcom_stats->get_file_downloads( $req->get_params() );

			case 'video-plays':
				return $this->wpcom_stats->get_video_plays( $req->get_params() );

			case 'clicks':
				return $this->wpcom_stats->get_clicks( $req->get_params() );

			case 'search-terms':
				return $this->wpcom_stats->get_search_terms( $req->get_params() );

			case 'top-authors':
				return $this->wpcom_stats->get_top_authors( $req->get_params() );

			case 'country-views':
				return $this->wpcom_stats->get_views_by_country( $req->get_params() );

			case 'referrers':
				return $this->wpcom_stats->get_referrers( $req->get_params() );

			case 'top-posts':
				return $this->wpcom_stats->get_top_posts( $req->get_params() );

			case 'publicize':
				return $this->wpcom_stats->get_publicize_followers( $req->get_params() );

			case 'followers':
				return $this->wpcom_stats->get_followers( $req->get_params() );

			case 'tags':
				return $this->wpcom_stats->get_tags( $req->get_params() );

			case 'visits':
				return $this->wpcom_stats->get_visits( $req->get_params() );

			case 'comments':
				return $this->wpcom_stats->get_top_comments( $req->get_params() );

			case 'comment-followers':
				return $this->wpcom_stats->get_comment_followers( $req->get_params() );

			case 'streak':
				return $this->wpcom_stats->get_streak( $req->get_params() );

			case 'insights':
				return $this->wpcom_stats->get_insights( $req->get_params() );

			case 'highlights':
				return $this->wpcom_stats->get_highlights( $req->get_params() );

			default:
				return $this->get_forbidden_error();
		}
	}

	/**
	 * Return likes of a single post.
	 *
	 * @param WP_REST_Request $req The request object.
	 */
	public function get_single_post_likes( $req ) {
		$response = wp_remote_get(
			sprintf(
				'%s/rest/v1.2/sites/%d/posts/%d/likes?%s',
				Constants::get_constant( 'JETPACK__WPCOM_JSON_API_BASE' ),
				Jetpack_Options::get_option( 'id' ),
				$req->get_param( 'resource_id' ),
				$this->filter_and_build_query_string(
					$req->get_params(),
					array( 'resource_id' )
				)
			),
			array( 'timeout' => 5 )
		);

		$response_code = wp_remote_retrieve_response_code( $response );
		$response_body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( 200 !== $response_code ) {
			return new WP_Error(
				isset( $response_body['error'] ) ? 'remote-error-' . $response_body['error'] : 'remote-error',
				isset( $response_body['message'] ) ? $response_body['message'] : 'unknown remote error',
				array( 'status' => $response_code )
			);
		}

		return $response_body;
	}

	/**
	 * Site Stats Resource endpoint.
	 *
	 * @param WP_REST_Request $req The request object.
	 * @return array
	 */
	public function get_single_resource_stats( $req ) {
		switch ( $req->get_param( 'resource' ) ) {
			case 'post':
				return $this->wpcom_stats->get_post_views(
					intval( $req->get_param( 'resource_id' ) ),
					$req->get_params()
				);

			case 'video':
				return $this->wpcom_stats->get_video_details(
					intval( $req->get_param( 'resource_id' ) ),
					$req->get_params()
				);

			default:
				return $this->get_forbidden_error();
		}
	}

	/**
	 * Get brief information for a single post.
	 *
	 * @param WP_REST_Request $req The request object.
	 * @return array
	 */
	public function get_single_post( $req ) {
		$post = get_post( intval( $req->get_param( 'resource_id' ) ), 'OBJECT', 'display' );
		if ( is_wp_error( $post ) || empty( $post ) ) {
			return $post;
		}

		// It shouldn't be a problem because only title and ID are exposed.
		return array(
			'ID'    => $post->ID,
			'title' => $post->post_title,
			'URL'   => get_permalink( $post->ID ),
		);
	}

	/**
	 * Get site stats.
	 *
	 * @param WP_REST_Request $req The request object.
	 * @return array
	 */
	public function get_site_stats( $req ) {
		return $this->wpcom_stats->get_stats( $req->get_params() );
	}

	/**
	 * List posts for the site.
	 *
	 * @param WP_REST_Request $req The request object.
	 * @return array
	 */
	public function get_site_posts( $req ) {
		// Force wpcom response.
		$params   = array_merge( array( 'force' => 'wpcom' ), $req->get_params() );
		$response = wp_remote_get(
			sprintf(
				'%s/rest/v1.2/sites/%d/posts?%s',
				Constants::get_constant( 'JETPACK__WPCOM_JSON_API_BASE' ),
				Jetpack_Options::get_option( 'id' ),
				$req->get_param( 'resource_id' ),
				$this->filter_and_build_query_string( $params, array( 'resource_id' ) )
			),
			array( 'timeout' => 5 )
		);

		$response_code = wp_remote_retrieve_response_code( $response );
		$response_body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( 200 !== $response_code ) {
			return new WP_Error(
				isset( $response_body['error'] ) ? 'remote-error-' . $response_body['error'] : 'remote-error',
				isset( $response_body['message'] ) ? $response_body['message'] : 'unknown remote error',
				array( 'status' => $response_code )
			);
		}

		return $response_body;
	}

	/**
	 * Whether site has never published post.
	 *
	 * @param WP_REST_Request $req The request object.
	 * @return array
	 */
	public function site_has_never_published_post( $req ) {
		return $this->request_as_blog_cached(
			sprintf(
				'/sites/%d/site-has-never-published-post?%s',
				Jetpack_Options::get_option( 'id' ),
				$this->filter_and_build_query_string(
					$req->get_params()
				)
			),
			'v2',
			array( 'timeout' => 5 ),
			null,
			'wpcom'
		);
	}

	/**
	 * Get detailed WordAds earnings information for the site.
	 *
	 * @param WP_REST_Request $req The request object.
	 * @return array
	 */
	public function get_wordads_earnings( $req ) {
		return $this->request_as_blog_cached(
			sprintf(
				'/sites/%d/wordads/earnings?%s',
				Jetpack_Options::get_option( 'id' ),
				$this->filter_and_build_query_string(
					$req->get_params()
				)
			),
			'v1.1',
			array( 'timeout' => 5 )
		);
	}

	/**
	 * Get WordAds stats for the site.
	 *
	 * @param WP_REST_Request $req The request object.
	 * @return array
	 */
	public function get_wordads_stats( $req ) {
		return $this->request_as_blog_cached(
			sprintf(
				'/sites/%d/wordads/stats?%s',
				Jetpack_Options::get_option( 'id' ),
				$this->filter_and_build_query_string(
					$req->get_params()
				)
			),
			'v1.1',
			array( 'timeout' => 5 )
		);
	}

	/**
	 * Dismiss or delay stats notices.
	 *
	 * @param WP_REST_Request $req The request object.
	 * @return array
	 */
	public function update_notice_status( $req ) {
		return ( new Notices() )->update_notice( $req->get_param( 'id' ), $req->get_param( 'status' ), $req->get_param( 'postponed_for' ) );
	}

	/**
	 * Query the WordPress.com REST API using the blog token
	 *
	 * @param String $path The API endpoint relative path.
	 * @param String $version The API version.
	 * @param array  $args Request arguments.
	 * @param String $body Request body.
	 * @param String $base_api_path (optional) the API base path override, defaults to 'rest'.
	 * @param bool   $use_cache (optional) default to true.
	 * @return array|WP_Error $response Data.
	 */
	protected function request_as_blog_cached( $path, $version = '1.1', $args = array(), $body = null, $base_api_path = 'rest', $use_cache = true ) {
		// Arrays are serialized without considering the order of objects, but it's okay atm.
		$cache_key = 'STATS_REST_RESP_' . md5( implode( '|', array( $path, $version, wp_json_encode( $args ), wp_json_encode( $body ), $base_api_path ) ) );

		if ( $use_cache ) {
			$response_body_content = get_transient( $cache_key );
			if ( false !== $response_body_content ) {
				return json_decode( $response_body_content, true );
			}
		}

		$response = Client::wpcom_json_api_request_as_blog(
			$path,
			$version,
			$args,
			$body,
			$base_api_path
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$response_code         = wp_remote_retrieve_response_code( $response );
		$response_body_content = wp_remote_retrieve_body( $response );
		$response_body         = json_decode( $response_body_content, true );

		if ( 200 !== $response_code ) {
			return $this->get_wp_error( $response_body, $response_code );
		}

		// Cache the successful JSON response for 5 minutes.
		set_transient( $cache_key, $response_body_content, 5 * MINUTE_IN_SECONDS );
		return $response_body;
	}

	/**
	 * Return a WP_Error object with a forbidden error.
	 */
	protected function get_forbidden_error() {
		$error_msg = esc_html__(
			'You are not allowed to perform this action.',
			'jetpack-stats-admin'
		);

		return new WP_Error( 'rest_forbidden', $error_msg, array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Filter and build query string from all the requested params.
	 *
	 * @param array $params The params to filter.
	 * @param array $keys_to_unset The keys to unset from the params array.
	 * @return string The filtered and built query string.
	 */
	protected function filter_and_build_query_string( $params, $keys_to_unset = array() ) {
		if ( isset( $params['rest_route'] ) ) {
			unset( $params['rest_route'] );
		}
		if ( ! empty( $keys_to_unset ) && is_array( $keys_to_unset ) ) {
			foreach ( $keys_to_unset as $key ) {
				if ( isset( $params[ $key ] ) ) {
					unset( $params[ $key ] );
				}
			}
		}
		return http_build_query( $params );
	}

	/**
	 * Build error object from remote response body and status code.
	 *
	 * @param array $response_body Remote response body.
	 * @param int   $response_code Http response code.
	 * @return WP_Error
	 */
	protected function get_wp_error( $response_body, $response_code = 500 ) {
		$error_code = 'remote-error';
		foreach ( array( 'code', 'error' ) as $error_code_key ) {
			if ( isset( $response_body[ $error_code_key ] ) ) {
				$error_code = $response_body[ $error_code_key ];
				break;
			}
		}

		$error_message = isset( $response_body['message'] ) ? $response_body['message'] : 'unknown remote error';

		return new WP_Error(
			$error_code,
			$error_message,
			array( 'status' => $response_code )
		);
	}
}
