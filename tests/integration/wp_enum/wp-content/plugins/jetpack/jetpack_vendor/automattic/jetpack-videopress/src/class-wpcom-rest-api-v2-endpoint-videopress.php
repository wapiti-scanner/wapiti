<?php
/**
 * REST API endpoint for managing VideoPress metadata.
 *
 * @package automattic/jetpack
 * @since-jetpack 9.3.0
 * @since 0.1.3
 */

namespace Automattic\Jetpack\VideoPress;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Constants;
use WP_Error;
use WP_REST_Controller;
use WP_REST_Response;
use WP_REST_Server;

/**
 * VideoPress wpcom api v2 endpoint
 */
class WPCOM_REST_API_V2_Endpoint_VideoPress extends WP_REST_Controller {
	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->namespace = 'wpcom/v2';
		$this->rest_base = 'videopress';

		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register the route.
	 */
	public function register_routes() {
		// Meta Route.
		register_rest_route(
			$this->namespace,
			$this->rest_base . '/meta',
			array(
				'args'                => array(
					'id'              => array(
						'description'       => __( 'The post id for the attachment.', 'jetpack-videopress-pkg' ),
						'type'              => 'int',
						'required'          => true,
						'validate_callback' => function ( $param ) {
							return is_numeric( $param );
						},
					),
					'title'           => array(
						'description'       => __( 'The title of the video.', 'jetpack-videopress-pkg' ),
						'type'              => 'string',
						'required'          => false,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'description'     => array(
						'description'       => __( 'The description of the video.', 'jetpack-videopress-pkg' ),
						'type'              => 'string',
						'required'          => false,
						'sanitize_callback' => 'sanitize_textarea_field',
					),
					'caption'         => array(
						'description'       => __( 'The caption of the video.', 'jetpack-videopress-pkg' ),
						'type'              => 'string',
						'required'          => false,
						'sanitize_callback' => 'sanitize_textarea_field',
					),
					'rating'          => array(
						'description'       => __( 'The video content rating. One of G, PG-13 or R-17', 'jetpack-videopress-pkg' ),
						'type'              => 'string',
						'required'          => false,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'display_embed'   => array(
						'description'       => __( 'Display the share menu in the player.', 'jetpack-videopress-pkg' ),
						'type'              => 'boolean',
						'required'          => false,
						'sanitize_callback' => 'rest_sanitize_boolean',
					),
					'allow_download'  => array(
						'description'       => __( 'Display download option and allow viewers to download this video', 'jetpack-videopress-pkg' ),
						'type'              => 'boolean',
						'required'          => false,
						'sanitize_callback' => 'rest_sanitize_boolean',
					),
					'privacy_setting' => array(
						'description'       => __( 'How to determine if the video should be public or private', 'jetpack-videopress-pkg' ),
						'type'              => 'int',
						'required'          => false,
						'validate_callback' => function ( $param ) {
							return is_numeric( $param );
						},
					),
				),
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( $this, 'videopress_block_update_meta' ),
				'permission_callback' => function () {
					return Data::can_perform_action() && current_user_can( 'edit_posts' );
				},
			)
		);

		// Poster Route.
		register_rest_route(
			$this->namespace,
			$this->rest_base . '/(?P<video_guid>\w+)/poster',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'videopress_block_get_poster' ),
					'permission_callback' => function () {
						return current_user_can( 'read' );
					},
				),
				array(
					'args'                => array(
						'at_time'              => array(
							'description'       => __( 'The time in the video to use as the poster frame.', 'jetpack-videopress-pkg' ),
							'type'              => 'int',
							'required'          => false,
							'validate_callback' => function ( $param ) {
								return is_numeric( $param );
							},
						),
						'is_millisec'          => array(
							'description'       => __( 'Whether the time is in milliseconds or seconds.', 'jetpack-videopress-pkg' ),
							'type'              => 'boolean',
							'required'          => false,
							'sanitize_callback' => 'rest_sanitize_boolean',
						),
						'poster_attachment_id' => array(
							'description'       => __( 'The attachment id of the poster image.', 'jetpack-videopress-pkg' ),
							'type'              => 'int',
							'required'          => false,
							'validate_callback' => function ( $param ) {
								return is_numeric( $param );
							},
						),
					),
					'methods'             => WP_REST_Server::EDITABLE,
					'callback'            => array( $this, 'videopress_block_update_poster' ),
					'permission_callback' => function () {
						return Data::can_perform_action() && current_user_can( 'upload_files' );
					},
				),
			)
		);

		// Token Route
		register_rest_route(
			$this->namespace,
			$this->rest_base . '/upload-jwt',
			array(
				'methods'             => \WP_REST_Server::EDITABLE,
				'callback'            => array( $this, 'videopress_upload_jwt' ),
				'permission_callback' => function () {
					return Data::can_perform_action() && current_user_can( 'upload_files' );
				},
			)
		);

		// Playback Token Route
		register_rest_route(
			$this->namespace,
			$this->rest_base . '/playback-jwt/(?P<video_guid>\w+)',
			array(
				'methods'             => \WP_REST_Server::EDITABLE,
				'callback'            => array( $this, 'videopress_playback_jwt' ),
				'permission_callback' => function () {
					return current_user_can( 'read' );
				},
			)
		);
	}

	/**
	 * Hit WPCOM poster endpoint.
	 *
	 * @param string $video_guid  The VideoPress GUID.
	 * @param array  $args        Request args.
	 * @param array  $body        Request body.
	 * @param string $query       Request query.
	 * @return WP_REST_Response|WP_Error
	 */
	public function wpcom_poster_request( $video_guid, $args, $body = null, $query = '' ) {
		$query    = $query !== '' ? '?' . $query : '';
		$endpoint = 'videos/' . $video_guid . '/poster' . $query;

		$url = sprintf(
			'%s/%s/v%s/%s',
			Constants::get_constant( 'JETPACK__WPCOM_JSON_API_BASE' ),
			'rest',
			'1.1',
			$endpoint
		);

		$request_args = array_merge( $args, array( 'body' => $body ) );

		$result = Client::_wp_remote_request( $url, $request_args );

		if ( is_wp_error( $result ) ) {
			return rest_ensure_response( $result );
		}

		$response = $result['http_response'];

		$status = $response->get_status();

		$data = array(
			'code' => $status,
			'data' => json_decode( $response->get_data(), true ),
		);

		return rest_ensure_response(
			new WP_REST_Response( $data, $status )
		);
	}

	/**
	 * Update the a poster image via the WPCOM REST API.
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function videopress_block_update_poster( $request ) {
		try {
			$blog_id     = VideoPressToken::blog_id();
			$token       = VideoPressToken::videopress_onetime_upload_token();
			$video_guid  = $request->get_param( 'video_guid' );
			$json_params = $request->get_json_params();

			$args = array(
				'method'  => 'POST',
				'headers' => array(
					'content-type'  => 'application/json',
					'Authorization' => 'X_UPLOAD_TOKEN token="' . $token . '" blog_id="' . $blog_id . '"',
				),
			);

			return $this->wpcom_poster_request(
				$video_guid,
				$args,
				wp_json_encode( $json_params )
			);
		} catch ( \Exception $e ) {
			return rest_ensure_response( new WP_Error( 'videopress_block_update_poster_error', $e->getMessage() ) );
		}
	}

	/**
	 * Retrieves a poster image via the WPCOM REST API.
	 *
	 * @param WP_REST_Request $request the request object.
	 * @return object|WP_Error Success object or WP_Error with error details.
	 */
	public function videopress_block_get_poster( $request ) {
		$video_guid = $request->get_param( 'video_guid' );
		$jwt        = VideoPressToken::videopress_playback_jwt( $video_guid );

		$args = array(
			'method' => 'GET',
		);

		return $this->wpcom_poster_request(
			$video_guid,
			$args,
			null,
			'metadata_token=' . $jwt
		);
	}

	/**
	 * Endpoint for getting the VideoPress Upload JWT
	 *
	 * @return WP_Rest_Response - The response object.
	 */
	public static function videopress_upload_jwt() {
		$has_connected_owner = Data::has_connected_owner();
		if ( ! $has_connected_owner ) {
			return rest_ensure_response(
				new WP_Error(
					'owner_not_connected',
					'User not connected.',
					array(
						'code'        => 503,
						'connect_url' => Admin_UI::get_admin_page_url(),
					)
				)
			);
		}

		$blog_id = Data::get_blog_id();
		if ( ! $blog_id ) {
			return rest_ensure_response(
				new WP_Error( 'site_not_registered', 'Site not registered.', 503 )
			);
		}

		try {
			$token  = VideoPressToken::videopress_upload_jwt();
			$status = 200;
			$data   = array(
				'upload_token'   => $token,
				'upload_url'     => videopress_make_resumable_upload_path( $blog_id ),
				'upload_blog_id' => $blog_id,
			);
		} catch ( \Exception $e ) {
			$status = 500;
			$data   = array(
				'error' => $e->getMessage(),
			);

		}

		return rest_ensure_response(
			new WP_REST_Response( $data, $status )
		);
	}

	/**
	 * Endpoint for generating a VideoPress Playback JWT
	 *
	 * @param WP_REST_Request $request the request object.
	 * @return WP_Rest_Response - The response object.
	 */
	public static function videopress_playback_jwt( $request ) {
		$has_connected_owner = Data::has_connected_owner();
		if ( ! $has_connected_owner ) {
			return rest_ensure_response(
				new WP_Error(
					'owner_not_connected',
					'User not connected.',
					array(
						'code'        => 503,
						'connect_url' => Admin_UI::get_admin_page_url(),
					)
				)
			);
		}

		$blog_id = Data::get_blog_id();
		if ( ! $blog_id ) {
			return rest_ensure_response(
				new WP_Error( 'site_not_registered', 'Site not registered.', 503 )
			);
		}

		try {
			$video_guid = $request->get_param( 'video_guid' );
			$token      = VideoPressToken::videopress_playback_jwt( $video_guid );
			$status     = 200;
			$data       = array(
				'playback_token' => $token,
			);
		} catch ( \Exception $e ) {
			$status = 500;
			$data   = array(
				'error' => $e->getMessage(),
			);

		}

		return rest_ensure_response(
			new WP_REST_Response( $data, $status )
		);
	}

	/**
	 * Updates attachment meta and video metadata via the WPCOM REST API.
	 *
	 * @param WP_REST_Request $request the request object.
	 * @return object|WP_Error Success object or WP_Error with error details.
	 */
	public function videopress_block_update_meta( $request ) {
		$json_params = $request->get_json_params();
		$post_id     = $json_params['id'];

		if ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) {
			$guid = get_post_meta( $post_id, 'videopress_guid', true );
		} else {
			$blog_id = get_current_blog_id();
			$info    = video_get_info_by_blogpostid( $blog_id, $post_id );
			$guid    = $info->guid;
		}

		if ( ! $guid ) {
			return rest_ensure_response(
				new WP_Error(
					'error',
					__( 'This attachment cannot be updated yet.', 'jetpack-videopress-pkg' )
				)
			);
		}

		$video_request_params = $json_params;
		unset( $video_request_params['id'] );
		$video_request_params['guid'] = $guid;

		$endpoint = 'videos';
		$args     = array(
			'method'  => 'POST',
			'headers' => array( 'content-type' => 'application/json' ),
		);

		$result = Client::wpcom_json_api_request_as_blog(
			$endpoint,
			'2',
			$args,
			wp_json_encode( $video_request_params ),
			'wpcom'
		);

		if ( is_wp_error( $result ) ) {
			return rest_ensure_response( $result );
		}

		$response_body = json_decode( wp_remote_retrieve_body( $result ) );
		if ( is_bool( $response_body ) && $response_body ) {
			/*
			 * Title, description and caption of the video are not stored as metadata on the attachment,
			 * but as post_content, post_title and post_excerpt on the attachment's post object.
			 * We need to update those fields here, too.
			 */
			$post_title = null;
			if ( isset( $json_params['title'] ) ) {
				$post_title = sanitize_text_field( $json_params['title'] );
				wp_update_post(
					array(
						'ID'         => $post_id,
						'post_title' => $post_title,
					)
				);
			}

			$post_content = null;
			if ( isset( $json_params['description'] ) ) {
				$post_content = sanitize_textarea_field( $json_params['description'] );
				wp_update_post(
					array(
						'ID'           => $post_id,
						'post_content' => $post_content,
					)
				);
			}

			$post_excerpt = null;
			if ( isset( $json_params['caption'] ) ) {
				$post_excerpt = sanitize_textarea_field( $json_params['caption'] );
				wp_update_post(
					array(
						'ID'           => $post_id,
						'post_excerpt' => $post_excerpt,
					)
				);
			}

			// VideoPress data is stored in attachment meta for Jetpack sites, but not on wpcom.
			if ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) {
				$meta               = wp_get_attachment_metadata( $post_id );
				$should_update_meta = false;

				if ( ! $meta ) {
					return rest_ensure_response(
						new WP_Error(
							'error',
							__( 'Attachment meta was not found.', 'jetpack-videopress-pkg' )
						)
					);
				}

				if ( isset( $json_params['display_embed'] ) && isset( $meta['videopress']['display_embed'] ) ) {
					$meta['videopress']['display_embed'] = $json_params['display_embed'];
					$should_update_meta                  = true;
				}

				if ( isset( $json_params['rating'] ) && isset( $meta['videopress']['rating'] ) && videopress_is_valid_video_rating( $json_params['rating'] ) ) {
					$meta['videopress']['rating'] = $json_params['rating'];
					$should_update_meta           = true;

					/** Set a new meta field so we can filter using it directly */
					update_post_meta( $post_id, 'videopress_rating', $json_params['rating'] );
				}

				if ( isset( $json_params['title'] ) ) {
					$meta['videopress']['title'] = $post_title;
					$should_update_meta          = true;
				}

				if ( isset( $json_params['description'] ) ) {
					$meta['videopress']['description'] = $post_content;
					$should_update_meta                = true;
				}

				if ( isset( $json_params['caption'] ) ) {
					$meta['videopress']['caption'] = $post_excerpt;
					$should_update_meta            = true;
				}

				if ( isset( $json_params['poster'] ) ) {
					$meta['videopress']['poster'] = $json_params['poster'];
					$should_update_meta           = true;
				}

				if ( isset( $json_params['allow_download'] ) ) {
					$allow_download = (bool) $json_params['allow_download'];
					if ( ! isset( $meta['videopress']['allow_download'] ) || $meta['videopress']['allow_download'] !== $allow_download ) {
						$meta['videopress']['allow_download'] = $allow_download;
						$should_update_meta                   = true;
					}
				}

				if ( isset( $json_params['privacy_setting'] ) ) {
					$privacy_setting = $json_params['privacy_setting'];
					if ( ! isset( $meta['videopress']['privacy_setting'] ) || $meta['videopress']['privacy_setting'] !== $privacy_setting ) {
						$meta['videopress']['privacy_setting'] = $privacy_setting;
						$should_update_meta                    = true;

						/** Set a new meta field so we can filter using it directly */
						update_post_meta( $post_id, 'videopress_privacy_setting', $privacy_setting );
					}
				}

				if ( $should_update_meta ) {
					wp_update_attachment_metadata( $post_id, $meta );
				}
			}

			return rest_ensure_response(
				array(
					'code'    => 'success',
					'message' => __( 'Video meta updated successfully.', 'jetpack-videopress-pkg' ),
					'data'    => 200,
				)
			);
		} else {
			return rest_ensure_response(
				new WP_Error(
					$response_body->code,
					$response_body->message,
					$response_body->data
				)
			);
		}
	}
}

if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	wpcom_rest_api_v2_load_plugin( 'Automattic\Jetpack\VideoPress\WPCOM_REST_API_V2_Endpoint_VideoPress' );
}
