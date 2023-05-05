<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Extend the REST API functionality for VideoPress users.
 *
 * @package automattic/jetpack-videopress
 * @since-jetpack 7.1.0
 * @since 0.3.1
 */

namespace Automattic\Jetpack\VideoPress;

/**
 * Add per-attachment VideoPress data.
 *
 * { # Attachment Object
 *   ...
 *   jetpack_videopress: (object) VideoPress data
 *   ...
 * }
 *
 * @since 7.1.0
 */
class WPCOM_REST_API_V2_Attachment_VideoPress_Data {
	/**
	 * The REST Object Type to which the jetpack_videopress field will be added.
	 *
	 * @var string
	 */
	protected $object_type = 'attachment';

	/**
	 * The name of the REST API field to add.
	 *
	 * @var string $field_name
	 */
	protected $field_name = 'jetpack_videopress';

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'rest_api_init', array( $this, 'register_fields' ) );

		if ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) {
			add_action( 'rest_api_init', array( $this, 'add_jetpack_videopress_custom_query_filters' ) );
		}

		// do this again later to collect any CPTs that get registered later.
		add_action( 'restapi_theme_init', array( $this, 'register_fields' ), 20 );
	}

	/**
	 * Registers the jetpack_videopress field and adds a filter to remove it for attachments that are not videos.
	 */
	public function register_fields() {
		global $wp_rest_additional_fields;

		if ( ! empty( $wp_rest_additional_fields[ $this->object_type ][ $this->field_name ] ) ) {
			return;
		}

		register_rest_field(
			$this->object_type,
			$this->field_name,
			array(
				'get_callback'    => array( $this, 'get' ),
				'update_callback' => null,
				'schema'          => $this->get_schema(),
			)
		);

		add_filter( 'rest_prepare_attachment', array( $this, 'remove_field_for_non_videos' ), 10, 2 );
	}

	/**
	 * Adds the custom query filters
	 */
	public function add_jetpack_videopress_custom_query_filters() {
		add_filter( 'rest_attachment_query', array( $this, 'filter_attachments_by_jetpack_videopress_fields' ), 999, 2 );
	}

	/**
	 * Filter request args to handle the custom VideoPress query filters
	 *
	 * Possible filters:
	 *
	 * `no_videopress`: the returned attachments should not have a videopress_guid
	 *
	 * @param array      $args The original list of args before the filtering.
	 * @param WP_Request $request The original request data.
	 */
	public function filter_attachments_by_jetpack_videopress_fields( $args, $request ) {

		if ( ! isset( $args['meta_query'] ) || ! is_array( $args['meta_query'] ) ) {
			$args['meta_query'] = array();
		}

		/* To ignore all VideoPress videos, select only attachments without videopress_guid meta field */
		if ( isset( $request['no_videopress'] ) ) {
			$args['meta_query'][] = array(
				'key'     => 'videopress_guid',
				'compare' => 'NOT EXISTS',
			);
		}

		/* Filter using privacy setting meta key */
		if ( isset( $request['videopress_privacy_setting'] ) ) {
			$videopress_privacy_setting = sanitize_text_field( $request['videopress_privacy_setting'] );

			/* Allows the filtering to happens using a list of privacy settings separated by comma */
			$videopress_privacy_setting_list = explode( ',', $videopress_privacy_setting );

			$site_default_is_private = Data::get_videopress_videos_private_for_site();

			if ( $site_default_is_private ) {
				/**
				 * If the search is looking for private videos and the site default is private,
				 * the site default setting should be included on the search.
				 */
				if ( in_array( strval( \VIDEOPRESS_PRIVACY::IS_PRIVATE ), $videopress_privacy_setting_list, true ) ) {
					$videopress_privacy_setting_list[] = \VIDEOPRESS_PRIVACY::SITE_DEFAULT;
				}
			} else { // phpcs:ignore Universal.ControlStructures.DisallowLonelyIf.Found
				/**
				 * If the search is looking for public videos and the site default is public,
				 * the site default setting should be included on the search.
				 */
				if ( in_array( strval( \VIDEOPRESS_PRIVACY::IS_PUBLIC ), $videopress_privacy_setting_list, true ) ) {
					$videopress_privacy_setting_list[] = \VIDEOPRESS_PRIVACY::SITE_DEFAULT;
				}
			}

			$args['meta_query'][] = array(
				'key'     => 'videopress_privacy_setting',
				'value'   => $videopress_privacy_setting_list,
				'compare' => 'IN',
			);
		}

		/* Filter using rating meta key */
		if ( isset( $request['videopress_rating'] ) ) {
			$videopress_rating = sanitize_text_field( $request['videopress_rating'] );

			/* Allows the filtering to happens using a list of ratings separated by comma */
			$videopress_rating_list = explode( ',', $videopress_rating );

			$args['meta_query'][] = array(
				'key'     => 'videopress_rating',
				'value'   => $videopress_rating_list,
				'compare' => 'IN',
			);
		}

		return $args;
	}

	/**
	 * Defines data structure and what elements are visible in which contexts
	 */
	public function get_schema() {
		return array(
			'$schema'     => 'http://json-schema.org/draft-04/schema#',
			'title'       => $this->field_name,
			'type'        => 'object',
			'context'     => array( 'view', 'edit' ),
			'readonly'    => true,
			'description' => __( 'VideoPress Data', 'jetpack-videopress-pkg' ),
		);
	}

	/**
	 * Getter: Retrieve current VideoPress data for a given attachment.
	 *
	 * @param array           $attachment Response from the attachment endpoint.
	 * @param WP_REST_Request $request Request to the attachment endpoint.
	 *
	 * @return string
	 */
	public function get( $attachment, $request ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$blog_id = get_current_blog_id();
		} else {
			$blog_id = \Jetpack_Options::get_option( 'id' );
		}

		$post_id = absint( $attachment['id'] );

		$videopress = $this->get_videopress_data( $post_id, $blog_id );

		if ( ! $videopress ) {
			return array();
		}

		return $videopress;
	}

	/**
	 * Gets the VideoPress GUID for a given attachment.
	 *
	 * This is pulled out into a separate method to support unit test mocking.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @param int $blog_id Blog ID.
	 *
	 * @return string
	 */
	public function get_videopress_data( $attachment_id, $blog_id ) {
		$info = video_get_info_by_blogpostid( $blog_id, $attachment_id );
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$title       = video_get_title( $blog_id, $attachment_id );
			$description = video_get_description( $blog_id, $attachment_id );

			$video_attachment = get_blog_post( $blog_id, $attachment_id );
			if ( null === $video_attachment ) {
				$caption = '';
			} else {
				$caption = $video_attachment->post_excerpt;
			}
		} else {
			$title       = $info->title;
			$description = $info->description;
			$caption     = $info->caption;
		}

		$video_privacy_setting    = ! isset( $info->privacy_setting ) ? \VIDEOPRESS_PRIVACY::SITE_DEFAULT : intval( $info->privacy_setting );
		$private_enabled_for_site = Data::get_videopress_videos_private_for_site();
		$is_private               = $this->video_is_private( $video_privacy_setting, $private_enabled_for_site );

		// The video needs a playback token if it's private for any reason (video privacy setting or site default privacy setting)
		$video_needs_playback_token = $is_private;

		return array(
			'title'                    => $title,
			'description'              => $description,
			'caption'                  => $caption,
			'guid'                     => $info->guid,
			'rating'                   => $info->rating,
			'allow_download'           =>
				isset( $info->allow_download ) && $info->allow_download ? 1 : 0,
			'display_embed'            =>
				isset( $info->display_embed ) && $info->display_embed ? 1 : 0,
			'privacy_setting'          => $video_privacy_setting,
			'needs_playback_token'     => $video_needs_playback_token,
			'is_private'               => $is_private,
			'private_enabled_for_site' => $private_enabled_for_site,
		);
	}

	/**
	 * Checks if the given attachment is a video.
	 *
	 * @param object $attachment The attachment object.
	 *
	 * @return false|int
	 */
	public function is_video( $attachment ) {
		return isset( $attachment->post_mime_type ) && wp_startswith( $attachment->post_mime_type, 'video/' );
	}

	/**
	 * Removes the jetpack_videopress field from the response if the
	 * given attachment is not a video.
	 *
	 * @param WP_REST_Response $response Response from the attachment endpoint.
	 * @param WP_Post          $attachment The original attachment object.
	 *
	 * @return mixed
	 */
	public function remove_field_for_non_videos( $response, $attachment ) {
		if ( ! $this->is_video( $attachment ) ) {
			unset( $response->data[ $this->field_name ] );
		}

		return $response;
	}

	/**
	 * Determines if a video is private based on the video privacy
	 * setting and the site default privacy setting.
	 *
	 * @param int  $video_privacy_setting The privacy setting for the video.
	 * @param bool $private_enabled_for_site Flag stating if the default video privacy is private.
	 *
	 * @return bool
	 */
	private function video_is_private( $video_privacy_setting, $private_enabled_for_site ) {
		if ( $video_privacy_setting === \VIDEOPRESS_PRIVACY::IS_PUBLIC ) {
			return false;
		}
		if ( $video_privacy_setting === \VIDEOPRESS_PRIVACY::IS_PRIVATE ) {
			return true;
		}

		return $private_enabled_for_site;
	}
}

if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	wpcom_rest_api_v2_load_plugin( 'Automattic\Jetpack\VideoPress\WPCOM_REST_API_V2_Attachment_VideoPress_Data' );
}
