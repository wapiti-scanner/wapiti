<?php
/**
 * The Data class.
 * This class provides methods for data VideoPress access and manipulation.
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Status\Host;
use WP_REST_Request;
/**
 * The Data class.
 */
class Data {

	/**
	 * Gets the Jetpack blog ID
	 *
	 * @return int The blog ID
	 */
	public static function get_blog_id() {
		return VideoPressToken::blog_id();
	}

	/**
	 * Gets the VideoPress site privacy configuration.
	 *
	 * @return boolean If all the videos are private on the site
	 */
	public static function get_videopress_videos_private_for_site() {
		/**
		 * If it's a Simple site, returns the site privacy setting.
		 */
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			return video_is_private_wpcom_blog( get_current_blog_id() );
		}
		/**
		 * If it's a private Atomic site, the default setting is private as well.
		 */
		if ( ( new Host() )->is_woa_site() ) {
			if ( ( intval( get_option( 'blog_public', '' ) ) === -1 ) ) {
				return true;
			}
		}

		/* If it's a Jetpack site or a public Atomic site, check the settings */
		return boolval( get_option( 'videopress_private_enabled_for_site', false ) );
	}

	/**
	 * Gets the VideoPress Settings.
	 *
	 * @return array The settings as an associative array.
	 */
	public static function get_videopress_settings() {
		$site_type       = 'jetpack';
		$site_is_private = false;

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$site_type       = 'simple';
			$site_is_private = video_is_private_wpcom_blog( get_current_blog_id() );
		} elseif ( ( new Host() )->is_woa_site() ) {
			$site_type       = 'atomic';
			$site_is_private = intval( get_option( 'blog_public', '' ) ) === -1;
		}

		return array(
			'videopress_videos_private_for_site' => self::get_videopress_videos_private_for_site(),
			'site_is_private'                    => $site_is_private,
			'site_type'                          => $site_type,
		);
	}

	/**
	 * Gets the video data
	 *
	 * @param boolean $is_videopress - True when getting VideoPress data.
	 * @return array
	 */
	public static function get_video_data( $is_videopress = true ) {
		$video_data = array(
			'videos'     => array(),
			'total'      => 0,
			'totalPages' => 0,
			'query'      => array(
				'order'        => 'desc',
				'orderBy'      => 'date',
				'itemsPerPage' => 6,
				'page'         => 1,
			),
		);

		$args = array(
			'order'      => $video_data['query']['order'],
			'orderby'    => $video_data['query']['orderBy'],
			'per_page'   => $video_data['query']['itemsPerPage'],
			'page'       => $video_data['query']['page'],
			'media_type' => 'video',
		);

		if ( $is_videopress ) {
			$args['mime_type'] = 'video/videopress';
		} else {
			$args['no_videopress'] = true;
		}

		// Do an internal request for the media list
		$request = new WP_REST_Request( 'GET', '/wp/v2/media' );
		$request->set_query_params( $args );
		$response = rest_do_request( $request );

		if ( $response->is_error() ) {
			// @todo: error handling
			return $video_data;
		}

		// load the real values
		$video_data['videos'] = $response->get_data();
		$headers              = $response->get_headers();

		if ( isset( $headers['X-WP-Total'] ) ) {
			$video_data['total'] = $headers['X-WP-Total'];
		}

		if ( isset( $headers['X-WP-TotalPages'] ) ) {
			$video_data['totalPages'] = $headers['X-WP-TotalPages'];
		}

		return $video_data;
	}

	/**
	 * Gets the user data
	 *
	 * @return array
	 */
	public static function get_user_data() {
		$user_data = array(
			'items'      => array(),
			'pagination' => array(
				'total'      => 0,
				'totalPages' => 1,
			),
			'query'      => array(
				'order'   => 'asc',
				'orderBy' => 'name',
			),
			'_meta'      => array(
				'relyOnInitialState' => true,
			),
		);

		$args = array(
			'order'   => $user_data['query']['order'],
			'orderby' => $user_data['query']['orderBy'],
		);

		// Do an internal request for the user list
		$request = new WP_REST_Request( 'GET', '/wp/v2/users' );
		$request->set_query_params( $args );
		$response = rest_do_request( $request );

		if ( $response->is_error() ) {
			// @todo: error handling
			return $user_data;
		}

		// load the real values
		$user_data['items'] = $response->get_data();
		$headers            = $response->get_headers();

		if ( isset( $headers['X-WP-Total'] ) ) {
			$user_data['pagination']['total'] = $headers['X-WP-Total'];
		}

		if ( isset( $headers['X-WP-TotalPages'] ) ) {
			$user_data['pagination']['totalPages'] = $headers['X-WP-TotalPages'];
		}

		return $user_data;
	}

	/**
	 * Gets the VideoPress used storage space in bytes
	 *
	 * @return int the used storage space
	 */
	public static function get_storage_used() {
		$site_data = Site::get_site_info();
		if ( is_wp_error( $site_data ) ) {
			return 0;
		}

		if ( isset( $site_data['options'] ) && isset( $site_data['options']['videopress_storage_used'] ) ) {
			return intval( round( $site_data['options']['videopress_storage_used'] * 1024 * 1024 ) );
		} else {
			return 0;
		}
	}

	/**
	 * Return all the initial state that depends on a valid site connection
	 *
	 * @return array
	 */
	public static function get_connected_initial_state() {
		return array(
			'videos'    => array(
				'storageUsed' => self::get_storage_used(),
			),
			'purchases' => array(
				'items'      => Site::get_purchases(),
				'isFetching' => false,
			),
		);
	}

	/**
	 * Checks if the site has as connected owner
	 */
	public static function has_connected_owner() {
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			return true;
		}

		if ( ( new Connection_Manager() )->has_connected_owner() ) {
			return true;
		}

		return false;
	}

	/**
	 * Checks if the user is able to perform actions that modify data
	 */
	public static function can_perform_action() {
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			return true;
		}

		$connection = new Connection_Manager();

		return (
			$connection->is_connected() &&
			self::has_connected_owner() &&
			$connection->is_user_connected()
		);
	}

	/**
	 * Return the initial state of the VideoPress app,
	 * used to render initially the app in the frontend.
	 *
	 * @return array
	 */
	public static function get_initial_state() {
		$videopress_data   = self::get_video_data();
		$local_videos_data = self::get_video_data( false );

		// Tweak local videos data.
		$local_videos = array_map(
			function ( $video ) {
				$video              = (array) $video;
				$id                 = $video['id'];
				$media_details      = $video['media_details'];
				$jetpack_videopress = $video['jetpack_videopress'];
				$read_error         = null;

				// In malformed files, the media_details or jetpack_videopress properties are not arrays.
				if ( ! is_array( $media_details ) || ! is_array( $jetpack_videopress ) ) {
					$media_details      = (array) $media_details;
					$jetpack_videopress = (array) $jetpack_videopress;
					$read_error         = Upload_Exception::ERROR_MALFORMED_FILE;
				}

				// Check if video is already uploaded to VideoPress or has some error.
				try {
					$uploader                  = new Uploader( $id );
					$is_uploaded_to_videopress = $uploader->is_uploaded();
				} catch ( Upload_Exception $e ) {
					$is_uploaded_to_videopress = false;
					$read_error                = $e->getCode();
				}

				$upload_date = $video['date'];
				$url         = $video['source_url'];

				$title       = $jetpack_videopress['title'];
				$description = $jetpack_videopress['description'];
				$caption     = $jetpack_videopress['caption'];

				$width    = isset( $media_details['width'] ) ? $media_details['width'] : null;
				$height   = isset( $media_details['height'] ) ? $media_details['height'] : null;
				$duration = isset( $media_details['length'] ) ? $media_details['length'] : null;

				return array(
					'id'                     => $id,
					'title'                  => $title,
					'description'            => $description,
					'caption'                => $caption,
					'width'                  => $width,
					'height'                 => $height,
					'url'                    => $url,
					'uploadDate'             => $upload_date,
					'duration'               => $duration,
					'isUploadedToVideoPress' => $is_uploaded_to_videopress,
					'readError'              => $read_error,
				);
			},
			$local_videos_data['videos']
		);

		// Tweak VideoPress videos data.
		$videos = array_map(
			function ( $video ) {
				$video              = (array) $video;
				$id                 = $video['id'];
				$guid               = $video['jetpack_videopress_guid'];
				$media_details      = (array) $video['media_details'];
				$jetpack_videopress = (array) $video['jetpack_videopress'];

				$videopress_media_details = $media_details['videopress'];
				$width                    = $media_details['width'];
				$height                   = $media_details['height'];

				$title                = $jetpack_videopress['title'];
				$description          = $jetpack_videopress['description'];
				$caption              = $jetpack_videopress['caption'];
				$rating               = $jetpack_videopress['rating'];
				$allow_download       = $jetpack_videopress['allow_download'];
				$display_embed        = $jetpack_videopress['display_embed'];
				$privacy_setting      = $jetpack_videopress['privacy_setting'];
				$needs_playback_token = $jetpack_videopress['needs_playback_token'];
				$is_private           = $jetpack_videopress['is_private'];

				$original      = $videopress_media_details['original'];
				$poster        = ( ! $needs_playback_token ) ? $videopress_media_details['poster'] : null;
				$upload_date   = $videopress_media_details['upload_date'];
				$duration      = $videopress_media_details['duration'];
				$file_url_base = $videopress_media_details['file_url_base'];
				$finished      = $videopress_media_details['finished'];
				$files         = $videopress_media_details['files'];
				$filename      = basename( $original );

				if ( isset( $files['dvd']['original_img'] ) && $privacy_setting !== 1 ) {
					$thumbnail = $file_url_base['https'] . $files['dvd']['original_img'];
				} else {
					$thumbnail = null;
				}

				return array(
					'id'                 => $id,
					'guid'               => $guid,
					'title'              => $title,
					'description'        => $description,
					'caption'            => $caption,
					'url'                => $original,
					'uploadDate'         => $upload_date,
					'duration'           => $duration,
					'isPrivate'          => $is_private,
					'posterImage'        => $poster,
					'allowDownload'      => $allow_download,
					'displayEmbed'       => $display_embed,
					'rating'             => $rating,
					'privacySetting'     => $privacy_setting,
					'needsPlaybackToken' => $needs_playback_token,
					'width'              => $width,
					'height'             => $height,
					'poster'             => array(
						'src' => $poster,
					),
					'thumbnail'          => $thumbnail,
					'finished'           => $finished,
					'filename'           => $filename,
				);
			},
			$videopress_data['videos']
		);

		$site_settings = self::get_videopress_settings();

		$initial_state = array(
			'users'        => self::get_user_data(),
			'siteSettings' => array(
				'videoPressVideosPrivateForSite' => $site_settings['videopress_videos_private_for_site'],
				'siteIsPrivate'                  => $site_settings['site_is_private'],
				'siteType'                       => $site_settings['site_type'],
			),
			'videos'       => array(
				'uploadedVideoCount'           => $videopress_data['total'],
				'items'                        => $videos,
				'isFetching'                   => false,
				'isFetchingUploadedVideoCount' => false,
				'pagination'                   => array(
					'totalPages' => $videopress_data['totalPages'],
					'total'      => $videopress_data['total'],
				),
				'query'                        => $videopress_data['query'],
				'_meta'                        => array(
					'processedAllVideosBeingRemoved' => true,
					'relyOnInitialState'             => true,
				),
			),
			'localVideos'  => array(
				'uploadedVideoCount'           => $local_videos_data['total'],
				'items'                        => $local_videos,
				'isFetching'                   => false,
				'isFetchingUploadedVideoCount' => false,
				'pagination'                   => array(
					'totalPages' => $local_videos_data['totalPages'],
					'total'      => $local_videos_data['total'],
				),
				'query'                        => $local_videos_data['query'],
				'_meta'                        => array(
					'relyOnInitialState' => true,
				),
			),
		);

		if ( self::has_connected_owner() ) {
			return array_merge_recursive( $initial_state, self::get_connected_initial_state() );
		}

		return $initial_state;
	}
}
