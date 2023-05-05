<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Connection\Client;

defined( 'VIDEOPRESS_MIN_WIDTH' ) || define( 'VIDEOPRESS_MIN_WIDTH', 60 );
defined( 'VIDEOPRESS_DEFAULT_WIDTH' ) || define( 'VIDEOPRESS_DEFAULT_WIDTH', 640 );

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * VideoPress Privacy constants.
 */
abstract class VIDEOPRESS_PRIVACY {
	const IS_PUBLIC    = 0;
	const IS_PRIVATE   = 1;
	const SITE_DEFAULT = 2;
}

/**
 * Validate user-supplied guid values against expected inputs
 *
 * @since 1.1
 * @param string $guid video identifier.
 * @return bool true if passes validation test
 */
function videopress_is_valid_guid( $guid ) {
	if ( ! empty( $guid ) && is_string( $guid ) && strlen( $guid ) === 8 && ctype_alnum( $guid ) ) {
		return true;
	}
	return false;
}

/**
 * Get details about a specific video by GUID:
 *
 * @param string $guid Video GUID.
 * @return object
 */
function videopress_get_video_details( $guid ) {
	if ( ! videopress_is_valid_guid( $guid ) ) {
		return new WP_Error( 'bad-guid-format', __( 'Invalid Video GUID!', 'jetpack-videopress-pkg' ) );
	}

	$version   = '1.1';
	$endpoint  = sprintf( '/videos/%1$s', $guid );
	$query_url = sprintf(
		'https://public-api.wordpress.com/rest/v%1$s%2$s',
		$version,
		$endpoint
	);

	// Look for data in our transient. If nothing, let's make a new query.
	$data_from_cache = get_transient( 'jetpack_videopress_' . $guid );
	if ( false === $data_from_cache ) {
		$response = wp_remote_get( esc_url_raw( $query_url ) );
		$data     = json_decode( wp_remote_retrieve_body( $response ) );

		// Cache the response for an hour.
		set_transient( 'jetpack_videopress_' . $guid, $data, HOUR_IN_SECONDS );
	} else {
		$data = $data_from_cache;
	}

	/**
	 * Allow functions to modify fetched video details.
	 *
	 * This filter allows third-party code to modify the return data
	 * about a given video.  It may involve swapping some data out or
	 * adding new parameters.
	 *
	 * @since 4.0.0
	 *
	 * @param object $data The data returned by the WPCOM API. See: https://developer.wordpress.com/docs/api/1.1/get/videos/%24guid/
	 * @param string $guid The GUID of the VideoPress video in question.
	 */
	return apply_filters( 'videopress_get_video_details', $data, $guid );
}

/**
 * Similar to `media_sideload_image` -- but returns an ID.
 *
 * @param string $url Image URL.
 * @param int    $attachment_id Post ID.
 *
 * @return int|mixed|object|WP_Error
 */
function videopress_download_poster_image( $url, $attachment_id ) {
	// Set variables for storage, fix file filename for query strings.
	preg_match( '/[^\?]+\.(jpe?g|jpe|gif|png)\b/i', $url, $matches );
	if ( ! $matches ) {
		return new WP_Error( 'image_sideload_failed', __( 'Invalid image URL', 'jetpack-videopress-pkg' ) );
	}

	$file_array             = array();
	$file_array['name']     = basename( $matches[0] );
	$file_array['tmp_name'] = download_url( $url );

	// If error storing temporarily, return the error.
	if ( is_wp_error( $file_array['tmp_name'] ) ) {
		return $file_array['tmp_name'];
	}

	// Do the validation and storage stuff.
	$thumbnail_id = media_handle_sideload( $file_array, $attachment_id, null );

	// Flag it as poster image, so we can exclude it from display.
	update_post_meta( $thumbnail_id, 'videopress_poster_image', 1 );

	return $thumbnail_id;
}

/**
 * Creates a local media library item of a remote VideoPress video.
 *
 * @param string $guid Video GUID.
 * @param int    $parent_id Parent post ID.
 *
 * @return int|object
 */
function create_local_media_library_for_videopress_guid( $guid, $parent_id = 0 ) {
	$vp_data = videopress_get_video_details( $guid );
	if ( ! $vp_data || is_wp_error( $vp_data ) ) {
		return $vp_data;
	}

	$args = array(
		'post_date'      => $vp_data->upload_date,
		'post_title'     => wp_kses( $vp_data->title, array() ),
		'post_content'   => wp_kses( $vp_data->description, array() ),
		'post_mime_type' => 'video/videopress',
		'guid'           => sprintf( 'https://videopress.com/v/%s', $guid ),
	);

	$attachment_id = wp_insert_attachment( $args, null, $parent_id );

	if ( ! is_wp_error( $attachment_id ) ) {
		update_post_meta( $attachment_id, 'videopress_guid', $guid );
		wp_update_attachment_metadata(
			$attachment_id,
			array(
				'width'  => $vp_data->width,
				'height' => $vp_data->height,
			)
		);

		$thumbnail_id = videopress_download_poster_image( $vp_data->poster, $attachment_id );
		update_post_meta( $attachment_id, '_thumbnail_id', $thumbnail_id );
	}

	return $attachment_id;
}

/**
 * Helper that will look for VideoPress media items that are more than 30 minutes old,
 * that have not had anything attached to them by a wpcom upload and deletes the ghost
 * attachment.
 *
 * These happen primarily because of failed upload attempts.
 *
 * @return int The number of items that were cleaned up.
 */
function videopress_cleanup_media_library() {
	// phpcs:disable Squiz.PHP.NonExecutableCode.Unreachable -- Function is disabled currently.
	// Disable this job for now.
	return 0;
	$query_args = array(
		'post_type'      => 'attachment',
		'post_status'    => 'inherit',
		'post_mime_type' => 'video/videopress',
		'meta_query'     => array(
			array(
				'key'   => 'videopress_status',
				'value' => 'new',
			),
		),
	);

	$query = new WP_Query( $query_args );

	$cleaned = 0;

	$now = current_time( 'timestamp' ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- Probably should refactor, but this function is disabled.

	if ( $query->have_posts() ) {
		foreach ( $query->posts as $post ) {
			$post_time = strtotime( $post->post_date_gmt );

			// If the post is older than 30 minutes, it is safe to delete it.
			if ( $now - $post_time > MINUTE_IN_SECONDS * 30 ) {
				// Force delete the attachment, because we don't want it appearing in the trash.
				wp_delete_attachment( $post->ID, true );

				++$cleaned;
			}
		}
	}

	return $cleaned;
	// phpcs:enable Squiz.PHP.NonExecutableCode.Unreachable
}

/**
 * Return an absolute URI for a given filename and guid on the CDN.
 * No check is performed to ensure the guid exists or the file is present. Simple centralized string builder.
 *
 * @param string $guid     VideoPress identifier.
 * @param string $filename name of file associated with the guid (video file name or thumbnail file name).
 *
 * @return string Absolute URL of VideoPress file for the given guid.
 */
function videopress_cdn_file_url( $guid, $filename ) {
	return "https://videos.files.wordpress.com/{$guid}/{$filename}";
}

/**
 * Get an array of the transcoding status for the given video post.
 *
 * @since 4.4
 * @param int $post_id Post ID.
 * @return array|bool Returns an array of statuses if this is a VideoPress post, otherwise it returns false.
 */
function videopress_get_transcoding_status( $post_id ) {
	$meta = wp_get_attachment_metadata( $post_id );

	// If this has not been processed by videopress, we can skip the rest.
	if ( ! $meta || ! isset( $meta['file_statuses'] ) ) {
		return false;
	}

	$info = (object) $meta['file_statuses'];

	$status = array(
		'std_mp4' => isset( $info->mp4 ) ? $info->mp4 : null,
		'std_ogg' => isset( $info->ogg ) ? $info->ogg : null,
		'dvd_mp4' => isset( $info->dvd ) ? $info->dvd : null,
		'hd_mp4'  => isset( $info->hd ) ? $info->hd : null,
	);

	return $status;
}

/**
 * Get the direct url to the video.
 *
 * @since 4.4
 * @param string $guid VideoPress GUID.
 * @return string
 */
function videopress_build_url( $guid ) {

	// No guid, no videopress url.
	if ( ! $guid ) {
		return '';
	}

	return 'https://videopress.com/v/' . $guid;
}

/**
 * Create an empty videopress media item that will be filled out later by an xmlrpc
 * callback from the VideoPress servers.
 *
 * @since 4.4
 * @param string $title The post_title.
 * @param string $guid The VideoPress guid.
 * @return int|WP_Error
 */
function videopress_create_new_media_item( $title, $guid = null ) {
	$post = array(
		'post_type'      => 'attachment',
		'post_mime_type' => 'video/videopress',
		'post_title'     => $title,
		'post_content'   => '',
		'guid'           => videopress_build_url( $guid ),
	);

	$media_id = wp_insert_post( $post );

	add_post_meta( $media_id, 'videopress_status', 'initiated' );

	add_post_meta( $media_id, 'videopress_guid', $guid );

	return $media_id;
}

/**
 * Merge VideoPress file status metadata.
 *
 * @param array $current_status The current status of the video.
 * @param array $new_meta The new meta data to merge with the current status.
 * @return array
 */
function videopress_merge_file_status( $current_status, $new_meta ) {
	$new_statuses = array();

	if ( isset( $new_meta['videopress']['files_status']['hd'] ) ) {
		$new_statuses['hd'] = $new_meta['videopress']['files_status']['hd'];
	}

	if ( isset( $new_meta['videopress']['files_status']['dvd'] ) ) {
		$new_statuses['dvd'] = $new_meta['videopress']['files_status']['dvd'];
	}

	if ( isset( $new_meta['videopress']['files_status']['std']['mp4'] ) ) {
		$new_statuses['mp4'] = $new_meta['videopress']['files_status']['std']['mp4'];
	}

	if ( isset( $new_meta['videopress']['files_status']['std']['ogg'] ) ) {
		$new_statuses['ogg'] = $new_meta['videopress']['files_status']['std']['ogg'];
	}

	foreach ( $new_statuses as $format => $status ) {
		if ( ! isset( $current_status[ $format ] ) ) {
			$current_status[ $format ] = $status;
			continue;
		}

		if ( $current_status[ $format ] !== 'DONE' ) {
			$current_status[ $format ] = $status;
		}
	}

	return $current_status;
}

/**
 * Check to see if a video has completed processing.
 *
 * @since 4.4
 * @param int $post_id Post ID.
 * @return bool
 */
function videopress_is_finished_processing( $post_id ) {
	$post = get_post( $post_id );

	if ( is_wp_error( $post ) ) {
		return false;
	}

	$meta = wp_get_attachment_metadata( $post->ID );
	if ( ! isset( $meta['videopress']['finished'] ) ) {
		return false;
	}

	return $meta['videopress']['finished'];
}

/**
 * Update the meta information  status for the given video post.
 *
 * @since 4.4
 * @param int $post_id Post ID.
 * @return bool
 */
function videopress_update_meta_data( $post_id ) {

	$meta = wp_get_attachment_metadata( $post_id );

	// If this has not been processed by VideoPress, we can skip the rest.
	if ( ! $meta || ! isset( $meta['videopress'] ) ) {
		return false;
	}

	$info = (object) $meta['videopress'];

	$result = Client::wpcom_json_api_request_as_blog( 'videos/' . $info->guid );

	if ( is_wp_error( $result ) ) {
		return false;
	}

	$response = json_decode( $result['body'], true );

	// Update the attachment metadata.
	$meta['videopress'] = $response;

	wp_update_attachment_metadata( $post_id, $meta );

	return true;
}

/**
 * Check to see if this is a VideoPress post that hasn't had a guid set yet.
 *
 * @param int $post_id Post ID.
 * @return bool
 */
function videopress_is_attachment_without_guid( $post_id ) {
	$post = get_post( $post_id );

	if ( is_wp_error( $post ) ) {
		return false;
	}

	if ( $post->post_mime_type !== 'video/videopress' ) {
		return false;
	}

	$videopress_guid = get_post_meta( $post_id, 'videopress_guid', true );

	if ( $videopress_guid ) {
		return false;
	}

	return true;
}

/**
 * Check to see if this is a VideoPress attachment.
 *
 * @param int $post_id Post ID.
 * @return bool
 */
function is_videopress_attachment( $post_id ) {
	$post = get_post( $post_id );

	if ( is_wp_error( $post ) ) {
		return false;
	}

	if ( $post->post_mime_type !== 'video/videopress' ) {
		return false;
	}

	return true;
}

/**
 * Get the video update path
 *
 * @since 4.4
 * @param string $guid VideoPress GUID.
 * @return string
 */
function videopress_make_video_get_path( $guid ) {
	return sprintf(
		'%s/rest/v%s/videos/%s',
		JETPACK__WPCOM_JSON_API_BASE,
		Client::WPCOM_JSON_API_VERSION,
		$guid
	);
}

/**
 * Get the upload api path.
 *
 * @since 4.4
 * @param int $blog_id The id of the blog we're uploading to.
 * @return string
 */
function videopress_make_media_upload_path( $blog_id ) {
	return sprintf(
		'https://public-api.wordpress.com/rest/v1.1/sites/%s/media/new?locale=%s',
		$blog_id,
		get_locale()
	);
}

/**
 * Get the resumable upload api path.
 *
 * @since 4.4
 * @param int $blog_id The id of the blog we're uploading to.
 * @return string
 */
function videopress_make_resumable_upload_path( $blog_id ) {
	return sprintf(
		'https://public-api.wordpress.com/rest/v1.1/video-uploads/%s/',
		$blog_id
	);
}

/**
 * This is a mock of the internal VideoPress method, which is meant to duplicate the functionality
 * of the WPCOM API, so that the Jetpack REST API returns the same data with no modifications.
 *
 * @param int $blog_id Blog ID.
 * @param int $post_id Post ID.
 * @return bool|stdClass
 */
function video_get_info_by_blogpostid( $blog_id, $post_id ) {
	$post = get_post( $post_id );

	$video_info                  = new stdClass();
	$video_info->post_id         = $post_id;
	$video_info->blog_id         = $blog_id;
	$video_info->guid            = null;
	$video_info->finish_date_gmt = '0000-00-00 00:00:00';
	$video_info->rating          = null;
	$video_info->description     = $post->post_content;
	$video_info->title           = $post->post_title;
	$video_info->caption         = $post->post_excerpt;

	if ( is_wp_error( $post ) ) {
		return $video_info;
	}

	if ( 'video/videopress' !== $post->post_mime_type ) {
		return $video_info;
	}

	// Since this is a VideoPress post, lt's fill out the rest of the object.
	$video_info->guid = get_post_meta( $post_id, 'videopress_guid', true );
	$meta             = wp_get_attachment_metadata( $post_id );

	if ( $meta && isset( $meta['videopress'] ) ) {
		$videopress_meta             = $meta['videopress'];
		$video_info->rating          = isset( $videopress_meta['rating'] ) ? $videopress_meta['rating'] : null;
		$video_info->allow_download  = isset( $videopress_meta['allow_download'] ) ? $videopress_meta['allow_download'] : 0;
		$video_info->display_embed   = isset( $videopress_meta['display_embed'] ) ? $videopress_meta['display_embed'] : 0;
		$video_info->privacy_setting = ! isset( $videopress_meta['privacy_setting'] ) ? VIDEOPRESS_PRIVACY::SITE_DEFAULT : $videopress_meta['privacy_setting'];
	}

	/** Make sure we are keeping some meta keys updated for filtering purposes */
	if ( get_post_meta( $post_id, 'videopress_rating', true ) !== $video_info->rating ) {
		update_post_meta( $post_id, 'videopress_rating', $video_info->rating );
	}
	if ( get_post_meta( $post_id, 'videopress_privacy_setting', true ) !== $video_info->privacy_setting ) {
		update_post_meta( $post_id, 'videopress_privacy_setting', $video_info->privacy_setting );
	}

	if ( videopress_is_finished_processing( $post_id ) ) {
		$video_info->finish_date_gmt = gmdate( 'Y-m-d H:i:s' );
	}

	return $video_info;
}

/**
 * Check that a VideoPress video format has finished processing.
 *
 * This uses the info object, because that is what the WPCOM endpoint
 * uses, however we don't have a complete info object in the same way
 * WPCOM does, so we pull the meta information out of the post
 * options instead.
 *
 * Note: This mimics the WPCOM function of the same name and helps the media
 * API endpoint add all needed VideoPress data.
 *
 * @param stdClass $info Info object.
 * @param string   $format Video format.
 * @return bool
 */
function video_format_done( $info, $format ) {

	// Avoids notice when a non-videopress item is found.
	if ( ! is_object( $info ) ) {
		return false;
	}

	$post_id = $info->post_id;

	if ( get_post_mime_type( $post_id ) !== 'video/videopress' ) {
		return false;
	}

	$post = get_post( $post_id );

	if ( is_wp_error( $post ) ) {
		return false;
	}

	$meta = wp_get_attachment_metadata( $post->ID );

	$video_format = str_replace( array( 'fmt_', 'fmt1_' ), '', $format );

	if ( 'ogg' === $video_format ) {
		return isset( $meta['videopress']['files']['std']['ogg'] );
	} else {
		return isset( $meta['videopress']['files'][ $video_format ]['mp4'] );
	}
}

/**
 * Get the image URL for the given VideoPress GUID
 *
 * We look up by GUID, because that is what WPCOM does and this needs to be
 * parameter compatible with that.
 *
 * Note: This mimics the WPCOM function of the same name and helps the media
 * API endpoint add all needed VideoPress data.
 *
 * @param string $guid VideoPress GUID.
 * @param string $format Video format.
 * @return string
 */
function video_image_url_by_guid( $guid, $format ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable

	$post = videopress_get_post_by_guid( $guid );

	if ( is_wp_error( $post ) ) {
		return null;
	}

	$meta = wp_get_attachment_metadata( $post->ID );

	$poster = apply_filters( 'jetpack_photon_url', $meta['videopress']['poster'] );

	return $poster;
}

/**
 * Using a GUID, find a post.
 *
 * @param string $guid The post guid.
 * @return WP_Post|false The post for that guid, or false if none is found.
 */
function videopress_get_post_by_guid( $guid ) {
	$cache_key   = 'get_post_by_guid_' . $guid;
	$cache_group = 'videopress';
	$cached_post = wp_cache_get( $cache_key, $cache_group );

	if ( is_object( $cached_post ) && 'WP_Post' === get_class( $cached_post ) ) {
		return $cached_post;
	}

	$post_id = videopress_get_post_id_by_guid( $guid );

	if ( is_int( $post_id ) ) {
		$post = get_post( $post_id );
		wp_cache_set( $cache_key, $post, $cache_group, HOUR_IN_SECONDS );

		return $post;
	}

	return false;
}

/**
 * Using a GUID, find the associated post ID.
 *
 * @since 8.4.0
 * @param string $guid The guid to look for the post ID of.
 * @return int|false The post ID for that guid, or false if none is found.
 */
function videopress_get_post_id_by_guid( $guid ) {
	$cache_key = 'videopress_get_post_id_by_guid_' . $guid;
	$cached_id = get_transient( $cache_key );

	if ( is_int( $cached_id ) ) {
		return $cached_id;
	}

	$args = array(
		'post_type'      => 'attachment',
		'post_mime_type' => 'video/videopress',
		'post_status'    => 'inherit',
		'no_found_rows'  => true,
		'fields'         => 'ids',
		'meta_query'     => array(
			array(
				'key'     => 'videopress_guid',
				'value'   => $guid,
				'compare' => '=',
			),
		),
	);

	$query = new WP_Query( $args );

	if ( $query->have_posts() ) {
		$post_id = $query->next_post();
		set_transient( $cache_key, $post_id, HOUR_IN_SECONDS );

		return $post_id;
	}

	return false;
}

/**
 * From the given VideoPress post_id, return back the appropriate attachment URL.
 *
 * When the MP4 hasn't been processed yet or this is not a VideoPress video, this will return null.
 *
 * @param int $post_id Post ID of the attachment.
 * @return string|null
 */
function videopress_get_attachment_url( $post_id ) {

	// We only handle VideoPress attachments.
	if ( get_post_mime_type( $post_id ) !== 'video/videopress' ) {
		return null;
	}

	$meta = wp_get_attachment_metadata( $post_id );

	// As of Jetpack 10.3 transcoded video files are reserved for the VideoPress player.
	// All other video file requests will receive the originally uploaded file, stored on the wpcom cdn.
	if ( ! isset( $meta['videopress']['original'] ) ) {
		// Use the original file as the url if it isn't transcoded yet.
		if ( isset( $meta['original'] ) ) {
			$return = $meta['original'];
		} else {
			// Otherwise, there isn't much we can do.
			return null;
		}
	} else {
		$return = $meta['videopress']['original'];
	}

	// If the URL is a string, return it. Otherwise, we shouldn't to avoid errors downstream, so null.
	return ( is_string( $return ) ) ? $return : null;
}

/**
 * Converts VideoPress flash embeds into oEmbed-able URLs.
 *
 * Older VideoPress embed depended on Flash, which no longer work,
 * so let us convert them to an URL that WordPress can oEmbed.
 *
 * Note that this file is always loaded via modules/module-extras.php and is not dependent on module status.
 *
 * @param string $content the content.
 * @return string filtered content
 */
function jetpack_videopress_flash_embed_filter( $content ) {
	$regex   = '%<embed[^>]*+>(?:\s*</embed>)?%i';
	$content = preg_replace_callback(
		$regex,
		function ( $matches ) {
			$embed_code  = $matches[0];
			$url_matches = array();

			// get video ID from flash URL.
			$url_matched = preg_match( '/src="http:\/\/v.wordpress.com\/([^"]+)"/', $embed_code, $url_matches );

			if ( $url_matched ) {
				$video_id = $url_matches[1];
				return "https://videopress.com/v/$video_id";
			}
		},
		$content
	);
	return $content;
}

/**
 * Checks if the provided rating string is a valid VideoPress video rating value.
 *
 * @param mixed $rating The video rating to validate.
 * @return bool
 */
function videopress_is_valid_video_rating( $rating ) {
	return in_array( $rating, array( 'G', 'PG-13', 'R-17' ), true );
}

add_filter( 'the_content', 'jetpack_videopress_flash_embed_filter', 7 ); // Needs to be priority 7 to allow Core to oEmbed.

if ( ! function_exists( 'wp_startswith' ) ) :
	/**
	 * Check whether a string starts with a specific substring.
	 *
	 * @param string $haystack String we are filtering.
	 * @param string $needle The substring we are looking for.
	 * @return bool
	 */
	function wp_startswith( $haystack, $needle ) {
		if ( ! $haystack || ! $needle || ! is_scalar( $haystack ) || ! is_scalar( $needle ) ) {
			return false;
		}

		$haystack = (string) $haystack;
		$needle   = (string) $needle;

		if ( function_exists( 'str_starts_with' ) ) { // remove when PHP 8.0 is the minimum supported.
			return str_starts_with( $haystack, $needle ); // phpcs:ignore PHPCompatibility.FunctionUse.NewFunctions
		}

		return 0 === strpos( $haystack, $needle );
	}
endif;
