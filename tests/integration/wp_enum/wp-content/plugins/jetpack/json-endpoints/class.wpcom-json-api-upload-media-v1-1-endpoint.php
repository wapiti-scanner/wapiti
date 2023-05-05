<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Upload media item API endpoint v1.1
 *
 * Endpoint: /sites/%s/media/new
 */

new WPCOM_JSON_API_Upload_Media_v1_1_Endpoint(
	array(
		'description'                => 'Upload a new piece of media.',
		'allow_cross_origin_request' => true,
		'allow_upload_token_auth'    => true,
		'group'                      => 'media',
		'stat'                       => 'media:new',
		'min_version'                => '1.1',
		'max_version'                => '1.1',
		'method'                     => 'POST',
		'path'                       => '/sites/%s/media/new',
		'path_labels'                => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'request_format'             => array(
			'media'      => '(media) An array of media to attach to the post. To upload media, the entire request should be multipart/form-data encoded. Accepts  jpg, jpeg, png, gif, pdf, doc, ppt, odt, pptx, docx, pps, ppsx, xls, xlsx, key. Audio and Video may also be available. See <code>allowed_file_types</code> in the options response of the site endpoint.<br /><br /><strong>Example</strong>:<br />' .
							"<code>curl \<br />--form 'media[]=@/path/to/file.jpg' \<br />-H 'Authorization: BEARER your-token' \<br />'https://public-api.wordpress.com/rest/v1/sites/123/media/new'</code>",
			'media_urls' => '(array) An array of URLs to upload to the post. Errors produced by media uploads, if any, will be in `media_errors` in the response.',
			'attrs'      => '(array) An array of attributes (`title`, `description`, `caption` `alt` for images, `artist` for audio, `album` for audio, and `parent_id`) are supported to assign to the media uploaded via the `media` or `media_urls` properties. You must use a numeric index for the keys of `attrs` which follows the same sequence as `media` and `media_urls`. <br /><br /><strong>Example</strong>:<br />' .
							"<code>curl \<br />--form 'media[]=@/path/to/file1.jpg' \<br />--form 'media_urls[]=http://example.com/file2.jpg' \<br /> \<br />--form 'attrs[0][caption]=This will be the caption for file1.jpg' \<br />--form 'attrs[1][title]=This will be the title for file2.jpg' \<br />-H 'Authorization: BEARER your-token' \<br />'https://public-api.wordpress.com/rest/v1/sites/123/posts/new'</code>",
		),

		'response_format'            => array(
			'media'  => '(array) Array of uploaded media objects',
			'errors' => '(array) Array of error messages of uploading media failures',
		),

		'example_request'            => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/media/new',
		'example_request_data'       => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'media_urls' => 'https://s.w.org/about/images/logos/codeispoetry-rgb.png',
			),
		),
	)
);

// phpcs:disable PEAR.NamingConventions.ValidClassName.Invalid
/**
 * Upload media item API class v1.1
 */
class WPCOM_JSON_API_Upload_Media_v1_1_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * Upload media item API endpoint callback v1.1
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 *
	 * @return array|int|WP_Error|void
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( ! current_user_can( 'upload_files' ) && ! $this->api->is_authorized_with_upload_token() ) {
			return new WP_Error( 'unauthorized', 'User cannot upload media.', 403 );
		}

		$input = $this->input( true );

		$media_files = ! empty( $input['media'] ) ? $input['media'] : array();
		$media_urls  = ! empty( $input['media_urls'] ) ? $input['media_urls'] : array();
		$media_attrs = ! empty( $input['attrs'] ) ? $input['attrs'] : array();

		if ( empty( $media_files ) && empty( $media_urls ) ) {
			return new WP_Error( 'invalid_input', 'No media provided in input.' );
		}

		$is_jetpack_site = false;
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// For jetpack sites, we send the media via a different method, because the sync is very different.
			$jetpack_sync    = Jetpack_Media_Sync::summon( $blog_id );
			$is_jetpack_site = $jetpack_sync->is_jetpack_site();
		}

		$jetpack_media_files = array();
		$other_media_files   = array();
		$media_items         = array();
		$errors              = array();

		// We're splitting out videos for Jetpack sites.
		foreach ( $media_files as $media_item ) {
			if ( preg_match( '@^video/@', $media_item['type'] ) && $is_jetpack_site ) {
				if ( defined( 'IS_WPCOM' ) && IS_WPCOM &&
					defined( 'VIDEOPRESS_JETPACK_VIDEO_ENABLED' ) && VIDEOPRESS_JETPACK_VIDEO_ENABLED
				) {
					// Check that video upload space is available for a Jetpack site (skipped if site is Atomic).
					$result = videopress_check_space_available_for_jetpack( $blog_id, $media_item['name'], $media_item['size'] );

					if ( true !== $result ) {
						$this->api->output_early( 400, array( 'errors' => $this->rewrite_generic_upload_error( array( $result ) ) ) );
					}
				}
				$jetpack_media_files[] = $media_item;

			} else {
				$other_media_files[] = $media_item;
			}
		}

		// New Jetpack / VideoPress media upload processing.
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			if ( count( $jetpack_media_files ) > 0 ) {
				add_filter( 'upload_mimes', array( $this, 'allow_video_uploads' ) );

				// get_space_used() checks blog upload directory storage,
				// so filter it temporarily to return only video storage used.
				add_filter( 'pre_get_space_used', 'videopress_filter_jetpack_get_space_used' );

				$media_items = $jetpack_sync->upload_media( $jetpack_media_files, $this->api );

				$errors = $jetpack_sync->get_errors();

				foreach ( $media_items as & $media_item ) {
					// More than likely a post has not been created yet, so we pass in the media item we
					// got back from the Jetpack site.
					$post       = (object) $media_item['post'];
					$media_item = $this->get_media_item_v1_1( $post->ID, $post, $media_item['file'] );
				}
				// Remove get_space_used filter after upload.
				remove_filter( 'pre_get_space_used', 'videopress_filter_jetpack_get_space_used' );
			}
		}

		// Normal WPCOM upload processing.
		if ( count( $other_media_files ) > 0 || count( $media_urls ) > 0 ) {
			if ( is_multisite() ) { // Do not check for available space in non multisites.
				add_filter( 'wp_handle_upload_prefilter', array( $this, 'check_upload_size' ), 9 ); // used for direct media uploads.
				add_filter( 'wp_handle_sideload_prefilter', array( $this, 'check_upload_size' ), 9 ); // used for uploading media via url.
			}

			if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
				require_lib( 'tos-acceptance-tracking' );
				add_filter( 'wp_handle_upload_prefilter', '\\A8C\\TOS_Acceptance_Tracking\\handle_uploads_wpcomtos_blog' );
			}

			$create_media = $this->handle_media_creation_v1_1( $other_media_files, $media_urls, $media_attrs );
			$media_ids    = $create_media['media_ids'];
			$errors       = $create_media['errors'];

			$media_items = array();
			foreach ( $media_ids as $media_id ) {
				$media_items[] = $this->get_media_item_v1_1( $media_id );
			}
		}

		if ( count( $media_items ) <= 0 ) {
			return $this->api->output_early( 400, array( 'errors' => $this->rewrite_generic_upload_error( $errors ) ) );
		}

		$results = array();
		foreach ( $media_items as $media_item ) {
			if ( is_wp_error( $media_item ) ) {
				$errors[] = array(
					'file'    => $media_item['ID'],
					'error'   => $media_item->get_error_code(),
					'message' => $media_item->get_error_message(),
				);

			} else {
				$results[] = $media_item;
			}
		}

		$response = array( 'media' => $results );

		if ( count( $errors ) > 0 ) {
			$response['errors'] = $this->rewrite_generic_upload_error( $errors );
		}

		return $response;
	}

	/**
	 * This changes the generic "upload_error" code to something more meaningful if possible
	 *
	 * @param  array $errors Errors for the uploaded file.
	 * @return array         The same array with an improved error message.
	 */
	public function rewrite_generic_upload_error( $errors ) {
		foreach ( $errors as $k => $error ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			if ( 'upload_error' === $error['error'] && false !== strpos( $error['message'], '|' ) ) {
				list( $errors[ $k ]['error'], $errors[ $k ]['message'] ) = explode( '|', $error['message'], 2 ); // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			}
		}
		return $errors;
	}

	/**
	 * Determine if uploaded file exceeds space quota on multisite.
	 *
	 * This is a copy of the core function with added functionality, synced
	 * with this with WP_REST_Attachments_Controller::check_upload_size()
	 * to allow for specifying a better error message.
	 *
	 * @param array $file $_FILES array for a given file.
	 * @return array Maybe extended with an error message.
	 */
	public function check_upload_size( $file ) {
		if ( get_site_option( 'upload_space_check_disabled' ) ) {
			return $file;
		}

		if ( isset( $file['error'] ) && $file['error'] > 0 ) { // There's already an error. Error Codes Reference: https://www.php.net/manual/en/features.file-upload.errors.php .
			return $file;
		}

		if ( defined( 'WP_IMPORTING' ) ) {
			return $file;
		}

		$space_left = get_upload_space_available();

		$file_size = filesize( $file['tmp_name'] );
		if ( $space_left < $file_size ) {
			/* translators: %s: Required disk space in kilobytes. */
			$file['error'] = 'rest_upload_limited_space|' . sprintf( __( 'Not enough space to upload. %s KB needed.', 'default' ), number_format( ( $file_size - $space_left ) / KB_IN_BYTES ) ); // phpcs:ignore WordPress.WP.I18n.TextDomainMismatch
		}

		$max_upload_size = KB_IN_BYTES * get_site_option( 'fileupload_maxk', 1500 );
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM && defined( 'WPCOM_MAX_UPLOAD_FILE_SIZE' ) ) {
			$max_upload_size = WPCOM_MAX_UPLOAD_FILE_SIZE;
		}

		if ( $file_size > $max_upload_size ) {
			/* translators: %s: Maximum allowed file size in kilobytes. */
			$file['error'] = 'rest_upload_file_too_big|' . sprintf( __( 'This file is too big. Files must be less than %s KB in size.', 'jetpack' ), $max_upload_size / KB_IN_BYTES );
		}

		if ( upload_is_user_over_quota( false ) ) {
			$file['error'] = 'rest_upload_user_quota_exceeded|' . __( 'You have used your space quota. Please delete files before uploading.', 'default' ); // phpcs:ignore WordPress.WP.I18n.TextDomainMismatch
		}

		return $file;
	}
	/**
	 * Force to use the WPCOM API instead of proxy back to the Jetpack API if the blog is a paid Jetpack
	 * blog w/ the VideoPress module enabled AND the uploaded file is a video.
	 *
	 * @param int $blog_id Blog ID.
	 * @return bool
	 */
	public function force_wpcom_request( $blog_id ) {

		// We don't need to do anything if VideoPress is not enabled for the blog.
		if ( ! is_videopress_enabled_on_jetpack_blog( $blog_id ) ) {
			return false;
		}

		// Check to see if the upload is not a video type, if not then return false.
		$input       = $this->input( true );
		$media_files = ! empty( $input['media'] ) ? $input['media'] : array();

		if ( empty( $media_files ) ) {
			return false;
		}

		foreach ( $media_files as $media_item ) {
			if ( ! preg_match( '@^video/@', $media_item['type'] ) ) {
				return false;
			}
		}

		// The API request should be for a blog w/ Jetpack, A valid plan, has VideoPress enabled,
		// and is a video file. Let's let it through.
		return true;
	}
}
