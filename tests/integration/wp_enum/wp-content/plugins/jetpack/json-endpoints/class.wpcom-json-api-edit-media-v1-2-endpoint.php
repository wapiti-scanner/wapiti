<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.media.php';

define( 'REVISION_HISTORY_MAXIMUM_AMOUNT', 5 );
define( 'WP_ATTACHMENT_IMAGE_ALT', '_wp_attachment_image_alt' );

new WPCOM_JSON_API_Edit_Media_v1_2_Endpoint(
	array(
		'description'          => 'Edit a media item.',
		'group'                => 'media',
		'stat'                 => 'media:1:POST',
		'min_version'          => '1',
		'max_version'          => '1.2',
		'method'               => 'POST',
		'path'                 => '/sites/%s/media/%d/edit',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$media_ID' => '(int) The ID of the media item',
		),

		'request_format'       => array(
			'parent_id'   => '(int) ID of the post this media is attached to',
			'title'       => '(string) The file name.',
			'caption'     => '(string) File caption.',
			'description' => '(HTML) Description of the file.',
			'alt'         => '(string) Alternative text for image files.',
			'artist'      => '(string) Audio Only. Artist metadata for the audio track.',
			'album'       => '(string) Audio Only. Album metadata for the audio track.',
			'media'       => '(object) An object file to attach to the post. To upload media, ' .
							'the entire request should be multipart/form-data encoded. ' .
							'Multiple media items will be displayed in a gallery. Accepts ' .
							'jpg, jpeg, png, gif, pdf, doc, ppt, odt, pptx, docx, pps, ppsx, xls, xlsx, key. ' .
							'Audio and Video may also be available. See <code>allowed_file_types</code> ' .
							'in the options response of the site endpoint. ' .
							'<br /><br /><strong>Example</strong>:<br />' .
							"<code>curl \<br />--form 'title=Image' \<br />--form 'media=@/path/to/file.jpg' \<br />-H 'Authorization: BEARER your-token' \<br />'https://public-api.wordpress.com/rest/v1/sites/123/posts/new'</code>",
			'attrs'       => '(object) An Object of attributes (`title`, `description` and `caption`) ' .
							'are supported to assign to the media uploaded via the `media` or `media_url`',
			'media_url'   => '(string) An URL of the image to attach to a post.',
		),

		'response_format'      => array(
			'ID'                         => '(int) The ID of the media item',
			'date'                       => '(ISO 8601 datetime) The date the media was uploaded',
			'post_ID'                    => '(int) ID of the post this media is attached to',
			'author_ID'                  => '(int) ID of the user who uploaded the media',
			'URL'                        => '(string) URL to the file',
			'guid'                       => '(string) Unique identifier',
			'file'                       => '(string) File name',
			'extension'                  => '(string) File extension',
			'mime_type'                  => '(string) File mime type',
			'title'                      => '(string) File name',
			'caption'                    => '(string) User provided caption of the file',
			'description'                => '(string) Description of the file',
			'alt'                        => '(string)  Alternative text for image files.',
			'thumbnails'                 => '(object) Media item thumbnail URL options',
			'height'                     => '(int) (Image & video only) Height of the media item',
			'width'                      => '(int) (Image & video only) Width of the media item',
			'length'                     => '(int) (Video & audio only) Duration of the media item, in seconds',
			'exif'                       => '(array) (Image & audio only) Exif (meta) information about the media item',
			'videopress_guid'            => '(string) (Video only) VideoPress GUID of the video when uploaded on a blog with VideoPress',
			'videopress_processing_done' => '(bool) (Video only) If the video is uploaded on a blog with VideoPress, this will return the status of processing on the video.',
			'revision_history'           => '(object) An object with `items` and `original` keys. ' .
									'`original` is an object with data about the original image. ' .
									'`items` is an array of snapshots of the previous images of this Media. ' .
									'Each item has the `URL`, `file, `extension`, `date`, and `mime_type` fields.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1.2/sites/82974409/media/446',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'title' => 'Updated Title',
			),
		),
	)
);

/**
 * Edit media v1_2 endpoint class.
 */
class WPCOM_JSON_API_Edit_Media_v1_2_Endpoint extends WPCOM_JSON_API_Update_Media_v1_1_Endpoint { //phpcs:ignore
	/**
	 * Return an array of mime_type items allowed when the media file is uploaded.
	 *
	 * @param Array $default_mime_types - array of default mime types.
	 *
	 * @return {Array} mime_type array
	 */
	public static function get_allowed_mime_types( $default_mime_types ) {
		return array_unique(
			array_merge(
				$default_mime_types,
				array(
					'application/msword',                                                         // .doc
					'application/vnd.ms-powerpoint',                                              // .ppt, .pps
					'application/vnd.ms-excel',                                                   // .xls
					'application/vnd.openxmlformats-officedocument.presentationml.presentation',  // .pptx
					'application/vnd.openxmlformats-officedocument.presentationml.slideshow',     // .ppsx
					'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',          // .xlsx
					'application/vnd.openxmlformats-officedocument.wordprocessingml.document',    // .docx
					'application/vnd.oasis.opendocument.text',                                    // .odt
					'application/pdf',                                                            // .pdf
				)
			)
		);
	}

	/**
	 * Update the media post grabbing the post values from
	 * the `attrs` parameter
	 *
	 * @param  {Number} $media_id - post media ID.
	 * @param  {Object} $attrs - `attrs` parameter sent from the client in the request body.
	 */
	private function update_by_attrs_parameter( $media_id, $attrs ) {
		$insert = array();

		// Attributes: Title, Caption, Description.
		if ( isset( $attrs['title'] ) ) {
			$insert['post_title'] = $attrs['title'];
		}

		if ( isset( $attrs['caption'] ) ) {
			$insert['post_excerpt'] = $attrs['caption'];
		}

		if ( isset( $attrs['description'] ) ) {
			$insert['post_content'] = $attrs['description'];
		}

		if ( ! empty( $insert ) ) {
			$insert['ID']  = $media_id;
			$update_action = wp_update_post( (object) $insert );
			if ( is_wp_error( $update_action ) ) {
				return $update_action;
			}
		}

		// Attributes: Alt.
		if ( isset( $attrs['alt'] ) ) {
			$alt                = wp_strip_all_tags( $attrs['alt'], true );
			$post_update_action = update_post_meta( $media_id, WP_ATTACHMENT_IMAGE_ALT, $alt );

			if ( is_wp_error( $post_update_action ) ) {
				return $post_update_action;
			}
		}

		// Attributes: Artist, Album.
		$id3_meta = array();

		foreach ( array( 'artist', 'album' ) as $key ) {
			if ( isset( $attrs[ $key ] ) ) {
				$id3_meta[ $key ] = wp_strip_all_tags( $attrs[ $key ], true );
			}
		}

		if ( ! empty( $id3_meta ) ) {
			// Before updating metadata, ensure that the item is audio.
			$item = $this->get_media_item_v1_1( $media_id );
			if ( 0 === strpos( $item->mime_type, 'audio/' ) ) {
				$update_action = wp_update_attachment_metadata( $media_id, $id3_meta );
				if ( is_wp_error( $update_action ) ) {
					return $update_action;
				}
			}
		}

		return $post_update_action;
	}

	/**
	 * Return an object to be used to store into the revision_history
	 *
	 * @param  {Object} $media_item - media post object.
	 * @return {Object} the snapshot object
	 */
	private function get_snapshot( $media_item ) {
		$current_file = get_attached_file( $media_item->ID );
		$file_paths   = pathinfo( $current_file );

		$snapshot = array(
			'date'      => (string) $this->format_date( $media_item->post_modified_gmt, $media_item->post_modified ),
			'URL'       => (string) wp_get_attachment_url( $media_item->ID ),
			'file'      => (string) $file_paths['basename'],
			'extension' => (string) $file_paths['extension'],
			'mime_type' => (string) $media_item->post_mime_type,
			'size'      => (int) filesize( $current_file ),
		);

		return (object) $snapshot;
	}

	/**
	 * Try to remove the temporal file from the given file array.
	 *
	 * @param  {Array} $file_array - Array with data about the temporal file.
	 */
	private function remove_tmp_file( $file_array ) {
		if ( file_exists( $file_array['tmp_name'] ) ) {
			wp_delete_file( $file_array['tmp_name'] );
		}
	}

	/**
	 * Save the given temporal file in a local folder.
	 *
	 * @param  {Array}  $file_array - array containing file data.
	 * @param  {Number} $media_id - the media id.
	 * @return {Array|WP_Error} An array with information about the new file saved or a WP_Error is something went wrong.
	 */
	private function save_temporary_file( $file_array, $media_id ) {
		$tmp_filename = $file_array['tmp_name'];

		if ( ! file_exists( $tmp_filename ) ) {
			return new WP_Error( 'invalid_input', 'No media provided in input.' );
		}

		// add additional mime_types through of the `jetpack_supported_media_sideload_types` filter.
		$mime_type_static_filter = array(
			'WPCOM_JSON_API_Edit_Media_v1_2_Endpoint',
			'get_allowed_mime_types',
		);

		add_filter( 'jetpack_supported_media_sideload_types', $mime_type_static_filter );
		if (
			! $this->is_file_supported_for_sideloading( $tmp_filename ) &&
			! file_is_displayable_image( $tmp_filename )
		) {
			wp_delete_file( $tmp_filename );
			return new WP_Error( 'invalid_input', 'Invalid file type.', 403 );
		}
		remove_filter( 'jetpack_supported_media_sideload_types', $mime_type_static_filter );

		// generate a new file name.
		$tmp_new_filename = Jetpack_Media::generate_new_filename( $media_id, $file_array['name'] );

		// start to create the parameters to move the temporal file.
		$overrides = array( 'test_form' => false );

		$time = $this->get_time_string_from_guid( $media_id );

		$file_array['name'] = $tmp_new_filename;
		$file               = wp_handle_sideload( $file_array, $overrides, $time );

		$this->remove_tmp_file( $file_array );

		if ( isset( $file['error'] ) ) {
			return new WP_Error( 'upload_error', $file['error'] );
		}

		return $file;
	}

	/**
	 * File urls use the post date to generate a folder path.
	 * Post dates can change, so we use the original date used in the guid
	 * url so edits can remain in the same folder. In the following function
	 * we capture a string in the format of `YYYY/MM` from the guid.
	 *
	 * For example with a guid of
	 * "http://test.files.wordpress.com/2016/10/test.png" the resulting string
	 * would be: "2016/10"
	 *
	 * @param int $media_id - the media id.
	 *
	 * @return string
	 */
	private function get_time_string_from_guid( $media_id ) {
		// @todo: investigate if we can replace date with gmdate()
		// phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date
		$time  = date( 'Y/m', strtotime( current_time( 'mysql' ) ) );
		$media = get_post( $media_id );
		if ( $media ) {
			$pattern = '/\/(\d{4}\/\d{2})\//';
			preg_match( $pattern, $media->guid, $matches );
			if ( count( $matches ) > 1 ) {
				$time = $matches[1];
			}
		}
		return $time;
	}

	/**
	 * Get the image from a remote url and then save it locally.
	 *
	 * @param  {Number} $media_id - media post ID.
	 * @param  {String} $url - image URL to save locally.
	 * @return {Array|WP_Error} An array with information about the new file saved or a WP_Error is something went wrong.
	 */
	private function build_file_array_from_url( $media_id, $url ) {
		if ( ! $url ) {
			return null;
		}

		// if we didn't get a URL, let's bail.
		$parsed = wp_parse_url( $url );
		if ( empty( $parsed ) ) {
			return new WP_Error( 'invalid_url', 'No media provided in url.' );
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$url = wpcom_get_private_file( $url );
		}

		// save the remote image into a tmp file.
		$tmp = download_url( $url );
		if ( is_wp_error( $tmp ) ) {
			return $tmp;
		}

		return array(
			'name'     => basename( $url ),
			'tmp_name' => $tmp,
		);
	}

	/**
	 * Add a new item into revision_history array.
	 *
	 * @param  {Object}  $media_item         - media post.
	 * @param  {file}    $file               - file recentrly added.
	 * @param  {Boolean} $has_original_media - condition is the original media has been already added.
	 * @return {Boolean} `true` if the item has been added. Otherwise `false`.
	 */
	private function register_revision( $media_item, $file, $has_original_media ) {
		if (
			is_wp_error( $file ) ||
			! $has_original_media
		) {
			return false;
		}

		add_post_meta( $media_item->ID, Jetpack_Media::WP_REVISION_HISTORY, $this->get_snapshot( $media_item ) );
	}

	/**
	 * Restore the original media file.
	 *
	 * @param  {Number} $media_id       - media post ID.
	 * @param  {Object} $original_media - orginal media data.
	 * @return {Array}                  - restore media info.
	 */
	private function restore_original( $media_id, $original_media ) {
		$revisions = (array) Jetpack_Media::get_revision_history( $media_id );
		$revisions = array_filter(
			$revisions,
			function ( $revision ) use ( $original_media ) {
				return $revision->file !== $original_media->file;
			}
		);
		$criteria  = array(
			'from' => 0,
			'to'   => REVISION_HISTORY_MAXIMUM_AMOUNT,
		);

		Jetpack_Media::remove_items_from_revision_history( $media_id, $criteria, $revisions );
		$file           = get_attached_file( $media_id );
		$file_parts     = pathinfo( $file );
		$orginal_file   = path_join( $file_parts['dirname'], $original_media->file );
		$restored_media = array(
			'file' => $orginal_file,
			'type' => $original_media->mime_type,
		);

		return $restored_media;
	}

	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $media_id - the media ID.
	 */
	public function callback( $path = '', $blog_id = 0, $media_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$media_item = get_post( $media_id );

		if ( ! $media_item || is_wp_error( $media_item ) ) {
			return new WP_Error( 'unknown_media', 'Unknown Media', 404 );
		}

		if ( is_wp_error( $media_item ) ) {
			return $media_item;
		}

		if ( ! current_user_can( 'upload_files', $media_id ) ) {
			return new WP_Error( 'unauthorized', 'User cannot view media', 403 );
		}

		$input = $this->input( true );

		// Images.
		$media_file  = isset( $input['media'] ) ? (array) $input['media'] : null;
		$media_url   = isset( $input['media_url'] ) ? $input['media_url'] : null;
		$media_attrs = isset( $input['attrs'] ) ? (array) $input['attrs'] : null;

		if ( isset( $media_url ) || $media_file ) {
			$user_can_upload_files = current_user_can( 'upload_files' ) || $this->api->is_authorized_with_upload_token();

			if ( ! $user_can_upload_files ) {
				return new WP_Error( 'unauthorized', 'User cannot upload media.', 403 );
			}

			$has_original_media = Jetpack_Media::get_original_media( $media_id );

			if ( ! $has_original_media ) {
				// The first time that the media is updated
				// the original media is stored into the revision_history.
				$snapshot = $this->get_snapshot( $media_item );
				add_post_meta( $media_id, Jetpack_Media::WP_ORIGINAL_MEDIA, $snapshot, true );
			}

			// save the temporal file locally.
			$temporal_file = $media_file ? $media_file : $this->build_file_array_from_url( $media_id, $media_url );

			if ( is_wp_error( $temporal_file ) ) {
				return $temporal_file;
			}

			// edited media is sent as $media_file and restored media is sent as $media_url
			$should_restore = isset( $media_url ) && ! isset( $media_file ) && $has_original_media;

			$uploaded_file = $should_restore
				? $this->restore_original( $media_id, $has_original_media )
				: $this->save_temporary_file( $temporal_file, $media_id );

			if ( is_wp_error( $uploaded_file ) ) {
				return $uploaded_file;
			}

			// revision_history control.
			$this->register_revision( $media_item, $uploaded_file, $has_original_media );

			$uploaded_path     = $uploaded_file['file'];
			$udpated_mime_type = $uploaded_file['type'];
			$was_updated       = update_attached_file( $media_id, $uploaded_path );

			if ( $was_updated ) {
				$new_metadata = wp_generate_attachment_metadata( $media_id, $uploaded_path );
				wp_update_attachment_metadata( $media_id, $new_metadata );

				// check maximum amount of revision_history.
				Jetpack_Media::limit_revision_history( $media_id, REVISION_HISTORY_MAXIMUM_AMOUNT );

				wp_update_post(
					(object) array(
						'ID'             => $media_id,
						'post_mime_type' => $udpated_mime_type,
					)
				);
			}

			unset( $input['media'] );
			unset( $input['media_url'] );
			unset( $input['attrs'] );
		}

		// update media through of `attrs` value it it's defined.
		if ( ( $media_file || isset( $media_url ) ) && $media_attrs ) {
			$was_updated = $this->update_by_attrs_parameter( $media_id, $media_attrs );

			if ( is_wp_error( $was_updated ) ) {
				return $was_updated;
			}
		}

		// call parent method.
		$response = parent::callback( $path, $blog_id, $media_id );

		// expose `revision_history` object.
		$response->revision_history = (object) array(
			'items'    => (array) Jetpack_Media::get_revision_history( $media_id ),
			'original' => (object) Jetpack_Media::get_original_media( $media_id ),
		);

		return $response;
	}
}
