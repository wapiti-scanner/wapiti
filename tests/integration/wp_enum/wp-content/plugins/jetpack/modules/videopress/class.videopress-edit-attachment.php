<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Connection\Client;

/**
 * VideoPress edit attachment screen
 *
 * @since 4.1
 */
class VideoPress_Edit_Attachment {

	/**
	 * Singleton method to initialize the object only once.
	 *
	 * @return VideoPress_Edit_Attachment
	 */
	public static function init() {
		static $instance = null;

		if ( ! $instance ) {
			$instance = new VideoPress_Edit_Attachment();
		}

		return $instance;
	}

	/**
	 * VideoPress_Edit_Attachment constructor.
	 *
	 * Adds in appropriate actions for attachment fields editor, meta boxes and saving.
	 */
	public function __construct() {
		add_filter( 'attachment_fields_to_edit', array( $this, 'fields_to_edit' ), 10, 2 );
		add_filter( 'attachment_fields_to_save', array( $this, 'save_fields' ), 10, 2 );
		add_filter( 'wp_ajax_save-attachment', array( $this, 'save_fields' ), -1 );
		add_filter( 'wp_ajax_save-attachment-compat', array( $this, 'save_fields' ), -1 );

		add_action( 'add_meta_boxes', array( $this, 'configure_meta_boxes' ), 10, 2 );
	}

	/**
	 * Add VideoPress meta box.
	 *
	 * @param string $post_type Post type.
	 * @param object $post Post object.
	 */
	public function configure_meta_boxes( $post_type = 'unknown', $post = null ) {
		if ( null === $post ) {
			$post = (object) array( 'ID' => 0 );
		}

		if ( 'attachment' !== $post_type ) {
			return;
		}

		// If this has not been processed by videopress, we can skip the rest.
		if ( ! is_videopress_attachment( $post->ID ) ) {
			return;
		}

		add_meta_box( 'videopress-media-info', __( 'VideoPress Information', 'jetpack' ), array( $this, 'videopress_information_box' ), 'attachment', 'side', 'core' );
	}

	/**
	 * Filter attachment fields data to save.
	 *
	 * @param array      $post Post data.
	 * @param array|null $attachment Attachment metadata.
	 *
	 * @return array
	 */
	public function save_fields( $post, $attachment = null ) {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verification already done by core.
		if ( null === $attachment && isset( $_POST['attachment'] ) ) {
			$attachment = filter_var( wp_unslash( $_POST['attachment'] ) );
		}

		if ( ! isset( $attachment['is_videopress_attachment'] ) || 'yes' !== $attachment['is_videopress_attachment'] ) {
			return $post;
		}

		// If this has not been processed by videopress, we can skip the rest.
		if ( ! is_videopress_attachment( $post['ID'] ) ) {
			$post['errors']['videopress']['errors'][] = __( 'The media you are trying to update is not processed by VideoPress.', 'jetpack' );
			return $post;
		}

		$post_title      = isset( $_POST['post_title'] ) ? sanitize_text_field( wp_unslash( $_POST['post_title'] ) ) : null;
		$post_excerpt    = isset( $_POST['post_excerpt'] ) ? sanitize_textarea_field( wp_unslash( $_POST['post_excerpt'] ) ) : null;
		$rating          = isset( $attachment['rating'] ) ? $attachment['rating'] : null;
		$display_embed   = isset( $attachment['display_embed'] ) ? $attachment['display_embed'] : 0;
		$allow_download  = isset( $attachment['allow_download'] ) ? $attachment['allow_download'] : 0;
		$privacy_setting = isset( $attachment['privacy_setting'] ) ? $attachment['privacy_setting'] : VIDEOPRESS_PRIVACY::SITE_DEFAULT;

		$result = Videopress_Attachment_Metadata::persist_metadata(
			$post['ID'],
			get_post_meta( $post['ID'], 'videopress_guid', true ),
			$post_title,
			null, // @todo: Check why we haven't sent the caption in the first place.
			$post_excerpt,
			$rating,
			$this->normalize_checkbox_value( $display_embed ),
			$this->normalize_checkbox_value( $allow_download ),
			$privacy_setting
		);

		if ( is_wp_error( $result ) ) {
			$post['errors']['videopress']['errors'][] = $result->get_error_message();
			return $post;
		}

		return $post;
		// phpcs:enable WordPress.Security.NonceVerification.Missing
	}

	/**
	 * Convert the string values of a checkbox option to the format that they will be stored in db.
	 *
	 * @param string $value The denormalized version.
	 *
	 * @return int
	 */
	private function normalize_checkbox_value( $value ) {
		return 'on' === $value ? 1 : 0;
	}

	/**
	 * Get the upload api path.
	 *
	 * @param string $guid The guid of the video.
	 * @return string
	 */
	public function make_video_api_path( $guid ) {
		return sprintf(
			'%s/rest/v%s/videos/%s',
			JETPACK__WPCOM_JSON_API_BASE,
			Client::WPCOM_JSON_API_VERSION,
			$guid
		);
	}

	/**
	 * Creates an array of video fields to edit based on transcoded videos.
	 *
	 * @param array    $fields video fields of interest.
	 * @param stdClass $post Post object.
	 * @return array modified version of video fields for administrative interface display
	 */
	public function fields_to_edit( $fields, $post ) {
		$post_id = absint( $post->ID );

		$meta = wp_get_attachment_metadata( $post_id );

		// If this has not been processed by videopress, we can skip the rest.
		if ( ! is_videopress_attachment( $post_id ) || ! isset( $meta['videopress'] ) ) {
			return $fields;
		}

		$info          = (object) $meta['videopress'];
		$file_statuses = isset( $meta['file_statuses'] ) ? $meta['file_statuses'] : array();

		$guid = get_post_meta( $post_id, 'videopress_guid', true );

		unset( $fields['url'] );
		unset( $fields['post_content'] );

		// If a video isn't attached to any specific post, manually add a post ID.
		if ( ! isset( $info->post_id ) ) {
			$info->post_id = 0;
		}

		if ( isset( $file_statuses['ogg'] ) && 'done' === $file_statuses['ogg'] ) {
			$v_name     = preg_replace( '/\.\w+/', '', basename( $info->path ) );
			$video_name = $v_name . '_fmt1.ogv';
			$ogg_url    = videopress_cdn_file_url( $guid, $video_name );

			$fields['video-ogg'] = array(
				'label' => __( 'Ogg File URL', 'jetpack' ),
				'input' => 'html',
				'html'  => "<input type='text' class='urlfield' readonly='readonly' name='attachments[$post_id][oggurl]' value='" . esc_url( $ogg_url, array( 'http', 'https' ) ) . "' />",
				'helps' => __( 'Location of the Ogg video file.', 'jetpack' ),
			);
		}

		$fields['post_title']['helps'] = __( 'Title will appear on the first frame of your video', 'jetpack' );

		$fields['post_excerpt']['label'] = _x( 'Description', 'A header for the short description display', 'jetpack' );
		$fields['post_excerpt']['input'] = 'textarea';
		$fields['post_excerpt']['value'] = ! empty( $info->description ) ? $info->description : '';

		$fields['is_videopress_attachment'] = array(
			'input' => 'hidden',
			'value' => 'yes',
		);

		$fields['videopress_shortcode'] = array(
			'label'         => _x( 'Shortcode', 'A header for the shortcode display', 'jetpack' ),
			'input'         => 'html',
			'html'          => "<input type=\"text\" name=\"videopress_shortcode\" value=\"[videopress {$guid}]\" readonly=\"readonly\"/>",
			'show_in_modal' => true,
			'show_in_edit'  => false,
		);

		$fields['display_embed'] = array(
			'label' => _x( 'Share', 'A header for the video sharing options area', 'jetpack' ),
			'input' => 'html',
			'html'  => $this->display_embed_choice( $info ),
		);

		$fields['allow_download'] = array(
			'label' => _x( 'Download', 'A header for the video allow download option area', 'jetpack' ),
			'input' => 'html',
			'html'  => $this->display_download_choice( $info ),
		);

		$fields['video-rating'] = array(
			'label' => _x( 'Rating', 'A header for the video rating area', 'jetpack' ),
			'input' => 'html',
			'html'  => $this->display_rating( $info ),
		);

		$fields['privacy_setting'] = array(
			'label' => _x( 'Privacy Setting', 'A header for the video privacy setting area.', 'jetpack' ),
			'input' => 'html',
			'html'  => $this->display_privacy_setting( $info ),
		);

		return $fields;
	}

	/**
	 * Meta box output.
	 *
	 * @param stdClass $post Post object.
	 */
	public function videopress_information_box( $post ) {
		$post_id = absint( $post->ID );

		$meta = wp_get_attachment_metadata( $post_id );
		$guid = get_post_meta( $post_id, 'videopress_guid', true );

		// If this has not been processed by videopress, we can skip the rest.
		if ( ! is_videopress_attachment( $post_id ) ) {
			return;
		}

		$info = (object) $meta['videopress'];

		$embed = "[videopress {$guid}]";

		$shortcode = '<input type="text" id="plugin-embed" readonly="readonly" style="width:180px;" value="' . esc_attr( $embed ) . '" onclick="this.focus();this.select();" />';

		$url = 'empty';
		if ( ! empty( $guid ) ) {
			$url = videopress_build_url( $guid );
			$url = "<a href=\"{$url}\">{$url}</a>";
		}

		$poster = '<em>Still Processing</em>';
		if ( ! empty( $info->poster ) ) {
			$poster = "<br><img src=\"{$info->poster}\" width=\"175px\">";
		}

		$html = <<< HTML

<div class="misc-pub-section misc-pub-shortcode">
	<strong>Shortcode</strong><br>
	{$shortcode}
</div>
<div class="misc-pub-section misc-pub-url">
	<strong>Url</strong>
	{$url}
</div>
<div class="misc-pub-section misc-pub-poster">
	<strong>Poster</strong>
	{$poster}
</div>
HTML;

		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Variables built above.
	}

	/**
	 * Creates a checkbox and a label for a video option.
	 *
	 * @param string $id the checkbox id.
	 * @param string $name the checkbox name.
	 * @param string $label the label text.
	 * @param bool   $is_checked if the checkbox should be checked.
	 *
	 * @return string the generated HTML
	 */
	protected function create_checkbox_for_option( $id, $name, $label, $is_checked ) {
		$html = "<label for='$id'><input type='checkbox' name='$name' id='$id'";
		if ( $is_checked ) {
			$html .= ' checked="checked"';
		}
		$html .= " />$label</label>";
		return $html;
	}

	/**
	 * Build HTML to display a form checkbox for embedcode display preference
	 *
	 * @param object $info Database row from the videos table.
	 * @return string Input element of type checkbox set to checked state based on stored embed preference.
	 */
	protected function display_embed_choice( $info ) {
		return $this->create_checkbox_for_option(
			"attachments-{$info->post_id}-displayembed",
			"attachments[{$info->post_id}][display_embed]",
			__( 'Display share menu and allow viewers to copy a link or embed this video', 'jetpack' ),
			isset( $info->display_embed ) ? $info->display_embed : 0
		);
	}

	/**
	 * Build HTML to display a form checkbox for the "allow download" video option
	 *
	 * @param object $info database row from the videos table.
	 * @return string input element of type checkbox with checked state matching the download preference
	 */
	protected function display_download_choice( $info ) {
		return $this->create_checkbox_for_option(
			"attachments-{$info->post_id}-allowdownload",
			"attachments[{$info->post_id}][allow_download]",
			__( 'Display download option and allow viewers to download this video', 'jetpack' ),
			isset( $info->allow_download ) && $info->allow_download
		);
	}

	/**
	 * Build HTML to display a form input radio button for video ratings
	 *
	 * @param object $info Database row from the videos table.
	 *
	 * @return string Input Elements of type radio with existing stored value selected.
	 */
	protected function display_privacy_setting( $info ) {
		$privacy_settings = array(
			VIDEOPRESS_PRIVACY::SITE_DEFAULT => __( 'Site Default', 'jetpack' ),
			VIDEOPRESS_PRIVACY::IS_PUBLIC    => __( 'Public', 'jetpack' ),
			VIDEOPRESS_PRIVACY::IS_PRIVATE   => __( 'Private', 'jetpack' ),
		);

		$displayed_privacy_setting = intval( isset( $info->privacy_setting ) ? $info->privacy_setting : VIDEOPRESS_PRIVACY::SITE_DEFAULT );

		$out = "<select name='attachments[{$info->post_id}][privacy_setting]'>";
		foreach ( $privacy_settings as $r => $label ) {
			$out .= "<option value=\"$r\"";
			if ( intval( $r ) === $displayed_privacy_setting ) {
				$out .= ' selected';
			}

			$out .= ">$label</option>";
		}

		$out .= '</select>';

		return $out;
	}

	/**
	 * Build HTML to display a form input radio button for video ratings
	 *
	 * @param object $info Database row from the videos table.
	 * @return string Input elements of type radio with existing stored value selected.
	 */
	protected function display_rating( $info ) {
		$out = '';

		$ratings = array(
			'G'     => 'G',
			'PG-13' => 'PG-13',
			'R-17'  => 'R',
		);

		$displayed_rating = isset( $info->rating ) ? $info->rating : null;

		// X-18 was previously supported but is now removed to better comply with our TOS.
		if ( 'X-18' === $displayed_rating ) {
			$displayed_rating = 'R-17';
		}

		foreach ( $ratings as $r => $label ) {
			$id   = "attachments-{$info->post_id}-rating-$r";
			$out .= "<label for=\"$id\"><input type=\"radio\" name=\"attachments[{$info->post_id}][rating]\" id=\"$id\" value=\"$r\"";
			if ( $displayed_rating === $r ) {
				$out .= ' checked="checked"';
			}

			$out .= " />$label</label>";
			unset( $id );
		}

		return $out;
	}
}

// Let's start this thing up.
VideoPress_Edit_Attachment::init();
