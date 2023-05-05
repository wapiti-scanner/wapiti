<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * VideoPress video object retrieved from VideoPress servers and parsed.
 *
 * @since 1.3
 */
class VideoPress_Video {
	/**
	 * VideoPress version.
	 *
	 * @var int
	 */
	public $version = 3;

	/**
	 * Manifest version returned by remote service.
	 *
	 * @var string
	 * @since 1.3
	 */
	const manifest_version = '1.5'; // phpcs:ignore Generic.NamingConventions.UpperCaseConstantName.ClassConstantNotUpperCase

	/**
	 * Expiration of the video expressed in Unix time
	 *
	 * @var int
	 * @since 1.3
	 */
	public $expires;

	/**
	 * VideoPress unique identifier
	 *
	 * @var string
	 * @since 1.3
	 */
	public $guid;

	/**
	 * WordPress.com blog identifier
	 *
	 * @var int
	 * @since 1.5
	 */
	public $blog_id;

	/**
	 * Remote blog attachment identifier
	 *
	 * @var int
	 * @since 1.5
	 */
	public $post_id;

	/**
	 * Maximum desired width.
	 *
	 * @var int
	 * @since 1.3
	 */
	public $maxwidth;

	/**
	 * Video width calculated based on original video dimensions and the requested maxwidth
	 *
	 * @var int
	 * @since 1.3
	 */
	public $calculated_width;

	/**
	 * Video height calculated based on original video dimensions and the requested maxwidth
	 *
	 * @var int
	 * @since 1.3
	 */
	public $calculated_height;

	/**
	 * Video title
	 *
	 * @var string
	 * @since 1.3
	 */
	public $title;

	/**
	 * Video description
	 *
	 * @var string
	 * @since 4.4
	 */
	public $description;

	/**
	 * Directionality of title text. ltr or rtl
	 *
	 * @var string
	 * @since 1.3
	 */
	public $text_direction;

	/**
	 * Text and audio language as ISO 639-2 language code
	 *
	 * @var string
	 * @since 1.3
	 */
	public $language;

	/**
	 * Video duration in whole seconds
	 *
	 * @var int
	 * @since 1.3
	 */
	public $duration;

	/**
	 * Recommended minimum age of the viewer.
	 *
	 * @var int
	 * @since 1.3
	 */
	public $age_rating;

	/**
	 * Video author has restricted video embedding or sharing
	 *
	 * @var bool
	 * @since 1.3
	 */
	public $restricted_embed;

	/**
	 * Poster frame image URI for the given video guid and calculated dimensions.
	 *
	 * @var string
	 * @since 1.3
	 */
	public $poster_frame_uri;

	/**
	 * Video files associated with the given guid for the calculated dimensions.
	 *
	 * @var stdClass
	 * @since 1.3
	 */
	public $videos;

	/**
	 * Video player information
	 *
	 * @var stdClass
	 * @since 1.3
	 */
	public $players;

	/**
	 * Video player skinning preferences including background color and watermark
	 *
	 * @var array
	 * @since 1.5
	 */
	public $skin;

	/**
	 * Closed captions if available for the given video. Associative array of ISO 639-2 language code and a WebVTT URI
	 *
	 * @var array
	 * @since 1.5
	 */
	public $captions;

	/**
	 * Setup the object.
	 * Request video information from VideoPress servers and process the response.
	 *
	 * @since 1.3
	 * @param string $guid VideoPress unique identifier.
	 * @param int    $maxwidth maximum requested video width. final width and height are calculated on VideoPress servers based on the aspect ratio of the original video upload.
	 */
	public function __construct( $guid, $maxwidth = 640 ) {
		$this->guid = $guid;

		$maxwidth = absint( $maxwidth );
		if ( $maxwidth > 0 ) {
			$this->maxwidth = $maxwidth;
		}

		$data = $this->get_data();
		if ( is_wp_error( $data ) || empty( $data ) ) {
			/** This filter is documented in modules/videopress/class.videopress-player.php */
			if ( ! apply_filters( 'jetpack_videopress_use_legacy_player', false ) ) {
				// Unlike the Flash player, the new player does it's own error checking, age gate, etc.
				$data = (object) array(
					'guid'   => $guid,
					'width'  => $maxwidth,
					'height' => $maxwidth / 16 * 9,
				);
			} else {
				$this->error = $data;
				return;
			}
		}

		if ( isset( $data->blog_id ) ) {
			$this->blog_id = absint( $data->blog_id );
		}

		if ( isset( $data->post_id ) ) {
			$this->post_id = absint( $data->post_id );
		}

		if ( isset( $data->title ) && $data->title !== '' ) {
			$this->title = trim( str_replace( '&nbsp;', ' ', $data->title ) );
		}

		if ( isset( $data->description ) && $data->description !== '' ) {
			$this->description = trim( $data->description );
		}

		if ( isset( $data->text_direction ) && $data->text_direction === 'rtl' ) {
			$this->text_direction = 'rtl';
		} else {
			$this->text_direction = 'ltr';
		}

		if ( isset( $data->language ) ) {
			$this->language = $data->language;
		}

		if ( isset( $data->duration ) && $data->duration > 0 ) {
			$this->duration = absint( $data->duration );
		}

		if ( isset( $data->width ) && $data->width > 0 ) {
			$this->calculated_width = absint( $data->width );
		}

		if ( isset( $data->height ) && $data->height > 0 ) {
			$this->calculated_height = absint( $data->height );
		}

		if ( isset( $data->age_rating ) ) {
			$this->age_rating = absint( $this->age_rating );
		}

		if ( isset( $data->restricted_embed ) && $data->restricted_embed === true ) {
			$this->restricted_embed = true;
		} else {
			$this->restricted_embed = false;
		}

		if ( isset( $data->posterframe ) && $data->posterframe !== '' ) {
			$this->poster_frame_uri = esc_url_raw( $data->posterframe, array( 'http', 'https' ) );
		}

		if ( isset( $data->mp4 ) || isset( $data->ogv ) ) {
			$this->videos = new stdClass();
			if ( isset( $data->mp4 ) ) {
				$this->videos->mp4 = $data->mp4;
			}
			if ( isset( $data->ogv ) ) {
				$this->videos->ogv = $data->ogv;
			}
		}

		if ( isset( $data->swf ) ) {
			if ( ! isset( $this->players ) ) {
				$this->players = new stdClass();
			}
			$this->players->swf = $data->swf;
		}

		if ( isset( $data->skin ) ) {
			$this->skin = $data->skin;
		}

		if ( isset( $data->captions ) ) {
			$this->captions = (array) $data->captions;
		}
	}

	/**
	 * Convert an Expires HTTP header value into Unix time for use in WP Cache.
	 *
	 * @since 1.3
	 * @param string $expires_header Expires header value.
	 * @return int|bool Unix time or false
	 */
	public static function calculate_expiration( $expires_header ) {
		if ( empty( $expires_header ) || ! is_string( $expires_header ) ) {
			return false;
		}

		$expires_date = DateTime::createFromFormat( 'D, d M Y H:i:s T', $expires_header, new DateTimeZone( 'UTC' ) );
		if ( $expires_date instanceof DateTime ) {
			return date_format( $expires_date, 'U' );
		}
		return false;
	}

	/**
	 * Extract the site's host domain for statistics and comparison against an allowed site list in the case of restricted embeds.
	 *
	 * @since 1.2
	 * @param string $url absolute URL.
	 * @return bool|string host component of the URL, or false if none found.
	 */
	public static function hostname( $url ) {
		return wp_parse_url( esc_url_raw( $url ), PHP_URL_HOST );
	}

	/**
	 * Request data from WordPress.com for the given guid, maxwidth, and calculated blog hostname.
	 *
	 * @since 1.3
	 * @return stdClass|WP_Error parsed JSON response or WP_Error if request unsuccessful
	 */
	private function get_data() {
		global $wp_version;

		$domain         = self::hostname( home_url() );
		$request_params = array(
			'guid'   => $this->guid,
			'domain' => $domain,
		);
		if ( isset( $this->maxwidth ) && $this->maxwidth > 0 ) {
			$request_params['maxwidth'] = $this->maxwidth;
		}

		$url = 'https://v.wordpress.com/data/wordpress.json';

		$response = wp_remote_get(
			add_query_arg( $request_params, $url ),
			array(
				'redirection' => 1,
				'user-agent'  => 'VideoPress plugin ' . $this->version . '; WordPress ' . $wp_version . ' (' . home_url( '/' ) . ')',
			)
		);

		unset( $request_params );
		unset( $url );
		$response_body = wp_remote_retrieve_body( $response );
		$response_code = absint( wp_remote_retrieve_response_code( $response ) );

		if ( is_wp_error( $response ) ) {
			return $response;
		} elseif ( $response_code === 400 ) {
			return new WP_Error( 'bad_config', __( 'The VideoPress plugin could not communicate with the VideoPress servers. This error is most likely caused by a misconfigured plugin. Please reinstall or upgrade.', 'jetpack' ) );
		} elseif ( $response_code === 403 ) {
			/* translators: %s URL of site trying to embed a VideoPress video */
			return new WP_Error( 'http_forbidden', '<p>' . sprintf( __( '<strong>%s</strong> is not an allowed embed site.', 'jetpack' ), esc_html( $domain ) ) . '</p><p>' . __( 'Publisher limits playback of video embeds.', 'jetpack' ) . '</p>' );
		} elseif ( $response_code === 404 ) {
			/* translators: %s VideoPress object identifier */
			return new WP_Error( 'http_not_found', '<p>' . sprintf( __( 'No data found for VideoPress identifier: <strong>%s</strong>.', 'jetpack' ), $this->guid ) . '</p>' );
		} elseif ( $response_code !== 200 || empty( $response_body ) ) {
			return;
		} else {
			$expires_header = wp_remote_retrieve_header( $response, 'Expires' );
			if ( ! empty( $expires_header ) ) {
				$expires = self::calculate_expiration( $expires_header );
				if ( ! empty( $expires ) ) {
					$this->expires = $expires;
				}
			}
			return json_decode( $response_body );
		}
	}
}
