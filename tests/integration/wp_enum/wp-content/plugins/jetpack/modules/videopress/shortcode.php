<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * VideoPress Shortcode Handler
 *
 * This file may or may not be included from the Jetpack VideoPress module.
 */
class VideoPress_Shortcode {
	/**
	 * Singleton VideoPress_Shortcode instance.
	 *
	 * @var VideoPress_Shortcode
	 */
	protected static $instance;

	/**
	 * VideoPress_Shortcode constructor.
	 */
	protected function __construct() {
		// Only add the shortcode if it hasn't already been added by the standalone VideoPress plugin.
		if ( ! shortcode_exists( 'videopress' ) ) {
			add_shortcode( 'videopress', array( $this, 'shortcode_callback' ) );
			add_shortcode( 'wpvideo', array( $this, 'shortcode_callback' ) );

			add_filter( 'wp_video_shortcode_override', array( $this, 'video_shortcode_override' ), 10, 4 );
		}

		$this->add_video_embed_hander();
	}

	/**
	 * VideoPress_Shortcode initialization.
	 *
	 * @return VideoPress_Shortcode
	 */
	public static function initialize() {
		if ( ! isset( self::$instance ) ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Translate a 'videopress' or 'wpvideo' shortcode and arguments into a video player display.
	 *
	 * Expected input formats:
	 *
	 * [videopress OcobLTqC]
	 * [wpvideo OcobLTqC]
	 *
	 * @link https://codex.wordpress.org/Shortcode_API Shortcode API
	 * @param array $attr shortcode attributes.
	 * @return string HTML markup or blank string on fail
	 */
	public function shortcode_callback( $attr ) {
		global $content_width;

		/**
		 * We only accept GUIDs as a first unnamed argument.
		 */
		$guid = isset( $attr[0] ) ? $attr[0] : null;

		if ( isset( $attr['postid'] ) ) {
			$guid = get_post_meta( $attr['postid'], 'videopress_guid', true );
		}

		/**
		 * Make sure the GUID passed in matches how actual GUIDs are formatted.
		 */
		if ( ! videopress_is_valid_guid( $guid ) ) {
			return '';
		}

		/**
		 * Set the defaults
		 */
		$defaults = array(
			'w'               => 0,     // Width of the video player, in pixels
			'at'              => 0,     // How many seconds in to initially seek to
			'hd'              => true,  // Whether to display a high definition version
			'loop'            => false, // Whether to loop the video repeatedly
			'freedom'         => false, // Whether to use only free/libre codecs
			'autoplay'        => false, // Whether to autoplay the video on load
			'permalink'       => true,  // Whether to display the permalink to the video
			'flashonly'       => false, // Whether to support the Flash player exclusively
			'defaultlangcode' => false, // Default language code
			'cover'           => true,  // Whether to scale the video to its container.
			'muted'           => false, // Whether the video should start without sound.
			'controls'        => true,  // Whether the video should display controls.
			'playsinline'     => false, // Whether the video should be allowed to play inline (for browsers that support this).
			'useaveragecolor' => false, // Whether the video should use the seekbar automatic average color.
			'preloadcontent'  => 'metadata', // Setting for how the browser should preload the video (none, metadata, auto).
		);

		// Make sure "false" will be actually false.
		foreach ( $attr as $key => $value ) {
			if ( is_string( $value ) && 'false' === strtolower( $value ) ) {
				$attr[ $key ] = false;
			}
		}

		if ( isset( $attr['preload'] ) ) {
			$attr['preloadcontent'] = $attr['preload'];
		}

		$attr = shortcode_atts( $defaults, $attr, 'videopress' );

		/**
		 * Cast the attributes, post-input.
		 */
		$attr['width']   = absint( $attr['w'] );
		$attr['hd']      = (bool) $attr['hd'];
		$attr['freedom'] = (bool) $attr['freedom'];

		/**
		 * If the provided width is less than the minimum allowed
		 * width, or greater than `$content_width` ignore.
		 */
		if ( $attr['width'] < VIDEOPRESS_MIN_WIDTH ) {
			$attr['width'] = 0;
		} elseif ( isset( $content_width ) && $content_width > VIDEOPRESS_MIN_WIDTH && $attr['width'] > $content_width ) {
			$attr['width'] = 0;
		}

		/**
		 * If there was an invalid or unspecified width, set the width equal to the theme's `$content_width`.
		 */
		if ( 0 === $attr['width'] && isset( $content_width ) && $content_width >= VIDEOPRESS_MIN_WIDTH ) {
			$attr['width'] = $content_width;
		}

		/**
		 * If the width isn't an even number, reduce it by one (making it even).
		 */
		if ( 1 === ( $attr['width'] % 2 ) ) {
			--$attr['width'];
		}

		/**
		 * Filter the default VideoPress shortcode options.
		 *
		 * @module videopress
		 *
		 * @since 2.5.0
		 *
		 * @param array $args Array of VideoPress shortcode options.
		 */
		$options = apply_filters(
			'videopress_shortcode_options',
			array(
				'at'              => (int) $attr['at'],
				'hd'              => $attr['hd'],
				'cover'           => (bool) $attr['cover'],
				'loop'            => $attr['loop'],
				'freedom'         => $attr['freedom'],
				'autoplay'        => $attr['autoplay'],
				'permalink'       => $attr['permalink'],
				'force_flash'     => (bool) $attr['flashonly'],
				'defaultlangcode' => $attr['defaultlangcode'],
				'forcestatic'     => false, // This used to be a displayed option, but now is only.
				'muted'           => $attr['muted'],
				'controls'        => $attr['controls'],
				'playsinline'     => $attr['playsinline'],
				'useAverageColor' => (bool) $attr['useaveragecolor'], // The casing is intentional, shortcode params are lowercase, but player expects useAverageColor
				'preloadContent'  => $attr['preloadcontent'], // The casing is intentional, shortcode params are lowercase, but player expects preloadContent
			// accessible via the `videopress_shortcode_options` filter.
			)
		);

		// Register VideoPress scripts
		wp_register_script( 'videopress', 'https://v0.wordpress.com/js/videopress.js', array( 'jquery', 'swfobject' ), '1.09', false );

		require_once __DIR__ . '/class.videopress-video.php';
		require_once __DIR__ . '/class.videopress-player.php';

		$player = new VideoPress_Player( $guid, $attr['width'], $options );

		if ( is_feed() ) {
			return $player->as_xml();
		} else {
			return $player->as_html();
		}
	}

	/**
	 * Override the standard video short tag to also process videopress files as well.
	 *
	 * This will, parse the src given, and if it is a videopress file, it will parse as the
	 * VideoPress shortcode instead.
	 *
	 * @param string $html     Empty variable to be replaced with shortcode markup.
	 * @param array  $attr     Attributes of the video shortcode.
	 * @param string $content  Video shortcode content.
	 * @param int    $instance Unique numeric ID of this video shortcode instance.
	 *
	 * @return string
	 */
	public function video_shortcode_override( $html, $attr, $content, $instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$videopress_guid = null;

		if ( isset( $attr['videopress_guid'] ) ) {
			$videopress_guid = $attr['videopress_guid'];
		} else {
			// Handle the different possible url attributes
			$url_keys = array( 'src', 'mp4' );

			foreach ( $url_keys as $key ) {
				if ( isset( $attr[ $key ] ) ) {
					$url = $attr[ $key ];
					// phpcs:ignore WordPress.WP.CapitalPDangit
					if ( preg_match( '@videos.(videopress\.com|files\.wordpress\.com)/([a-z0-9]{8})/@i', $url, $matches ) ) {
						$videopress_guid = $matches[2];
					}

					// Also test for videopress oembed url, which is used by the Video Media Widget.
					if ( ! $videopress_guid && preg_match( '@https://videopress.com/v/([a-z0-9]{8})@i', $url, $matches ) ) {
						$videopress_guid = $matches[1];
					}

					// Also test for old v.wordpress.com oembed URL.
					if ( ! $videopress_guid && preg_match( '|^https?://v\.wordpress\.com/([a-zA-Z\d]{8})(.+)?$|i', $url, $matches ) ) { // phpcs:ignore WordPress.WP.CapitalPDangit.Misspelled
						$videopress_guid = $matches[1];
					}

					break;
				}
			}
		}

		if ( $videopress_guid ) {
			$videopress_attr = array( $videopress_guid );
			if ( isset( $attr['width'] ) ) {
				$videopress_attr['w'] = (int) $attr['width'];
			}
			if ( isset( $attr['muted'] ) ) {
				$videopress_attr['muted'] = $attr['muted'];
			}
			if ( isset( $attr['autoplay'] ) ) {
				$videopress_attr['autoplay'] = $attr['autoplay'];
			}
			if ( isset( $attr['loop'] ) ) {
				$videopress_attr['loop'] = $attr['loop'];
			}
			// The core video block doesn't support the cover attribute, setting it to false for consistency.
			$videopress_attr['cover'] = false;

			// Then display the VideoPress version of the stored GUID!
			return $this->shortcode_callback( $videopress_attr );
		}

		return '';
	}

	/**
	 * Register a VideoPress handler for direct links to .mov files (and potential other non-handled types later).
	 */
	public function add_video_embed_hander() {
		// These are the video extensions that VideoPress can transcode and considers video as well (even if core does not).
		$extensions          = array( 'mov' );
		$override_extensions = implode( '|', $extensions );

		$regex = "#^https?://videos.(videopress.com|files.wordpress.com)/.+?.($override_extensions)$#i";

		/** This filter is already documented in core/wp-includes/embed.php */
		$filter = apply_filters( 'wp_video_embed_handler', 'wp_embed_handler_video' );
		wp_embed_register_handler( 'video', $regex, $filter, 10 );
	}
}

VideoPress_Shortcode::initialize();
