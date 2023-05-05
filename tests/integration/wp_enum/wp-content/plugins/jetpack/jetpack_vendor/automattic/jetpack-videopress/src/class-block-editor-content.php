<?php
/**
 * VideoPress Block Editor Content
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

/**
 * VideoPress block editor class for content generation
 */
class Block_Editor_Content {
	/**
	 * Initializer
	 *
	 * This method should be called only once by the Initializer class. Do not call this method again.
	 */
	public static function init() {
		if ( ! Status::is_standalone_plugin_active() ) {
			return;
		}

		// Remove the videopress shortcodes added by the Jetpack plugin.
		if ( shortcode_exists( 'videopress' ) ) {
			remove_shortcode( 'videopress' );
		}
		if ( shortcode_exists( 'wpvideo' ) ) {
			remove_shortcode( 'wpvideo' );
		}

		add_shortcode( 'videopress', array( static::class, 'videopress_embed_shortcode' ) );
		add_shortcode( 'wpvideo', array( static::class, 'videopress_embed_shortcode' ) );

		add_filter( 'wp_video_shortcode_override', array( static::class, 'video_shortcode_override' ), 10, 4 );

		add_filter( 'default_content', array( static::class, 'videopress_video_block_by_guid' ), 10, 2 );
	}

	/**
	 * VideoPress embed shortcode
	 *
	 * Expected input format:
	 * [videopress tLvEwHYZ]
	 *
	 * @param array $atts Shortcode attributes.
	 *
	 * @return string html
	 */
	public static function videopress_embed_shortcode( $atts ) {
		/**
		 * We only accept GUIDs as a first unnamed argument.
		 */
		$guid = isset( $atts[0] ) ? $atts[0] : null;

		/**
		 * Make sure the GUID passed in matches how actual GUIDs are formatted.
		 */
		if ( ! videopress_is_valid_guid( $guid ) ) {
			return '<!-- error: missing or invalid VideoPress video ID -->';
		}

		/**
		 * Set the defaults
		 */
		$defaults = array(
			'w'               => 640,   // Width of the video player, in pixels
			'h'               => 0,     // Height of the video player, in pixels
			'at'              => 0,     // How many seconds in to initially seek to
			'loop'            => false, // Whether to loop the video repeatedly
			'autoplay'        => false, // Whether to autoplay the video on load
			'cover'           => true,  // Whether to scale the video to its container
			'muted'           => false, // Whether the video should start without sound
			'controls'        => true,  // Whether the video should display controls
			'playsinline'     => false, // Whether the video should be allowed to play inline (for browsers that support this)
			'useaveragecolor' => false, // Whether the video should use the seekbar automatic average color
			'preloadcontent'  => 'metadata',
		);

		// Make sure "false" will be actually false.
		foreach ( $atts as $key => $value ) {
			if ( is_string( $value ) && 'false' === strtolower( $value ) ) {
				$atts[ $key ] = false;
			}
		}

		if ( isset( $atts['preload'] ) ) {
			$atts['preloadcontent'] = $atts['preload'];
		}

		$atts = shortcode_atts( $defaults, $atts, 'videopress' );

		$base_url     = 'https://videopress.com/embed/' . $guid;
		$query_params = array(
			'at'              => $atts['at'],
			'loop'            => $atts['loop'],
			'autoplay'        => $atts['autoplay'],
			'muted'           => $atts['muted'],
			'controls'        => $atts['controls'],
			'playsinline'     => $atts['playsinline'],
			'useAverageColor' => $atts['useaveragecolor'], // The casing is intentional, shortcode params are lowercase, but player expects useAverageColor
			'preloadContent'  => $atts['preloadcontent'], // The casing is intentional, shortcode params are lowercase, but player expects preloadContent
		);
		$src          = esc_url( add_query_arg( $query_params, $base_url ) );

		$width = absint( $atts['w'] );
		if ( ! $atts['h'] ) {
			$aspect_ratio = 16 / 9; // TODO: Get the correct aspect ratio for the video.
			$height       = $width / $aspect_ratio;
		} else {
			$height = absint( $atts['h'] );
		}

		$cover = $atts['cover'] ? ' data-resize-to-parent="true"' : '';

		$block_template =
		'<figure class="wp-block-videopress-video wp-block-jetpack-videopress jetpack-videopress-player">' .
			'<div class="jetpack-videopress-player__wrapper">' .
				'<iframe ' .
					'title="' . __( 'VideoPress Video Player', 'jetpack-videopress-pkg' ) . '" ' .
					'aria-label="' . __( 'VideoPress Video Player', 'jetpack-videopress-pkg' ) . '" ' .
					'src="%s" ' .
					'width="%s"' .
					'height="%s" ' .
					'frameborder="0" ' .
					'allowfullscreen%s allow="clipboard-write">' .
				'</iframe>' .
			'</div>' .
		'</figure>';

		$version = Package_Version::PACKAGE_VERSION;
		wp_enqueue_script( 'videopress-iframe', 'https://videopress.com/videopress-iframe.js', array(), $version, true );

		return sprintf( $block_template, $src, $width, $height, $cover );
	}

	/**
	 * Generates a VideoPress video block content with the given guid
	 *
	 * @param string  $content Post content.
	 * @param WP_Post $post Post.
	 * @return string
	 */
	public static function videopress_video_block_by_guid( $content, $post ) {
		if ( isset( $_GET['videopress_guid'], $_GET['_wpnonce'] )
			&& wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'videopress-content-nonce' )
			&& current_user_can( 'edit_post', $post->ID )
			&& '' === $content
		) {
			$guid = sanitize_text_field( wp_unslash( $_GET['videopress_guid'] ) );

			$base_url     = 'https://videopress.com/v/' . $guid;
			$query_params = array(
				'resizeToParent'  => 'true',
				'cover'           => 'true',
				'preloadContent'  => 'metadata',
				'useAverageColor' => 'true',
			);
			$url          = esc_url( add_query_arg( $query_params, $base_url ) );

			if ( ! empty( $guid ) ) {
				// ref /client/lib/url/index.ts
				$content = '<!-- wp:videopress/video {"guid":"' . $guid . '"} -->
				<figure class="wp-block-videopress-video wp-block-jetpack-videopress jetpack-videopress-player">
					<div class="jetpack-videopress-player__wrapper">' . $url . '</div>
				</figure>
				<!-- /wp:videopress/video -->';
			}
		}

		return $content;
	}

	/**
	 * Override the standard video short tag to also process videopress files as well.
	 *
	 * This will parse the given src and, if it is a videopress file, parse as the
	 * VideoPress shortcode instead.
	 *
	 * @param string $html     Empty variable to be replaced with shortcode markup.
	 * @param array  $attr     Attributes of the video shortcode.
	 * @param string $content  Video shortcode content.
	 * @param int    $instance Unique numeric ID of this video shortcode instance.
	 *
	 * @return string
	 */
	public static function video_shortcode_override( $html, $attr, $content, $instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
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
			$videopress_atts = array( $videopress_guid );

			// height is ignored on jetpack video block, so we don't pass it for consistency.
			if ( isset( $attr['width'] ) ) {
				$videopress_atts['w'] = (int) $attr['width'];
			}
			if ( isset( $attr['muted'] ) ) {
				$videopress_atts['muted'] = $attr['muted'];
			}
			if ( isset( $attr['autoplay'] ) ) {
				$videopress_atts['autoplay'] = $attr['autoplay'];
			}
			if ( isset( $attr['loop'] ) ) {
				$videopress_atts['loop'] = $attr['loop'];
			}
			// The core video block doesn't support the cover attribute, setting it to false for consistency.
			$videopress_atts['cover'] = false;

			// Then display the VideoPress version of the stored GUID!
			return self::videopress_embed_shortcode( $videopress_atts );
		}

		return '';
	}
}
