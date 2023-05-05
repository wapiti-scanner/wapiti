<?php
/**
 * The Utils class.
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

/**
 * The Utils class.
 */
class Utils {
	/**
	 * Build a VideoPress video URL based on the guid and block attributes.
	 *
	 * @param {string} $guid       - Video GUID.
	 * @param {array}  $attributes - Video block attributes. Default is an empty array.
	 *
	 * @return {string} VideoPress video URL with the specified attributes.
	 */
	public static function get_video_press_url( $guid, $attributes = array() ) {
		if ( ! $guid ) {
			return null;
		}

		$video_press_url_options = wp_parse_args(
			$attributes,
			array(
				'autoplay'            => false,
				'controls'            => true,
				'loop'                => false,
				'muted'               => false,
				'playsinline'         => false,
				'poster'              => '',
				'preload'             => 'metadata',
				'seekbarColor'        => '',
				'seekbarPlayedColor'  => '',
				'seekbarLoadingColor' => '',
				'useAverageColor'     => true,
			)
		);

		$query_args = array(
			'resizeToParent'  => 1,
			'cover'           => 1,
			'autoPlay'        => (int) $video_press_url_options['autoplay'],
			'controls'        => (int) $video_press_url_options['controls'],
			'loop'            => (int) $video_press_url_options['loop'],
			'muted'           => (int) $video_press_url_options['muted'],
			'persistVolume'   => $video_press_url_options['muted'] ? 0 : 1,
			'playsinline'     => (int) $video_press_url_options['playsinline'],
			'preloadContent'  => $video_press_url_options['preload'],
			'sbc'             => $video_press_url_options['seekbarColor'],
			'sbpc'            => $video_press_url_options['seekbarPlayedColor'],
			'sblc'            => $video_press_url_options['seekbarLoadingColor'],
			'useAverageColor' => (int) $video_press_url_options['useAverageColor'],
		);

		if ( ! empty( $video_press_url_options['poster'] ) ) {
			$query_args['posterUrl'] = rawurlencode( $video_press_url_options['poster'] );
		}

		$url = 'https://videopress.com/v/' . $guid;
		return add_query_arg( $query_args, $url );
	}

	/**
	 * Determines if a given URL is a VideoPress URL.
	 *
	 * @since x.x.x
	 *
	 * @param string $url The URL to check.
	 * @return bool True if the URL is a VideoPress URL, false otherwise.
	 */
	public static function is_videopress_url( $url ) {
		$pattern = '/^https?:\/\/(?:(?:v(?:ideo)?\.wordpress\.com|videopress\.com)\/(?:v|embed)|v\.wordpress\.com)\/([a-z\d]{8})(\/|\b)/i'; // phpcs:ignore WordPress.WP.CapitalPDangit.Misspelled
		return (bool) preg_match( $pattern, $url );
	}
}
