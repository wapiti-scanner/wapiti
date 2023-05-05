<?php
/**
 * Flickr Short Code
 * Author: kellan
 * License: BSD/GPL/public domain (take your pick)
 *
 * [flickr video=www.flickr.com/photos/kalakeli/49931239842]
 * [flickr video=49931239842]
 * [flickr video=49931239842 w=200 h=150]
 * [flickr video=49931239842 autoplay="yes" controls="no"]
 * [flickr video=49931239842 autoplay="no" controls="yes" w=200 h=150]
 *
 * <div class="flick_video" style="max-width: 100%;width: 500px;height: 300px;"><video src="https://www.flickr.com/photos/kalakeli/49931239842/play/360p/183f75d545/" controls autoplay ></video></div>
 *
 * @package automattic/jetpack
 */

/**
 * Transform embed to shortcode on save.
 *
 * @param string $content Post content.
 *
 * @return string Shortcode or the embed content itself.
 */
function flickr_embed_to_shortcode( $content ) {
	if ( ! is_string( $content ) ) {
		return $content;
	}

	if ( false !== strpos( $content, '<div class="flickr_video"' ) && false !== strpos( $content, '<video' ) ) {
		return jetpack_flickr_video_to_shortcode( $content );
	} elseif ( preg_match( '/<iframe src="(https?:)?\/\/([\da-z\-]+\.)*?((static)?flickr\.com|flic\.kr)\/[^\"]+\"/', $content ) ) {
		return jetpack_flickr_photo_to_shortcode( $content );
	}

	return $content;
}

/**
 * Transforms embed to shortcode on save when the photo param is used.
 * If embed content can not be transformed to a valid shortcode,
 * the embed content itself is returned.
 *
 * @param string $content Embed output.
 *
 * @return string Shortcode or the embed content.
 */
function jetpack_flickr_photo_to_shortcode( $content ) {
	preg_match( '/<iframe src=\"([^\"]+)\"(\s+height=\"([^\"]*)\")?(\s+width=\"([^\"]*)\")?/', $content, $matches );

	if ( empty( $matches[1] ) ) {
		return $content;
	}

	$src    = esc_attr( str_replace( 'player/', '', $matches[1] ) );
	$height = empty( $matches[3] ) ? '' : esc_attr( $matches[3] );
	$width  = empty( $matches[5] ) ? '' : esc_attr( $matches[5] );

	/** This action is documented in modules/shortcodes/youtube.php */
	do_action( 'jetpack_embed_to_shortcode', 'flickr_photo', $src );

	return '[flickr photo="' . $src . '" w=' . $width . ' h=' . $height . ']';
}

/**
 * Transforms embed to shortcode on save when the video param is used.
 * If embed content can not be transformed to a valid shortcode,
 * the embed content itself is returned.
 *
 * @param string $content Embed output.
 *
 * @return string Shortcode or the embed content.
 */
function jetpack_flickr_video_to_shortcode( $content ) {
	// Get video src.
	preg_match( '/<video src=\"([^\"]+)\"/', $content, $matches );

	if ( empty( $matches[1] ) ) {
		return $content;
	}

	preg_match( '/(https?:)?\/\/([\da-z\-]+\.)*?((static)?flickr\.com|flic\.kr)\/photos\/([^\/]+)\/\d+\//', $matches[1], $matches );

	$video_src = esc_attr( $matches[0] );

	// Get width and height.

	preg_match( '/style=\"max-width: 100%;(width:\s(\d+)px;)?(height:\s(\d+)px;)?/', $content, $matches );

	$width = empty( $matches[2] ) ? '' : 'w=' . esc_attr( $matches[2] );

	$height = empty( $matches[4] ) ? '' : 'h=' . esc_attr( $matches[4] );

	$controls = false !== strpos( $content, 'controls' ) ? 'yes' : 'no';

	$autoplay = false !== strpos( $content, 'autoplay' ) ? 'yes' : 'no';

	/** This action is documented in modules/shortcodes/youtube.php */
	do_action( 'jetpack_embed_to_shortcode', 'flickr_video', $video_src );

	return '[flickr video="' . $video_src . '" ' . $width . ' ' . $height . ' controls="' . $controls . '" autoplay="' . $autoplay . '"]';
}

add_filter( 'pre_kses', 'flickr_embed_to_shortcode' );

/**
 * Flickr Shortcode handler.
 *
 * @param array $atts Shortcode attributes.
 *
 * @return string Shortcode Output.
 */
function flickr_shortcode_handler( $atts ) {
	$atts = shortcode_atts(
		array(
			'video'    => 0,
			'photo'    => 0,
			'w'        => '',
			'h'        => '',
			'controls' => 'yes',
			'autoplay' => '',
		),
		$atts,
		'flickr'
	);

	if ( ! empty( $atts['video'] ) ) {
		$showing = 'video';
		$src     = $atts['video'];
	} elseif ( ! empty( $atts['photo'] ) ) {
		$showing = 'photo';
		$src     = $atts['photo'];
	} else {
		return '';
	}

	$src = str_replace( 'http://', 'https://', $src );

	if ( 'video' === $showing ) {

		$video_id = flick_shortcode_video_id( $src );

		if ( empty( $video_id ) ) {
			return '';
		}

		$atts = array_map( 'esc_attr', $atts );
		return flickr_shortcode_video_markup( $atts, $video_id, $src );
	} elseif ( 'photo' === $showing ) {

		if ( ! preg_match( '~^(https?:)?//([\da-z\-]+\.)*?((static)?flickr\.com|flic\.kr)/.*~i', $src ) ) {
			return '';
		}

		$height = empty( $atts['h'] ) ? 'auto' : esc_attr( $atts['h'] );

		$src = sprintf( '%s/player/', untrailingslashit( $src ) );

		$allow_full_screen = 'allowfullscreen webkitallowfullscreen mozallowfullscreen oallowfullscreen msallowfullscreen';

		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			$allow_full_screen = str_replace( ' oallowfullscreen msallowfullscreen', '', $allow_full_screen );
		}

		return sprintf( '<iframe src="%s" height="%s" width="%s"  frameborder="0" %s></iframe>', esc_url( $src ), $height, esc_attr( $atts['w'] ), $allow_full_screen );
	}

	return false;
}

/**
 * Return HTML markup for a Flickr embed.
 *
 * @param array  $atts Shortcode attributes.
 * @param string $id Video ID.
 * @param string $video_param video param of the shortcode.
 *
 * @return string Shortcode ouput for video.
 */
function flickr_shortcode_video_markup( $atts, $id, $video_param ) {

	$transient_name = "flickr_video_$id";
	$video_src      = get_transient( $transient_name );

	if ( empty( $video_src ) ) {
		$video_url = '';
		if ( ! is_numeric( $video_param ) ) {
			$video_url = $video_param;
		} else {
			// Get the URL of the video from the page of the video.
			$video_page_content = wp_remote_get( "http://flickr.com/photo.gne?id=$video_param" );

			// Bail if we do not get any info from Flickr.
			if ( is_wp_error( $video_page_content ) ) {
				return '';
			}

			// Extract the URL from the og:url meta tag.
			preg_match( '/property=\"og:url\"\scontent=\"([^\"]+)\"/', $video_page_content['body'], $matches );
			if ( empty( $matches[1] ) ) {
				return '';
			}
			$video_url = $matches[1];
		}

		$provider = 'https://www.flickr.com/services/oembed/';
		$oembed   = _wp_oembed_get_object();
		$data     = (array) $oembed->fetch( $provider, $video_url );
		if ( empty( $data['html'] ) ) {
			return '';
		}

		// Get the embed url.
		preg_match( '/src=\"([^\"]+)\"/', $data['html'], $matches );

		$embed_url = $matches[1];

		$embed_page = wp_remote_get( $embed_url );

		// Get the video url from embed html markup.

		preg_match( '/video.+src=\"([^\"]+)\"/', $embed_page['body'], $matches );

		$video_src = $matches[1];

		set_transient( $transient_name, $video_src, 2592000 ); // 30 days transient.
	}

	$style = 'max-width: 100%;';

	if ( ! empty( $atts['w'] ) && is_numeric( $atts['w'] ) ) {
		$style .= sprintf( 'width: %dpx;', $atts['w'] );
	}

	if ( ! empty( $atts['h'] ) && is_numeric( $atts['h'] ) ) {
		$style .= sprintf( 'height: %dpx;', $atts['h'] );
	}

	$controls = 'yes' === $atts['controls'] ? 'controls' : '';
	$autoplay = 'yes' === $atts['autoplay'] ? 'autoplay' : '';

	return sprintf(
		'<div class="flick_video" style="%s"><video src="%s" %s %s /></div>',
		esc_attr( $style ),
		esc_attr( $video_src ),
		$controls,
		$autoplay
	);
}

/**
 * Extract the id of the flickr video from the video param.
 *
 * @param string $video_param Video parameter of the shortcode.
 *
 * @return string|boolean ID of the video or false in case the ID can not be extracted.
 */
function flick_shortcode_video_id( $video_param ) {
	if ( preg_match( '/^https?:\/\/(www\.)?flickr\.com\/.+/', $video_param ) || preg_match( '/^https?:\/\/flic\.kr\/.+/', $video_param ) ) {

		// Extract the video id from the url.
		preg_match( '/\d+/', $video_param, $matches );

		if ( empty( $matches ) ) {
			return false;
		}

		return $matches[0];

	} elseif ( is_numeric( $video_param ) ) {
		return $video_param;
	}

	return false;
}

add_shortcode( 'flickr', 'flickr_shortcode_handler' );

// Override core's Flickr support because Flickr oEmbed doesn't support web embeds.
wp_embed_register_handler( 'flickr', '#https?://(www\.)?flickr\.com/.*#i', 'jetpack_flickr_oembed_handler' );

/**
 * Callback to modify output of embedded Vimeo video using Jetpack's shortcode.
 *
 * @since 3.9
 *
 * @param array $matches Regex partial matches against the URL passed.
 * @param array $attr    Attributes received in embed response.
 * @param array $url     Requested URL to be embedded.
 *
 * @return string Return output of Vimeo shortcode with the proper markup.
 */
function jetpack_flickr_oembed_handler( $matches, $attr, $url ) {
	/*
	 * Legacy slideshow embeds end with /show/
	 * e.g. http://www.flickr.com/photos/yarnaholic/sets/72157615194738969/show/
	 */
	if ( '/show/' !== substr( $url, -strlen( '/show/' ) ) ) {
		// These lookups need cached, as they don't use WP_Embed (which caches).
		$cache_key   = md5( $url . wp_json_encode( $attr ) );
		$cache_group = 'oembed_flickr';

		$html = wp_cache_get( $cache_key, $cache_group );

		if ( false === $html ) {
			$html = _wp_oembed_get_object()->get_html( $url, $attr );

			wp_cache_set( $cache_key, $html, $cache_group, 60 * MINUTE_IN_SECONDS );
		}

		return $html;
	}

	return flickr_shortcode_handler( array( 'photo' => $url ) );
}
