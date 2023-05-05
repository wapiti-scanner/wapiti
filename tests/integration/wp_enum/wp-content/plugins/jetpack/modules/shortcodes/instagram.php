<?php
/**
 * Instagram Embeds.
 *
 * Full links: https://www.instagram.com/p/BnMOk_FFsxg/
 * https://www.instagram.com/tv/BkQjCfsBIzi/
 * [instagram url=https://www.instagram.com/p/BnMOk_FFsxg/]
 * [instagram url=https://www.instagram.com/p/BZoonmAHvHf/ width=320]
 * Embeds can be converted to a shortcode when the author does not have unfiltered_html caps:
 * <blockquote class="instagram-media" data-instgrm-captioned data-instgrm-version="2" style=" background:#FFF; border:0; border-radius:3px; box-shadow:0 0 1px 0 rgba(0,0,0,0.5),0 1px 10px 0 rgba(0,0,0,0.15); margin: 1px; max-width:658px; padding:0; width:99.375%; width:-webkit-calc(100% - 2px); width:calc(100% - 2px);"><div style="padding:8px;"><div style=" background:#F8F8F8; line-height:0; margin-top:40px; padding-bottom:55%; padding-top:45%; text-align:center; width:100%;"><div style="position:relative;"><div style=" -webkit-animation:dkaXkpbBxI 1s ease-out infinite; animation:dkaXkpbBxI 1s ease-out infinite; background:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACwAAAAsCAMAAAApWqozAAAAGFBMVEUiIiI9PT0eHh4gIB4hIBkcHBwcHBwcHBydr+JQAAAACHRSTlMABA4YHyQsM5jtaMwAAADfSURBVDjL7ZVBEgMhCAQBAf//42xcNbpAqakcM0ftUmFAAIBE81IqBJdS3lS6zs3bIpB9WED3YYXFPmHRfT8sgyrCP1x8uEUxLMzNWElFOYCV6mHWWwMzdPEKHlhLw7NWJqkHc4uIZphavDzA2JPzUDsBZziNae2S6owH8xPmX8G7zzgKEOPUoYHvGz1TBCxMkd3kwNVbU0gKHkx+iZILf77IofhrY1nYFnB/lQPb79drWOyJVa/DAvg9B/rLB4cC+Nqgdz/TvBbBnr6GBReqn/nRmDgaQEej7WhonozjF+Y2I/fZou/qAAAAAElFTkSuQmCC); display:block; height:44px; margin:0 auto -44px; position:relative; top:-44px; width:44px;"></div><span style=" color:#c9c8cd; font-family:Arial,sans-serif; font-size:12px; font-style:normal; font-weight:bold; position:relative; top:15px;">Loading</span></div></div><p style=" font-family:Arial,sans-serif; font-size:14px; line-height:17px; margin:8px 0 0 0; padding:0 4px; word-wrap:break-word;"> Balloons</p><p style=" line-height:32px; margin-bottom:0; margin-top:8px; padding:0; text-align:center;"> <a href="https://instagram.com/p/r9vfPrmjeB/" style=" color:#c9c8cd; font-family:Arial,sans-serif; font-size:14px; font-style:normal; font-weight:normal; text-decoration:none;" target="_top"> View on Instagram</a></p></div><style>@-webkit-keyframes"dkaXkpbBxI"{ 0%{opacity:0.5;} 50%{opacity:1;} 100%{opacity:0.5;} } @keyframes"dkaXkpbBxI"{ 0%{opacity:0.5;} 50%{opacity:1;} 100%{opacity:0.5;} }</style></blockquote>
 * <script async defer src="https://platform.instagram.com/en_US/embeds.js"></script>
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Status;

if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	add_action( 'init', 'jetpack_instagram_enable_embeds' );
} else {
	jetpack_instagram_enable_embeds();
}

/**
 * Register Instagram as oembed provider, and add required filters for the API request.
 * Add filter to reverse iframes to shortcode. Register [instagram] shortcode.
 *
 * @since 9.1.0
 */
function jetpack_instagram_enable_embeds() {
	wp_oembed_add_provider(
		'#https?://(www\.)?instagr(\.am|am\.com)/(p|tv|reel)/.*#i',
		'https://graph.facebook.com/v5.0/instagram_oembed/',
		true
	);

	/**
	 * Handle an alternate Instagram URL format, where the username is also part of the URL.
	 */
	wp_oembed_add_provider(
		'#https?://(?:www\.)?instagr(?:\.am|am\.com)/(?:[^/]*)/(p|tv|reel)/([^\/]*)#i',
		'https://graph.facebook.com/v5.0/instagram_oembed/',
		true
	);

	/**
	 * Add auth token required by Instagram's oEmbed REST API, or proxy through WP.com.
	 */
	add_filter( 'oembed_fetch_url', 'jetpack_instagram_oembed_fetch_url', 10, 3 );

	/**
	 * Add JP auth headers if we're proxying through WP.com.
	 */
	add_filter( 'oembed_remote_get_args', 'jetpack_instagram_oembed_remote_get_args', 10, 2 );

	/**
	 * Embed reversal: Convert an embed code from Instagram.com to an oEmbeddable URL.
	 */
	add_filter( 'pre_kses', 'jetpack_instagram_embed_reversal' );

	/**
	 * Add the shortcode.
	 */
	add_shortcode( 'instagram', 'jetpack_shortcode_instagram' );
}

/**
 * Embed Reversal for Instagram
 *
 * Hooked to pre_kses, converts an embed code from Instagram.com to an oEmbeddable URL.
 *
 * @param string $content Post content.
 *
 * @return string The filtered or the original content.
 **/
function jetpack_instagram_embed_reversal( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'instagram.com' ) ) {
		return $content;
	}

	/*
	 * Sample embed code:
	 * <blockquote class="instagram-media" data-instgrm-captioned data-instgrm-version="2" style=" background:#FFF; border:0; border-radius:3px; box-shadow:0 0 1px 0 rgba(0,0,0,0.5),0 1px 10px 0 rgba(0,0,0,0.15); margin: 1px; max-width:658px; padding:0; width:99.375%; width:-webkit-calc(100% - 2px); width:calc(100% - 2px);"><div style="padding:8px;"><div style=" background:#F8F8F8; line-height:0; margin-top:40px; padding-bottom:55%; padding-top:45%; text-align:center; width:100%;"><div style="position:relative;"><div style=" -webkit-animation:dkaXkpbBxI 1s ease-out infinite; animation:dkaXkpbBxI 1s ease-out infinite; background:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACwAAAAsCAMAAAApWqozAAAAGFBMVEUiIiI9PT0eHh4gIB4hIBkcHBwcHBwcHBydr+JQAAAACHRSTlMABA4YHyQsM5jtaMwAAADfSURBVDjL7ZVBEgMhCAQBAf//42xcNbpAqakcM0ftUmFAAIBE81IqBJdS3lS6zs3bIpB9WED3YYXFPmHRfT8sgyrCP1x8uEUxLMzNWElFOYCV6mHWWwMzdPEKHlhLw7NWJqkHc4uIZphavDzA2JPzUDsBZziNae2S6owH8xPmX8G7zzgKEOPUoYHvGz1TBCxMkd3kwNVbU0gKHkx+iZILf77IofhrY1nYFnB/lQPb79drWOyJVa/DAvg9B/rLB4cC+Nqgdz/TvBbBnr6GBReqn/nRmDgaQEej7WhonozjF+Y2I/fZou/qAAAAAElFTkSuQmCC); display:block; height:44px; margin:0 auto -44px; position:relative; top:-44px; width:44px;"></div><span style=" color:#c9c8cd; font-family:Arial,sans-serif; font-size:12px; font-style:normal; font-weight:bold; position:relative; top:15px;">Loading</span></div></div><p style=" font-family:Arial,sans-serif; font-size:14px; line-height:17px; margin:8px 0 0 0; padding:0 4px; word-wrap:break-word;"> Balloons</p><p style=" line-height:32px; margin-bottom:0; margin-top:8px; padding:0; text-align:center;"> <a href="https://instagram.com/p/r9vfPrmjeB/" style=" color:#c9c8cd; font-family:Arial,sans-serif; font-size:14px; font-style:normal; font-weight:normal; text-decoration:none;" target="_top"> View on Instagram</a></p></div><style>@-webkit-keyframes"dkaXkpbBxI"{ 0%{opacity:0.5;} 50%{opacity:1;} 100%{opacity:0.5;} } @keyframes"dkaXkpbBxI"{ 0%{opacity:0.5;} 50%{opacity:1;} 100%{opacity:0.5;} }</style></blockquote>
	 * <script async defer src="https://platform.instagram.com/en_US/embeds.js"></script>
	*/

	$regexes = array();

	// new style js.
	$regexes[] = '#<blockquote[^>]+?class="instagram-media"[^>].+?>(.+?)</blockquote><script[^>]+?src="(https?:)?//platform\.instagram\.com/(.+?)/embeds\.js"></script>#ix';

	// Let's play nice with the visual editor too.
	$regexes[] = '#&lt;blockquote(?:[^&]|&(?!gt;))+?class="instagram-media"(?:[^&]|&(?!gt;)).+?&gt;(.+?)&lt;/blockquote&gt;&lt;script(?:[^&]|&(?!gt;))+?src="(https?:)?//platform\.instagram\.com/(.+?)/embeds\.js"(?:[^&]|&(?!gt;))*+&gt;&lt;/script&gt;#ix';

	// old style iframe.
	$regexes[] = '#<iframe[^>]+?src="((?:https?:)?//(?:www\.)?instagram\.com/p/([^"\'/]++)[^"\']*?)"[^>]*+>\s*?</iframe>#i';

	// Let's play nice with the visual editor too.
	$regexes[] = '#&lt;iframe(?:[^&]|&(?!gt;))+?src="((?:https?:)?//(?:www\.)instagram\.com/p/([^"\'/]++)[^"\']*?)"(?:[^&]|&(?!gt;))*+&gt;\s*?&lt;/iframe&gt;#i';

	foreach ( $regexes as $regex ) {
		if ( ! preg_match_all( $regex, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			if ( ! preg_match( '#(https?:)?//(?:www\.)?instagr(\.am|am\.com)/p/([^/]*)#i', $match[1], $url_matches ) ) {
				continue;
			}

			// Since we support Instagram via oEmbed, we simply leave a link on a line by itself.
			$replace_regex = sprintf( '#\s*%s\s*#', preg_quote( $match[0], '#' ) );
			$url           = esc_url( $url_matches[0] );

			$content = preg_replace( $replace_regex, sprintf( "\n\n%s\n\n", $url ), $content );
			/** This action is documented in modules/shortcodes/youtube.php */
			do_action( 'jetpack_embed_to_shortcode', 'instagram', $url );
		}
	}

	return $content;
}

/**
 * List of allowed and sanitized parameters
 * that can be used with the Instagram oEmbed endpoint.
 *
 * Those parameters can be provided via the Instagram URL, or via shortcode parameters.
 *
 * @see https://developers.facebook.com/docs/graph-api/reference/instagram-oembed#parameters
 *
 * @since 9.1.0
 *
 * @param string $url  URL of the content to be embedded.
 * @param array  $atts Shortcode attributes.
 *
 * @return array $params Array of parameters to be used in Instagram query.
 */
function jetpack_instagram_get_allowed_parameters( $url, $atts = array() ) {
	global $content_width;

	// Any URL passed via a shortcode attribute takes precedence.
	if ( ! empty( $atts['url'] ) ) {
		$url = $atts['url'];
		unset( $atts['url'] );
	}

	/*
	 * Get URL and parameters from the URL if possible.
	 *
	 * We'll also clean any other query params from the URL since Facebook's new API for Instagram
	 * embeds does not like query parameters. See p7H4VZ-2DU-p2.
	 */
	$parsed_url = wp_parse_url( $url );
	if ( $parsed_url && isset( $parsed_url['host'] ) && isset( $parsed_url['path'] ) ) {
		// Bail early if this is not an Instagram URL.
		if ( ! preg_match( '/(?:^|\.)instagr(?:\.am|am\.com)$/', $parsed_url['host'] ) ) {
			return array();
		}

		$url = 'https://www.instagram.com' . $parsed_url['path'];

		// If we have any parameters as part of the URL, we merge them with our attributes.
		if ( ! empty( $parsed_url['query'] ) ) {
			$query_args = array();
			wp_parse_str( $parsed_url['query'], $query_args );

			$atts = array_merge( $atts, $query_args );
		}
	} else {
		return array();
	}

	$max_width = 698;
	$min_width = 320;

	$params = shortcode_atts(
		array(
			'url'         => $url,
			'width'       => ( is_numeric( $content_width ) && $content_width > 0 ) ? $content_width : $max_width,
			'height'      => '',
			'hidecaption' => false,
		),
		$atts,
		'instagram'
	);

	// Ensure width is within bounds.
	$params['width'] = absint( $params['width'] );
	if ( $params['width'] > $max_width ) {
		$params['width'] = $max_width;
	} elseif ( $params['width'] < $min_width ) {
		$params['width'] = $min_width;
	}

	return $params;
}

/**
 * Add auth token required by Instagram's oEmbed REST API, or proxy through WP.com.
 *
 * @since 9.1.0
 *
 * @param string $provider URL of the oEmbed provider.
 * @param string $url      URL of the content to be embedded.
 * @param array  $args      Additional arguments for retrieving embed HTML.
 *
 * @return string
 */
function jetpack_instagram_oembed_fetch_url( $provider, $url, $args ) {
	if ( ! wp_startswith( $provider, 'https://graph.facebook.com/v5.0/instagram_oembed/' ) ) {
		return $provider;
	}

	// Get a set of URL and parameters supported by Facebook.
	$clean_parameters = jetpack_instagram_get_allowed_parameters( $url, $args );

	// Replace existing URL by our clean version.
	if ( ! empty( $clean_parameters['url'] ) ) {
		$provider = add_query_arg( 'url', rawurlencode( $clean_parameters['url'] ), $provider );
	}

	// Our shortcode supports the width param, but the API expects maxwidth.
	if ( ! empty( $clean_parameters['width'] ) ) {
		$provider = add_query_arg( 'maxwidth', $clean_parameters['width'], $provider );
	}

	if ( ! empty( $clean_parameters['hidecaption'] ) ) {
		$provider = add_query_arg( 'hidecaption', true, $provider );
	}

	$access_token = jetpack_instagram_get_access_token();

	if ( ! empty( $access_token ) ) {
		return add_query_arg( 'access_token', $access_token, $provider );
	}

	// If we don't have an access token, we go through the WP.com proxy instead.
	// To that end, we need to make sure that we're connected to WP.com.
	if ( ! Jetpack::is_connection_ready() || ( new Status() )->is_offline_mode() ) {
		return $provider;
	}

	// @TODO Use Core's /oembed/1.0/proxy endpoint on WP.com
	// (Currently not global but per-site, i.e. /oembed/1.0/sites/1234567/proxy)
	// and deprecate /oembed-proxy/instagram endpoint.
	$wpcom_oembed_proxy = Constants::get_constant( 'JETPACK__WPCOM_JSON_API_BASE' ) . '/wpcom/v2/oembed-proxy/instagram/';
	return str_replace( 'https://graph.facebook.com/v5.0/instagram_oembed/', $wpcom_oembed_proxy, $provider );
}

/**
 * Add JP auth headers if we're proxying through WP.com.
 *
 * @param array  $args oEmbed remote get arguments.
 * @param string $url  URL to be inspected.
 */
function jetpack_instagram_oembed_remote_get_args( $args, $url ) {
	if ( ! wp_startswith( $url, Constants::get_constant( 'JETPACK__WPCOM_JSON_API_BASE' ) . '/wpcom/v2/oembed-proxy/instagram/' ) ) {
		return $args;
	}

	$method         = 'GET';
	$signed_request = Client::build_signed_request(
		compact( 'url', 'method' )
	);

	return $signed_request['request'];
}

/**
 * Fetches a Facebook API access token used for query for Instagram embed information, if one is set.
 *
 * @return string The access token or ''
 */
function jetpack_instagram_get_access_token() {
	/**
	 * Filters the Instagram embed token that is used for querying the Facebook API.
	 *
	 * When this token is set, requests are not proxied through the WordPress.com API. Instead, a request is made directly to the
	 * Facebook API to query for information about the embed which should provide a performance benefit.
	 *
	 * @module shortcodes
	 *
	 * @since  9.0.0
	 *
	 * @param string string The access token set via the JETPACK_INSTAGRAM_EMBED_TOKEN constant.
	 */
	return (string) apply_filters( 'jetpack_instagram_embed_token', (string) Constants::get_constant( 'JETPACK_INSTAGRAM_EMBED_TOKEN' ) );
}

/**
 * Display the Instagram shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function jetpack_shortcode_instagram( $atts ) {
	global $wp_embed;

	if ( empty( $atts['url'] ) ) {
		return '';
	}

	$atts = jetpack_instagram_get_allowed_parameters( $atts['url'], $atts );

	if ( empty( $atts['url'] ) ) {
		return '';
	}

	if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
		$url_pattern = '#http(s?)://(www\.)?instagr(\.am|am\.com)/p/([^/?]+)#i';
		preg_match( $url_pattern, $atts['url'], $matches );
		if ( ! $matches ) {
			return sprintf(
				'<a href="%1$s" class="amp-wp-embed-fallback">%1$s</a>',
				esc_url( $atts['url'] )
			);
		}

		$shortcode_id = end( $matches );
		$width        = ! empty( $atts['width'] ) ? $atts['width'] : 600;
		$height       = ! empty( $atts['height'] ) ? $atts['height'] : 600;
		return sprintf(
			'<amp-instagram data-shortcode="%1$s" layout="responsive" width="%2$d" height="%3$d" data-captioned></amp-instagram>',
			esc_attr( $shortcode_id ),
			absint( $width ),
			absint( $height )
		);
	}

	return $wp_embed->shortcode( $atts, $atts['url'] );
}
