<?php
/**
 * Vimeo Shortcode.
 *
 * Examples:
 * [vimeo 141358]
 * [vimeo http://vimeo.com/141358]
 * [vimeo 141358 h=500&w=350]
 * [vimeo 141358 h=500 w=350]
 * [vimeo id=141358 width=350 height=500]
 *
 * <iframe src="http://player.vimeo.com/video/18427511" width="400" height="225" frameborder="0"></iframe><p><a href="http://vimeo.com/18427511">Eskmo 'We Got More' (Official Video)</a> from <a href="http://vimeo.com/ninjatune">Ninja Tune</a> on <a href="http://vimeo.com">Vimeo</a>.</p>
 *
 * @package automattic/jetpack
 */

/**
 * Extract Vimeo ID from shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function jetpack_shortcode_get_vimeo_id( $atts ) {
	if ( isset( $atts[0] ) ) {
		$atts[0] = trim( $atts[0], '=' );
		$id      = false;
		if ( is_numeric( $atts[0] ) ) {
			$id = (int) $atts[0];
		} elseif ( preg_match( '|vimeo\.com/(\d+)/?$|i', $atts[0], $match ) ) {
			$id = (int) $match[1];
		} elseif ( preg_match( '|player\.vimeo\.com/video/(\d+)/?$|i', $atts[0], $match ) ) {
			$id = (int) $match[1];
		}

		return $id;
	}

	return 0;
}

/**
 * Get video dimensions.
 *
 * @since 8.0.0
 *
 * @param array $attr     The attributes of the shortcode.
 * @param array $old_attr Optional array of attributes from the old shortcode format.
 *
 * @return array Width and height.
 */
function jetpack_shortcode_get_vimeo_dimensions( $attr, $old_attr = array() ) {
	global $content_width;

	$default_width  = 600;
	$default_height = 338;
	$aspect_ratio   = $default_height / $default_width;

	/*
	 * For width and height, we want to support both formats
	 * that can be provided in the new shortcode format:
	 * - for width: width or w
	 * - for height: height or h
	 *
	 * For each variation, the full word takes priority.
	 *
	 * If no variation is set, we default to the default width and height values set above.
	 */
	if ( ! empty( $attr['width'] ) ) {
		$width = absint( $attr['width'] );
	} elseif ( ! empty( $attr['w'] ) ) {
		$width = absint( $attr['w'] );
	} else {
		$width = $default_width;
	}

	if ( ! empty( $attr['height'] ) ) {
		$height = absint( $attr['height'] );
	} elseif ( ! empty( $attr['h'] ) ) {
		$height = absint( $attr['h'] );
	} else {
		$height = $default_height;
	}

	/*
	 * Support w and h argument as fallbacks in old shortcode format.
	 */
	if (
		$default_width === $width
		&& ! empty( $old_attr['w'] )
	) {
		$width = absint( $old_attr['w'] );

		if (
			$default_width === $width
			&& empty( $old_attr['h'] )
		) {
			$height = round( $width * $aspect_ratio );
		}
	}

	if (
		$default_height === $height
		&& ! empty( $old_attr['h'] )
	) {
		$height = absint( $old_attr['h'] );

		if ( empty( $old_attr['w'] ) ) {
			$width = round( $height * $aspect_ratio );
		}
	}

	/*
	 * If we have a content width defined, let it be the new default.
	 */
	if (
		$default_width === $width
		&& ! empty( $content_width )
	) {
		$width = absint( $content_width );
	}

	/*
	 * If we have a custom width, we need a custom height as well
	 * to maintain aspect ratio.
	 */
	if (
		$default_width !== $width
		&& $default_height === $height
	) {
		$height = round( ( $width / 640 ) * 360 );
	}

	/**
	 * Filter the Vimeo player width.
	 *
	 * @module shortcodes
	 *
	 * @since 3.4.0
	 *
	 * @param int $width Width of the Vimeo player in pixels.
	 */
	$width = (int) apply_filters( 'vimeo_width', $width );

	/**
	 * Filter the Vimeo player height.
	 *
	 * @module shortcodes
	 *
	 * @since 3.4.0
	 *
	 * @param int $height Height of the Vimeo player in pixels.
	 */
	$height = (int) apply_filters( 'vimeo_height', $height );

	return array( $width, $height );
}

/**
 * Convert a Vimeo shortcode into an embed code.
 *
 * @param array $atts An array of shortcode attributes.
 *
 * @return string The embed code for the Vimeo video.
 */
function vimeo_shortcode( $atts ) {
	$attr = array_map(
		'intval',
		shortcode_atts(
			array(
				'id'       => 0,
				'width'    => 0,
				'height'   => 0,
				'autoplay' => 0,
				'loop'     => 0,
				'w'        => 0,
				'h'        => 0,
			),
			$atts
		)
	);

	if ( isset( $atts[0] ) ) {
		$attr['id'] = jetpack_shortcode_get_vimeo_id( $atts );
	}

	if ( ! $attr['id'] ) {
		return '<!-- vimeo error: not a vimeo video -->';
	}

	// Handle old shortcode params such as h=500&w=350.
	$params = shortcode_new_to_old_params( $atts );
	$params = str_replace( array( '&amp;', '&#038;' ), '&', $params );
	parse_str( $params, $args );

	list( $width, $height ) = jetpack_shortcode_get_vimeo_dimensions( $attr, $args );

	$url = esc_url( 'https://player.vimeo.com/video/' . $attr['id'] );

	// Handle autoplay and loop arguments.
	if (
		isset( $args['autoplay'] ) && '1' === $args['autoplay'] // Parsed from the embedded URL.
		|| $attr['autoplay']                                    // Parsed from shortcode arguments.
		|| in_array( 'autoplay', $atts, true )                  // Catch the argument passed without a value.
	) {
		$url = add_query_arg( 'autoplay', 1, $url );
	}

	if (
		isset( $args['loop'] ) && '1' === $args['loop'] // Parsed from the embedded URL.
		|| $attr['loop']                                // Parsed from shortcode arguments.
		|| in_array( 'loop', $atts, true )              // Catch the argument passed without a value.
	) {
		$url = add_query_arg( 'loop', 1, $url );
	}

	if (
		class_exists( 'Jetpack_AMP_Support' )
		&& Jetpack_AMP_Support::is_amp_request()
	) {
		$html = sprintf(
			'<amp-vimeo data-videoid="%1$s" layout="responsive" width="%2$d" height="%3$d"></amp-vimeo>',
			esc_attr( $attr['id'] ),
			absint( $width ),
			absint( $height )
		);
	} else {
		$html = sprintf(
			'<div class="embed-vimeo" style="text-align: center;"><iframe src="%1$s" width="%2$u" height="%3$u" frameborder="0" webkitallowfullscreen mozallowfullscreen allowfullscreen></iframe></div>',
			esc_url( $url ),
			esc_attr( $width ),
			esc_attr( $height )
		);
	}

	/**
	 * Filter the Vimeo player HTML.
	 *
	 * @module shortcodes
	 *
	 * @since 1.2.3
	 *
	 * @param string $html Embedded Vimeo player HTML.
	 */
	$html = apply_filters( 'video_embed_html', $html );

	return $html;
}
add_shortcode( 'vimeo', 'vimeo_shortcode' );

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
function wpcom_vimeo_embed_url( $matches, $attr, $url ) {
	$vimeo_info = array( $url );

	// If we are able to extract a video ID, use it in the shortcode instead of the full URL.
	if ( ! empty( $matches['video_id'] ) ) {
		$vimeo_info = array( 'id' => $matches['video_id'] );
	}

	return vimeo_shortcode( $vimeo_info );
}

/**
 * For bare URLs on their own line of the form.
 *
 * Accepted formats:
 * https://vimeo.com/289091934/cd1f466bcc
 * https://vimeo.com/album/2838732/video/6342264
 * https://vimeo.com/6342264
 * http://player.vimeo.com/video/18427511
 *
 * @since 3.9
 *
 * @uses wpcom_vimeo_embed_url
 */
function wpcom_vimeo_embed_url_init() {
	wp_embed_register_handler( 'wpcom_vimeo_embed_url', '#https?://(?:[^/]+\.)?vimeo\.com/(?:album/(?<album_id>\d+)/)?(?:video/)?(?<video_id>\d+)(?:/.*)?$#i', 'wpcom_vimeo_embed_url' );
}

/*
 * Register handler to modify Vimeo embeds using Jetpack's shortcode output.
 * This does not happen on WordPress.com, since embeds are handled by core there.
 */
if ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) {
	add_action( 'init', 'wpcom_vimeo_embed_url_init' );
}

/**
 * Transform a Vimeo embed iFrame into a Vimeo shortcode.
 *
 * @param string $content Post content.
 */
function vimeo_embed_to_shortcode( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'player.vimeo.com/video/' ) ) {
		return $content;
	}

	$regexp     = '!<iframe\s+src=[\'"](https?:)?//player\.vimeo\.com/video/(\d+)[\w=&;?]*[\'"]((?:\s+\w+=[\'"][^\'"]*[\'"])*)((?:[\s\w]*))></iframe>!i';
	$regexp_ent = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $regexp, ENT_NOQUOTES ) );

	foreach ( compact( 'regexp', 'regexp_ent' ) as $reg => $regexp ) {
		if ( ! preg_match_all( $regexp, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			$id = (int) $match[2];

			$params = $match[3];

			if ( 'regexp_ent' === $reg ) {
				$params = html_entity_decode( $params, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 );
			}

			$params = wp_kses_hair( $params, array( 'http' ) );

			$width  = isset( $params['width'] ) ? (int) $params['width']['value'] : 0;
			$height = isset( $params['height'] ) ? (int) $params['height']['value'] : 0;

			$wh = '';
			if ( $width && $height ) {
				$wh = ' w=' . $width . ' h=' . $height;
			}

			$shortcode = '[vimeo ' . $id . $wh . ']';
			$content   = str_replace( $match[0], $shortcode, $content );
		}
	}

	return $content;
}
add_filter( 'pre_kses', 'vimeo_embed_to_shortcode' );

/**
 * Replaces shortcodes and plain-text URLs to Vimeo videos with Vimeo embeds.
 * Covers shortcode usage [vimeo 1234] | [vimeo https://vimeo.com/1234] | [vimeo http://vimeo.com/1234]
 * Or plain text URLs https://vimeo.com/1234 | vimeo.com/1234 | //vimeo.com/1234
 * Links are left intact.
 *
 * @since 3.7.0
 * @since 3.9.5 One regular expression matches shortcodes and plain URLs.
 *
 * @param string $content HTML content.
 *
 * @return string The content with embeds instead of URLs
 */
function vimeo_link( $content ) {
	/**
	 *  [vimeo 12345]
	 *  [vimeo http://vimeo.com/12345]
	 */
	$shortcode = '(?:\[vimeo\s+[^0-9]*)([0-9]+)(?:\])';

	/**
	 * Regex to look for a Vimeo link.
	 *
	 * - http://vimeo.com/12345
	 * - https://vimeo.com/12345
	 * - //vimeo.com/12345
	 * - vimeo.com/some/descender/12345
	 *
	 *  Should not capture inside HTML attributes
	 *  [Not] <a href="vimeo.com/12345">Cool Video</a>
	 *  [Not] <a href="https://vimeo.com/12345">vimeo.com/12345</a>
	 *
	 *  Could erroneously capture:
	 *  <a href="some.link/maybe/even/vimeo">This video (vimeo.com/12345) is teh cat's meow!</a>
	 */
	$plain_url = "(?:[^'\">]?\/?(?:https?:\/\/)?vimeo\.com[^0-9]+)([0-9]+)(?:[^'\"0-9<]|$)";

	return jetpack_preg_replace_callback_outside_tags(
		sprintf( '#%s|%s#i', $shortcode, $plain_url ),
		'vimeo_link_callback',
		$content,
		'vimeo'
	);
}

/**
 * Callback function for the regex that replaces Vimeo URLs with Vimeo embeds.
 *
 * @since 3.7.0
 *
 * @param array $matches An array containing a Vimeo URL.
 * @return string The Vimeo HTML embed code.
 */
function vimeo_link_callback( $matches ) {
	$id = isset( $matches[2] ) ? $matches[2] : $matches[1];
	if ( isset( $id ) && ctype_digit( $id ) ) {
		return "\n" . vimeo_shortcode( array( 'id' => $id ) ) . "\n";
	}
	return $matches[0];
}

if (
	! is_admin()
	/** This filter is documented in modules/shortcodes/youtube.php */
	&& apply_filters( 'jetpack_comments_allow_oembed', true )
	// No need for this on WordPress.com, this is done for multiple shortcodes at a time there.
	&& ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM )
) {
	/*
	 * We attach wp_kses_post to comment_text in default-filters.php with priority of 10 anyway,
	 * so the iframe gets filtered out.
	 * Higher priority because we need it before auto-link and autop get to it
	 */
	add_filter( 'comment_text', 'vimeo_link', 1 );
}
