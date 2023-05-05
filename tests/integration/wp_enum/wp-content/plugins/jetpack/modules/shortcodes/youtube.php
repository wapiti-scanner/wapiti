<?php
/**
 * Youtube shortcode
 *
 * Contains shortcode + some improvements over the Core Embeds syntax (see http://codex.wordpress.org/Embeds )
 *
 * Examples:
 * [youtube https://www.youtube.com/watch?v=WVbQ-oro7FQ]
 * [youtube=http://www.youtube.com/watch?v=wq0rXGLs0YM&fs=1&hl=bg_BG&autohide=1&rel=0]
 * http://www.youtube.com/watch?v=H2Ncxw1xfck&w=320&h=240&fmt=1&rel=0&showsearch=1&hd=0
 * http://www.youtube.com/v/9FhMMmqzbD8?fs=1&hl=en_US
 * https://www.youtube.com/playlist?list=PLP7HaNDU4Cifov7C2fQM8Ij6Ew_uPHEXW
 *
 * @package automattic/jetpack
 */

/**
 * Replaces YouTube embeds with YouTube shortcodes.
 *
 * Covers the following formats:
 * 2008-07-15:
 * <object width="425" height="344"><param name="movie" value="http://www.youtube.com/v/bZBHZT3a-FA&hl=en&fs=1"></param><param name="allowFullScreen" value="true"></param><embed src="http://www.youtube.com/v/bZBHZT3a-FA&hl=en&fs=1" type="application/x-shockwave-flash" allowfullscreen="true" width="425" height="344"></embed></object>
 * around 2008-06-06 youtube changed their old embed code to this:
 * <object width="425" height="344"><param name="movie" value="http://www.youtube.com/v/M1D30gS7Z8U&hl=en"></param><embed src="http://www.youtube.com/v/M1D30gS7Z8U&hl=en" type="application/x-shockwave-flash" width="425" height="344"></embed></object>
 * old style was:
 * <object width="425" height="344"><param name="movie" value="http://www.youtube.com/v/dGY28Qbj76A&rel=0"></param><param name="wmode" value="transparent"></param><embed src="http://www.youtube.com/v/dGY28Qbj76A&rel=0" type="application/x-shockwave-flash" wmode="transparent" width="425" height="344"></embed></object>
 * 12-2010:
 * <object width="640" height="385"><param name="movie" value="http://www.youtube.com/v/3H8bnKdf654?fs=1&amp;hl=en_GB"></param><param name="allowFullScreen" value="true"></param><param name="allowscriptaccess" value="always"></param><embed src="http://www.youtube.com/v/3H8bnKdf654?fs=1&amp;hl=en_GB" type="application/x-shockwave-flash" allowscriptaccess="always" allowfullscreen="true" width="640" height="385"></embed></object>
 * 01-2011:
 * <iframe title="YouTube video player" class="youtube-player" width="640" height="390" src="http://www.youtube.com/embed/Qq9El3ki0_g" frameborder="0" allowFullScreen></iframe>
 * <iframe class="youtube-player" width="640" height="385" src="http://www.youtube.com/embed/VIDEO_ID" frameborder="0"></iframe>
 *
 * @param string $content HTML content.
 * @return string The content with YouTube embeds replaced with YouTube shortcodes.
 */
function youtube_embed_to_short_code( $content ) {
	if ( ! is_string( $content ) || false === strpos( $content, 'youtube.com' ) ) {
		return $content;
	}

	// older codes.
	$regexp         = '!<object(.*?)>.*?<param\s+name=[\'"]movie[\'"]\s+value=[\'"](https?:)?//www\.youtube\.com/v/([^\'"]+)[\'"].*?>.*?</object>!i';
	$regexp_ent     = htmlspecialchars( $regexp, ENT_NOQUOTES );
	$old_regexp     = '!<embed(?:\s+\w+="[^"]*")*\s+src="https?(?:\:|&#0*58;)//www\.youtube\.com/v/([^"]+)"(?:\s+\w+="[^"]*")*\s*(?:/>|>\s*</embed>)!';
	$old_regexp_ent = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $old_regexp, ENT_NOQUOTES ) );

	// new code.
	$ifr_regexp     = '!<iframe((?:\s+\w+="[^"]*")*?)\s+src="(https?:)?//(?:www\.)*youtube.com/embed/([^"]+)".*?</iframe>!i';
	$ifr_regexp_ent = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $ifr_regexp, ENT_NOQUOTES ) );

	foreach ( compact( 'regexp', 'regexp_ent', 'old_regexp', 'old_regexp_ent', 'ifr_regexp', 'ifr_regexp_ent' ) as $reg => $regexp ) {
		if ( ! preg_match_all( $regexp, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			/*
			 * Hack, but '?' should only ever appear once, and
			 * it should be for the 1st field-value pair in query string,
			 * if it is present
			 * YouTube changed their embed code.
			 * Example of how it is now:
			 * <object width="640" height="385"><param name="movie" value="http://www.youtube.com/v/aP9AaD4tgBY?fs=1&amp;hl=en_US"></param><param name="allowFullScreen" value="true"></param><param name="allowscriptaccess" value="always"></param><embed src="http://www.youtube.com/v/aP9AaD4tgBY?fs=1&amp;hl=en_US" type="application/x-shockwave-flash" allowscriptaccess="always" allowfullscreen="true" width="640" height="385"></embed></object>
			 * As shown at the start of function, previous YouTube didn't '?'
			 * the 1st field-value pair.
			 */
			if ( in_array( $reg, array( 'ifr_regexp', 'ifr_regexp_ent', 'regexp', 'regexp_ent' ), true ) ) {
				$params = $match[1];

				if ( in_array( $reg, array( 'ifr_regexp_ent', 'regexp_ent' ), true ) ) {
					$params = html_entity_decode( $params, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 );
				}

				$params = wp_kses_hair( $params, array( 'http' ) );

				$width  = isset( $params['width'] ) ? (int) $params['width']['value'] : 0;
				$height = isset( $params['height'] ) ? (int) $params['height']['value'] : 0;
				$wh     = '';

				if ( $width && $height ) {
					$wh = "&w=$width&h=$height";
				}

				$url = esc_url_raw( "https://www.youtube.com/watch?v={$match[3]}{$wh}" );
			} else {
				$match[1] = str_replace( '?', '&', $match[1] );

				$url = esc_url_raw( 'https://www.youtube.com/watch?v=' . html_entity_decode( $match[1], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 ) );
			}

			$content = str_replace( $match[0], "[youtube $url]", $content );

			/**
			 * Fires before the YouTube embed is transformed into a shortcode.
			 *
			 * @module shortcodes
			 *
			 * @since 1.2.0
			 *
			 * @param string youtube Shortcode name.
			 * @param string $url YouTube video URL.
			 */
			do_action( 'jetpack_embed_to_shortcode', 'youtube', $url );
		}
	}

	return $content;
}
add_filter( 'pre_kses', 'youtube_embed_to_short_code' );

/**
 * Replaces plain-text links to YouTube videos with YouTube embeds.
 *
 * @param string $content HTML content.
 *
 * @return string The content with embeds instead of URLs
 */
function youtube_link( $content ) {
	return jetpack_preg_replace_callback_outside_tags( '!(?:\n|\A)https?://(?:www\.)?(?:youtube.com/(?:v/|playlist|watch[/\#?])|youtu\.be/)[^\s]+?(?:\n|\Z)!i', 'youtube_link_callback', $content, 'youtube.com/' );
}

/**
 * Callback function for the regex that replaces YouTube URLs with
 * YouTube embeds.
 *
 * @param array $matches An array containing a YouTube URL.
 */
function youtube_link_callback( $matches ) {
	return "\n" . youtube_id( $matches[0] ) . "\n";
}

/**
 * Normalizes a YouTube URL to include a v= parameter and a query string free of encoded ampersands.
 *
 * @param string $url
 * @return string The normalized URL
 */
if ( ! function_exists( 'youtube_sanitize_url' ) ) :
	/**
	 * Clean up Youtube URL to match a single format.
	 *
	 * @param string $url Youtube URL.
	 */
	function youtube_sanitize_url( $url ) {
		$url = trim( $url, ' "' );
		$url = trim( $url );
		$url = str_replace( array( 'youtu.be/', '/v/', '#!v=', '&amp;', '&#038;', 'playlist' ), array( 'youtu.be/?v=', '/?v=', '?v=', '&', '&', 'videoseries' ), $url );

		// Replace any extra question marks with ampersands - the result of a URL like "http://www.youtube.com/v/9FhMMmqzbD8?fs=1&hl=en_US" being passed in.
		$query_string_start = strpos( $url, '?' );

		if ( false !== $query_string_start ) {
			$url = substr( $url, 0, $query_string_start + 1 ) . str_replace( '?', '&', substr( $url, $query_string_start + 1 ) );
		}

		return $url;
	}
endif;

/**
 * Converts a YouTube URL into an embedded YouTube video.
 *
 * URL can be:
 *    http://www.youtube.com/embed/videoseries?list=PL94269DA08231042B&amp;hl=en_US
 *    http://www.youtube.com/watch#!v=H2Ncxw1xfck
 *    http://www.youtube.com/watch?v=H2Ncxw1xfck
 *    http://www.youtube.com/watch?v=H2Ncxw1xfck&w=320&h=240&fmt=1&rel=0&showsearch=1&hd=0
 *    http://www.youtube.com/v/jF-kELmmvgA
 *    http://www.youtube.com/v/9FhMMmqzbD8?fs=1&hl=en_US
 *    http://youtu.be/Rrohlqeir5E
 *    https://www.youtube.com/watch?v=GJNxoe-iSb4&list=PLAVZ4NFtZX0fE54mDSqNKym-o_rz-8xmk
 *
 * @param string $url Youtube URL.
 */
function youtube_id( $url ) {
	$id = jetpack_get_youtube_id( $url );

	if ( ! $id ) {
		return sprintf( '<!--%s-->', esc_html__( 'YouTube Error: bad URL entered', 'jetpack' ) );
	}

	$url = youtube_sanitize_url( $url );
	$url = wp_parse_url( $url );

	$thumbnail = "https://i.ytimg.com/vi/$id/hqdefault.jpg";
	$video_url = add_query_arg( 'v', $id, 'https://www.youtube.com/watch' );

	$args = jetpack_shortcode_youtube_args( $url );
	if ( empty( $args ) ) {
		return sprintf( '<!--%s-->', esc_html__( 'YouTube Error: empty URL args', 'jetpack' ) );
	}

	// Account for URL having both v and list, where jetpack_get_youtube_id() only accounts for one or the other.
	if ( isset( $args['list'] ) && $args['list'] === $id ) {
		$id = null;
	}
	if ( isset( $args['v'] ) ) {
		$id = $args['v'];
	}
	if ( ! $id && empty( $args['list'] ) ) {
		return sprintf( '<!--%s-->', esc_html__( 'YouTube Error: missing id and/or list', 'jetpack' ) );
	}

	list( $w, $h ) = jetpack_shortcode_youtube_dimensions( $args );

	$params = array(
		'rel'            => ( isset( $args['rel'] ) && '0' === $args['rel'] ) ? 0 : 1,
		'showsearch'     => ( isset( $args['showsearch'] ) && '1' === $args['showsearch'] ) ? 1 : 0, // Now deprecated. See https://developers.google.com/youtube/player_parameters#march-29,-2012.
		'showinfo'       => ( isset( $args['showinfo'] ) && '0' === $args['showinfo'] ) ? 0 : 1, // Now obsolete. See https://developers.google.com/youtube/player_parameters#showinfo.
		'iv_load_policy' => ( isset( $args['iv_load_policy'] ) && '3' === $args['iv_load_policy'] ) ? 3 : 1,
		'fs'             => 1,
		'hl'             => str_replace( '_', '-', get_locale() ),
	);
	if ( isset( $args['fmt'] ) && (int) $args['fmt'] ) {
		$params['fmt'] = (int) $args['fmt']; // Apparently an obsolete parameter. Not referenced on https://developers.google.com/youtube/player_parameters.
	}

	// The autohide parameter has been deprecated since 2015. See https://developers.google.com/youtube/player_parameters#august-19,-2015.
	if ( ! isset( $args['autohide'] ) || ( $args['autohide'] < 0 || 2 < $args['autohide'] ) ) {
		$params['autohide'] = 2;
	} else {
		$params['autohide'] = (int) $args['autohide'];
	}

	$start = 0;
	if ( isset( $args['start'] ) ) {
		$start = (int) $args['start'];
	} elseif ( isset( $args['t'] ) ) {
		if ( is_numeric( $args['t'] ) ) {
			$start = (int) $args['t'];
		} else {
			$time_pieces = preg_split( '/(?<=\D)(?=\d+)/', $args['t'] );

			foreach ( $time_pieces as $time_piece ) {
				$int = (int) $time_piece;
				switch ( substr( $time_piece, - 1 ) ) {
					case 'h':
						$start += $int * 3600;
						break;
					case 'm':
						$start += $int * 60;
						break;
					case 's':
						$start += $int;
						break;
				}
			}
		}
	}
	if ( $start ) {
		$params['start'] = (int) $start;
	}

	if ( isset( $args['end'] ) && (int) $args['end'] ) {
		$params['end'] = (int) $args['end'];
	}
	if ( isset( $args['hd'] ) && (int) $args['hd'] ) {
		$params['hd'] = (int) $args['hd']; // Now obsolete per https://developers.google.com/youtube/player_parameters#march-29,-2012.
	}
	if ( isset( $args['vq'] ) && in_array( $args['vq'], array( 'hd720', 'hd1080' ), true ) ) {
		$params['vq'] = $args['vq']; // Note, this appears to be obsolete. Not referenced on https://developers.google.com/youtube/player_parameters.
	}
	if ( isset( $args['cc_load_policy'] ) ) {
		$params['cc_load_policy'] = 1;
	}
	if ( isset( $args['cc_lang_pref'] ) ) {
		$params['cc_lang_pref'] = preg_replace( '/[^_a-z0-9-]/i', '', $args['cc_lang_pref'] );
	}

	// The wmode parameter appears to be obsolete. Not referenced on https://developers.google.com/youtube/player_parameters.
	if ( isset( $args['wmode'] ) && in_array( strtolower( $args['wmode'] ), array( 'opaque', 'window', 'transparent' ), true ) ) {
		$params['wmode'] = $args['wmode'];
	} else {
		$params['wmode'] = 'transparent';
	}

	// The theme parameter is obsolete per https://developers.google.com/youtube/player_parameters#august-19,-2015.
	if ( isset( $args['theme'] ) && in_array( strtolower( $args['theme'] ), array( 'dark', 'light' ), true ) ) {
		$params['theme'] = $args['theme'];
	}

	if ( isset( $args['list'] ) ) {
		$params['listType'] = 'playlist';
		$params['list']     = preg_replace( '|[^_a-z0-9-]|i', '', $args['list'] );
	}

	/**
	 * Allow YouTube videos to start playing automatically.
	 *
	 * @module shortcodes
	 *
	 * @since 2.2.2
	 *
	 * @param bool false Enable autoplay for YouTube videos.
	 */
	if ( apply_filters( 'jetpack_youtube_allow_autoplay', false ) && isset( $args['autoplay'] ) ) {
		$params['autoplay'] = (int) $args['autoplay'];
	}

	$is_amp = class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request();

	if ( $is_amp && $id ) {
		// Note that <amp-youtube> currently is not well suited for playlists that don't have an individual video selected, hence the $id check above.
		$placeholder = sprintf(
			'<a href="%1$s" placeholder><amp-img src="%2$s" alt="%3$s" layout="fill" object-fit="cover"><noscript><img src="%2$s" loading="lazy" decoding="async" alt="%3$s"></noscript></amp-img></a>',
			esc_url( $video_url ),
			esc_url( $thumbnail ),
			esc_attr__( 'YouTube Poster', 'jetpack' ) // Would be preferable to provide YouTube video title, but not available in this non-oEmbed context.
		);

		$html_attributes = array();
		foreach ( $params as $param_name => $param_value ) {
			$html_attributes[] = sprintf(
				'data-param-%s="%s"',
				sanitize_key( $param_name ),
				esc_attr( $param_value )
			);
		}

		$html = sprintf(
			'<amp-youtube data-videoid="%s" %s width="%d" height="%d" layout="responsive">%s</amp-youtube>',
			esc_attr( $id ),
			implode( ' ', $html_attributes ), // Note: Escaping done above.
			esc_attr( $w ),
			esc_attr( $h ),
			$placeholder
		);
	} else {
		// In AMP, the AMP_Iframe_Sanitizer will convert into <amp-iframe> as required.
		$src = 'https://www.youtube.com/embed';
		if ( $id ) {
			$src .= "/$id";
		}
		$src = add_query_arg(
			array_merge(
				array( 'version' => 3 ),
				$params
			),
			$src
		);

		$layout = $is_amp ? 'layout="responsive" ' : '';

		$html = sprintf(
			'<iframe class="youtube-player" width="%s" height="%s" %ssrc="%s" allowfullscreen="true" style="border:0;" sandbox="allow-scripts allow-same-origin allow-popups allow-presentation"></iframe>',
			esc_attr( $w ),
			esc_attr( $h ),
			$layout,
			esc_url( $src )
		);
	}

	// Let's do some alignment wonder in a span, unless we're producing a feed.
	if ( ! is_feed() ) {
		$alignmentcss = 'text-align:center;';
		if ( isset( $args['align'] ) ) {
			switch ( $args['align'] ) {
				case 'left':
					$alignmentcss = "float:left; width:{$w}px; height:{$h}px; margin-right:10px; margin-bottom: 10px;";
					break;
				case 'right':
					$alignmentcss = "float:right; width:{$w}px; height:{$h}px; margin-left:10px; margin-bottom: 10px;";
					break;
			}
		}

		$html = sprintf(
			'<span class="embed-youtube" style="%s display: block;">%s</span>',
			esc_attr( $alignmentcss ),
			$html
		);

	}

	/**
	 * Format output for Calypso Reader/Notifications/Comments
	 */
	if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
		require_once WP_CONTENT_DIR . '/lib/display-context.php';
		$context = A8C\Display_Context\get_current_context();
		if ( A8C\Display_Context\NOTIFICATIONS === $context ) {
			return sprintf(
				'<a href="%1$s" target="_blank" rel="noopener noreferrer"><img src="%2$s" alt="%3$s" /></a>',
				esc_url( $video_url ),
				esc_url( $thumbnail ),
				esc_html__( 'YouTube video', 'jetpack' )
			);
		}
	}

	/**
	 * Filter the YouTube video HTML output.
	 *
	 * @module shortcodes
	 *
	 * @since 1.2.3
	 *
	 * @param string $html YouTube video HTML output.
	 */
	$html = apply_filters( 'video_embed_html', $html );

	return $html;
}

/**
 * Gets the args present in the YouTube shortcode URL.
 *
 * @since 8.0.0
 *
 * @param array $url The parsed URL of the shortcode.
 *
 * @return array|false The query args of the URL, or false.
 */
function jetpack_shortcode_youtube_args( $url ) {
	$qargs = array();
	if ( ! empty( $url['query'] ) ) {
		wp_parse_str( $url['query'], $qargs );
	} else {
		return false;
	}

	$fargs = array();
	if ( ! empty( $url['fragment'] ) ) {
		wp_parse_str( $url['fragment'], $fargs );
	}

	return array_merge( $fargs, $qargs );
}

/**
 * Display the Youtube shortcode.
 *
 * @param array $atts Shortcode attributes.
 *
 * @return string The rendered shortcode.
 */
function youtube_shortcode( $atts ) {
	$url = ( isset( $atts[0] ) ) ? ltrim( $atts[0], '=' ) : shortcode_new_to_old_params( $atts );
	return youtube_id( $url );
}
add_shortcode( 'youtube', 'youtube_shortcode' );

/**
 * Gets the dimensions of the [youtube] shortcode.
 *
 * Calculates the width and height, taking $content_width into consideration.
 *
 * @since 8.0.0
 *
 * @param array $query_args The query args of the URL.
 *
 * @return array The width and height of the shortcode.
 */
function jetpack_shortcode_youtube_dimensions( $query_args ) {
	global $content_width;

	$input_w = ( isset( $query_args['w'] ) && (int) $query_args['w'] ) ? (int) $query_args['w'] : 0;
	$input_h = ( isset( $query_args['h'] ) && (int) $query_args['h'] ) ? (int) $query_args['h'] : 0;

	// If we have $content_width, use it.
	if ( ! empty( $content_width ) ) {
		$default_width = $content_width;
	} else {
		// Otherwise get default width from the old, now deprecated embed_size_w option.
		$default_width = get_option( 'embed_size_w' );
	}

	// If we don't know those 2 values use a hardcoded width.
	if ( empty( $default_width ) ) {
		$default_width = 640;
	}

	if ( $input_w > 0 && $input_h > 0 ) {
		$w = $input_w;
		$h = $input_h;
	} elseif ( 0 === $input_w && 0 === $input_h ) {
		if ( isset( $query_args['fmt'] ) && (int) $query_args['fmt'] ) {
			$w = ( ! empty( $content_width ) ? min( $content_width, 480 ) : 480 );
		} else {
			$w = ( ! empty( $content_width ) ? min( $content_width, $default_width ) : $default_width );
			$h = ceil( ( $w / 16 ) * 9 );
		}
	} elseif ( $input_w > 0 ) {
		$w = $input_w;
		$h = ceil( ( $w / 16 ) * 9 );
	} elseif ( isset( $query_args['fmt'] ) && (int) $query_args['fmt'] ) {
		$w = ( ! empty( $content_width ) ? min( $content_width, 480 ) : 480 );
	} else {
		$w = ( ! empty( $content_width ) ? min( $content_width, $default_width ) : $default_width );
		$h = $input_h;
	}

	/**
	 * Filter the YouTube player width.
	 *
	 * @module shortcodes
	 *
	 * @since 1.1.0
	 *
	 * @param int $w Width of the YouTube player in pixels.
	 */
	$w = (int) apply_filters( 'youtube_width', $w );

	/**
	 * Filter the YouTube player height.
	 *
	 * @module shortcodes
	 *
	 * @since 1.1.0
	 *
	 * @param int $h Height of the YouTube player in pixels.
	 */
	$h = (int) apply_filters( 'youtube_height', $h );

	return array( $w, $h );
}

/**
 * For bare URLs on their own line of the form
 * http://www.youtube.com/v/9FhMMmqzbD8?fs=1&hl=en_US
 *
 * @param array $matches Regex partial matches against the URL passed.
 * @param array $attr    Attributes received in embed response.
 * @param array $url     Requested URL to be embedded.
 */
function wpcom_youtube_embed_crazy_url( $matches, $attr, $url ) {
	return youtube_id( $url );
}

/**
 * Add a new handler to automatically transform custom Youtube URLs (like playlists) into embeds.
 */
function wpcom_youtube_embed_crazy_url_init() {
	wp_embed_register_handler( 'wpcom_youtube_embed_crazy_url', '#https?://(?:www\.)?(?:youtube.com/(?:v/|playlist|watch[/\#?])|youtu\.be/).*#i', 'wpcom_youtube_embed_crazy_url' );
}
add_action( 'init', 'wpcom_youtube_embed_crazy_url_init' );

if (
	! is_admin()
	/**
	 * Allow oEmbeds in Jetpack's Comment form.
	 *
	 * @module shortcodes
	 *
	 * @since 2.8.0
	 *
	 * @param int $allow_oembed Option to automatically embed all plain text URLs.
	 */
	&& apply_filters( 'jetpack_comments_allow_oembed', true )
	// No need for this on WordPress.com, this is done for multiple shortcodes at a time there.
	&& ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM )
) {
	/*
	 * We attach wp_kses_post to comment_text in default-filters.php with priority of 10 anyway,
	 * so the iframe gets filtered out.
	 * Higher priority because we need it before auto-link and autop get to it.
	 */
	add_filter( 'comment_text', 'youtube_link', 1 );
}

/**
 * Core changes to do_shortcode (https://core.trac.wordpress.org/changeset/34747) broke "improper" shortcodes
 * with the format [shortcode=http://url.com].
 *
 * This removes the "=" from the shortcode so it can be parsed.
 *
 * @see https://github.com/Automattic/jetpack/issues/3121
 *
 * @param string $content HTML content.
 */
function jetpack_fix_youtube_shortcode_display_filter( $content ) {
	if ( strpos( $content, '[youtube=' ) !== false ) {
		$content = preg_replace( '@\[youtube=(.*?)\]@', '[youtube $1]', $content );
	}

	return $content;
}
add_filter( 'the_content', 'jetpack_fix_youtube_shortcode_display_filter', 7 );
