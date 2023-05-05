<?php
/**
 * Dailymotion code
 *
 * @package automattic/jetpack
 */

/**
 * Original codes:
 *
 * <embed height="270" type="application/x-shockwave-flash" width="480" src="http&#58;//www.dailymotion.com/swf/video/xekmrq?additionalInfos=0" wmode="opaque" pluginspage="http&#58;//www.macromedia.com/go/getflashplayer" allowscriptaccess="never" allownetworking="internal" />
 *
 * <object width="480" height="240"><param name="movie" value="http://www.dailymotion.com/swf/video/xen4ms_ghinzu-cold-love-mirror-mirror_music?additionalInfos=0"></param><param name="allowFullScreen" value="true"></param><param name="allowScriptAccess" value="always"></param>
 *  <embed type="application/x-shockwave-flash" src="http://www.dailymotion.com/swf/video/xen4ms_ghinzu-cold-love-mirror-mirror_music?additionalInfos=0" width="480" height="240" allowfullscreen="true" allowscriptaccess="always"></embed>
 * </object><br /><b><a href="http://www.dailymotion.com/video/xen4ms_ghinzu-cold-love-mirror-mirror_music">Ghinzu - Cold Love (Mirror Mirror)</a></b><br /><i>Uploaded by <a href="http://www.dailymotion.com/GhinzuTV">GhinzuTV</a>. - <a href="http://www.dailymotion.com/us/channel/music">Watch more music videos, in HD!</a></i>
 *
 * Code as of 01.01.11:
 * <object width="560" height="421"><param name="movie" value="http://www.dailymotion.com/swf/video/xaose5?width=560&theme=denim&foreground=%2392ADE0&highlight=%23A2ACBF&background=%23202226&start=&animatedTitle=&iframe=0&additionalInfos=0&autoPlay=0&hideInfos=0"></param><param name="allowFullScreen" value="true"></param><param name="allowScriptAccess" value="always"></param><embed type="application/x-shockwave-flash" src="http://www.dailymotion.com/swf/video/xaose5?width=560&theme=denim&foreground=%2392ADE0&highlight=%23A2ACBF&background=%23202226&start=&animatedTitle=&iframe=0&additionalInfos=0&autoPlay=0&hideInfos=0" width="560" height="421" allowfullscreen="true" allowscriptaccess="always"></embed></object><br /><b><a href="http://www.dailymotion.com/video/x29zm17_funny-videos-of-cats-and-babies-compilation-2015_fun">Funny cats and babies!</a></b><br /><i>Uploaded by <a href="http://www.dailymotion.com/GilLavie">GilLavie</a>. - <a target="_self" href="http://www.dailymotion.com/channel/funny/featured/1">Find more funny videos.</a></i>
 * movie param enforces anti-xss protection
 *
 * Scroll down for the new <iframe> embed code handler.
 *
 * @param string $content Post content.
 */
function dailymotion_embed_to_shortcode( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'www.dailymotion.com/swf/' ) ) {
		return $content;
	}

	$regexp     = '!<object.*>\s*(<param.*></param>\s*)*<embed((?:\s+\w+="[^"]*")*)\s+src="http(?:\:|&#0*58;)//(www\.dailymotion\.com/swf/[^"]*)"((?:\s+\w+="[^"]*")*)\s*(?:/>|>\s*</embed>)\s*</object><br /><b><a .*>.*</a></b><br /><i>.*</i>!';
	$regexp_ent = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $regexp, ENT_NOQUOTES ) );

	foreach ( compact( 'regexp', 'regexp_ent' ) as $reg => $regexp ) {
		if ( ! preg_match_all( $regexp, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			$src    = html_entity_decode( $match[3], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 );
			$params = $match[2] . $match[4];

			if ( 'regexp_ent' === $reg ) {
				$src    = html_entity_decode( $src, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 );
				$params = html_entity_decode( $params, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 );
			}

			$params = wp_kses_hair( $params, array( 'http' ) );

			if ( ! isset( $params['type'] ) || 'application/x-shockwave-flash' !== $params['type']['value'] ) {
				continue;
			}

			$id = basename( substr( $src, strlen( 'www.dailymotion.com/swf' ) ) );
			$id = preg_replace( '/[^a-z0-9].*$/is', '', $id );

			$content = str_replace( $match[0], "[dailymotion id=$id]", $content );
			/** This action is documented in modules/shortcodes/youtube.php */
			do_action( 'jetpack_embed_to_shortcode', 'dailymotion', $id );
		}
	}
	return $content;
}
add_filter( 'pre_kses', 'dailymotion_embed_to_shortcode' );

/**
 * DailyMotion shortcode
 *
 * The documented shortcode is:
 * [dailymotion id=x8oma9]
 *
 * Possibilities, according to the old parsing regexp:
 * [dailymotion x8oma9]
 * [dailymotion=x8oma9]
 *
 * Hypothetical option, according to the old shortcode function is
 * [dailymotion id=1&title=2&user=3&video=4]
 *
 * The new style is now:
 * [dailymotion id=x8oma9 title=2 user=3 video=4]
 *
 * Supported parameters for player customization: width, height,
 * autoplay, endscreen-enable, mute, sharing-enabled, start, subtitles-default,
 * ui-highlight, ui-logo, ui-start-screen-info, ui-theme
 * see https://developer.dailymotion.com/player#player-parameters
 *
 * @todo: Update code to sniff for iframe embeds and convert those to shortcodes.
 *
 * @param array $atts Shortcode attributes.
 *
 * @return string html
 */
function dailymotion_shortcode( $atts ) {
	global $content_width;

	if ( isset( $atts[0] ) ) {
		$id         = ltrim( $atts[0], '=' );
		$atts['id'] = $id;

	} else {
		$params = shortcode_new_to_old_params( $atts );
		parse_str( $params, $atts_new );

		foreach ( $atts_new as $k => $v ) {
			$atts[ $k ] = $v;
		}
	}

	$atts = shortcode_atts(
		array(
			'id'                   => '', // string.
			'width'                => '', // int.
			'height'               => '', // int.
			'title'                => '', // string.
			'user'                 => '', // string.
			'video'                => '', // string.
			'autoplay'             => 0,  // int.
			'endscreen-enable'     => 1,  // int.
			'mute'                 => 0,  // int.
			'sharing-enable'       => 1,  // int.
			'start'                => '', // int.
			'subtitles-default'    => '', // string.
			'ui-highlight'         => '', // string.
			'ui-logo'              => 1,  // int.
			'ui-start-screen-info' => 0,  // int.
			'ui-theme'             => '', // string.
		),
		$atts,
		'dailymotion'
	);

	if ( isset( $atts['id'] ) && ! empty( $atts['id'] ) ) {
		$id = rawurlencode( $atts['id'] );
	} else {
		return '<!--Dailymotion error: bad or missing ID-->';
	}

	/*set width and height using provided parameters if any */
	$width  = isset( $atts['width'] ) ? (int) $atts['width'] : 0;
	$height = isset( $atts['height'] ) ? (int) $atts['height'] : 0;

	if ( ! $width && ! $height ) {
		if ( ! empty( $content_width ) ) {
			$width = absint( $content_width );
		} else {
			$width = 425;
		}
		$height = $width / 425 * 334;
	} elseif ( ! $height ) {
		$height = $width / 425 * 334;
	} elseif ( ! $width ) {
		$width = $height / 334 * 425;
	}

	if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
		return sprintf(
			'<amp-dailymotion data-videoid="%1$s" layout="responsive" width="%2$d" height="%3$d"></amp-dailymotion>',
			esc_attr( $id ),
			absint( $width ),
			absint( $height )
		);
	}

	/**
	 * Let's add parameters if needed.
	 *
	 * @see https://developer.dailymotion.com/player
	 */
	$player_params = array();

	if ( isset( $atts['autoplay'] ) && '1' === $atts['autoplay'] ) {
		$player_params['autoplay'] = '1';
	}
	if ( isset( $atts['endscreen-enable'] ) && '0' === $atts['endscreen-enable'] ) {
		$player_params['endscreen-enable'] = '0';
	}
	if ( isset( $atts['mute'] ) && '1' === $atts['mute'] ) {
		$player_params['mute'] = '1';
	}
	if ( isset( $atts['sharing-enable'] ) && '0' === $atts['sharing-enable'] ) {
		$player_params['sharing-enable'] = '0';
	}
	if ( isset( $atts['start'] ) && ! empty( $atts['start'] ) ) {
		$player_params['start'] = abs( (int) $atts['start'] );
	}
	if ( isset( $atts['subtitles-default'] ) && ! empty( $atts['subtitles-default'] ) ) {
		$player_params['subtitles-default'] = esc_attr( $atts['subtitles-default'] );
	}
	if ( isset( $atts['ui-highlight'] ) && ! empty( $atts['ui-highlight'] ) ) {
		$player_params['ui-highlight'] = esc_attr( $atts['ui-highlight'] );
	}
	if ( isset( $atts['ui-logo'] ) && '0' === $atts['ui-logo'] ) {
		$player_params['ui-logo'] = '0';
	}
	if ( isset( $atts['ui-start-screen-info'] ) && '0' === $atts['ui-start-screen-info'] ) {
		$player_params['ui-start-screen-info'] = '0';
	}
	if ( isset( $atts['ui-theme'] ) && in_array( strtolower( $atts['ui-theme'] ), array( 'dark', 'light' ), true ) ) {
		$player_params['ui-theme'] = esc_attr( $atts['ui-theme'] );
	}

	// Add those parameters to the Video URL.
	$video_url = add_query_arg(
		$player_params,
		'https://www.dailymotion.com/embed/video/' . $id
	);

	$output = '';

	if ( preg_match( '/^[A-Za-z0-9]+$/', $id ) ) {
		$output .= '<iframe width="' . esc_attr( $width ) . '" height="' . esc_attr( $height ) . '" src="' . esc_url( $video_url ) . '" style="border:0;" allowfullscreen></iframe>';

		$video = preg_replace( '/[^-a-z0-9_]/i', '', $atts['video'] );
		$title = wp_kses( $atts['title'], array() );
		if (
			array_key_exists( 'video', $atts )
			&& $video
			&& array_key_exists( 'title', $atts )
			&& $title
		) {
			$output .= '<br /><strong><a href="' . esc_url( 'https://www.dailymotion.com/video/' . $video ) . '" target="_blank">' . esc_html( $title ) . '</a></strong>';
		}

		$user = preg_replace( '/[^-a-z0-9_]/i', '', $atts['user'] );
		if ( array_key_exists( 'user', $atts ) && $user ) {
			/* translators: %s is a Dailymotion user name */
			$output .= '<br /><em>' . wp_kses(
				sprintf(
					/* Translators: placeholder is a Dailymotion username, linking to a Dailymotion profile page. */
					__( 'Uploaded by %s', 'jetpack' ),
					'<a href="' . esc_url( 'https://www.dailymotion.com/' . $user ) . '" target="_blank">' . esc_html( $user ) . '</a>'
				),
				array(
					'a' => array(
						'href'   => true,
						'target' => true,
					),
				)
			) . '</em>';
		}
	}

	/**
	 * Calypso Helper
	 *
	 * Makes shortcode output responsive to the location it is loaded:
	 * Notifications, Reader, Email
	 */
	if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
		require_once WP_CONTENT_DIR . '/lib/display-context.php';
		$context = A8C\Display_Context\get_current_context();

		// Notifications.
		if ( A8C\Display_Context\NOTIFICATIONS === $context ) {
			return sprintf(
				'<a href="%1$s" target="_blank" rel="noopener noreferrer">%1$s</a>',
				esc_url( 'https://www.dailymotion.com/video/' . $id )
			);
		}
	}

	return $output;
}
add_shortcode( 'dailymotion', 'dailymotion_shortcode' );

/**
 * DailyMotion Channel Shortcode
 *
 * Examples:
 * [dailymotion-channel user=MatthewDominick]
 * [dailymotion-channel user=MatthewDominick type=grid] (supports grid, carousel, badge/default)
 *
 * @param array $atts Shortcode attributes.
 */
function dailymotion_channel_shortcode( $atts ) {
	$username = $atts['user'];

	switch ( $atts['type'] ) {
		case 'grid':
			$channel_iframe = '<iframe sandbox="allow-popups allow-scripts allow-same-origin allow-presentation" width="300px" height="264px" scrolling="no" style="border:0;" src="' . esc_url( '//www.dailymotion.com/badge/user/' . $username . '?type=grid' ) . '"></iframe>';
			break;
		case 'carousel':
			$channel_iframe = '<iframe sandbox="allow-popups allow-scripts allow-same-origin allow-presentation" width="300px" height="360px" scrolling="no" style="border:0;" src="' . esc_url( '//www.dailymotion.com/badge/user/' . $username . '?type=carousel' ) . '"></iframe>';
			break;
		default:
			$channel_iframe = '<iframe sandbox="allow-popups allow-scripts allow-same-origin allow-presentation" width="300px" height="78px" scrolling="no" style="border:0;" src="' . esc_url( '//www.dailymotion.com/badge/user/' . $username ) . '"></iframe>';
	}

	return $channel_iframe;
}
add_shortcode( 'dailymotion-channel', 'dailymotion_channel_shortcode' );

/**
 * Embed Reversal for Badge/Channel
 *
 * @param string $content Post content.
 */
function dailymotion_channel_reversal( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'dailymotion.com/badge/' ) ) {
		return $content;
	}

	/*
	 * Sample embed code:
	 * <iframe width="300px" height="360px" scrolling="no" frameborder="0" src="http://www.dailymotion.com/badge/user/Dailymotion?type=carousel"></iframe>
	*/

	$regexes = array();

	$regexes[] = '#<iframe[^>]+?src=" (?:https?:)?//(?:www\.)?dailymotion\.com/badge/user/([^"\'/]++) "[^>]*+></iframe>#ix';

	// Let's play nice with the visual editor too.
	$regexes[] = '#&lt;iframe(?:[^&]|&(?!gt;))+?src=" (?:https?:)?//(?:www\.)?dailymotion\.com/badge/user/([^"\'/]++) "(?:[^&]|&(?!gt;))*+&gt;&lt;/iframe&gt;#ix';

	foreach ( $regexes as $regex ) {
		if ( ! preg_match_all( $regex, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			$url_pieces = wp_parse_url( $match[1] );

			if ( 'type=carousel' === $url_pieces['query'] ) {
				$type = 'carousel';
			} elseif ( 'type=grid' === $url_pieces['query'] ) {
				$type = 'grid';
			} else {
				$type = 'badge';
			}

			$shortcode     = '[dailymotion-channel user=' . esc_attr( $url_pieces['path'] ) . ' type=' . esc_attr( $type ) . ']';
			$replace_regex = sprintf( '#\s*%s\s*#', preg_quote( $match[0], '#' ) );
			$content       = preg_replace( $replace_regex, sprintf( "\n\n%s\n\n", $shortcode ), $content );
		}
	}

	return $content;
}
add_filter( 'pre_kses', 'dailymotion_channel_reversal' );

/**
 * Dailymotion Embed Reversal (with new iframe code as of 17.09.2014)
 *
 * Converts a generic HTML embed code from Dailymotion into an
 * oEmbeddable URL.
 *
 * @param string $content Post content.
 */
function jetpack_dailymotion_embed_reversal( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'dailymotion.com/embed' ) ) {
		return $content;
	}

	/*
	 * Sample embed code as of Sep 17th 2014:
	 * <iframe frameborder="0" width="480" height="270" src="//www.dailymotion.com/embed/video/x25x71x" allowfullscreen></iframe><br /><a href="http://www.dailymotion.com/video/x25x71x_dog-with-legs-in-casts-learns-how-to-enter-the-front-door_animals" target="_blank">Dog with legs in casts learns how to enter the...</a> <i>by <a href="http://www.dailymotion.com/videobash" target="_blank">videobash</a></i>
	*/
	$regexes = array();

	// I'm Konstantin and I love regex.
	$regexes[] = '#<iframe[^>]+?src=" (?:https?:)?//(?:www\.)?dailymotion\.com/embed/video/([^"\'/]++) "[^>]*+>\s*+</iframe>\s*+(?:<br\s*+/>)?\s*+
	(?: <a[^>]+?href=" (?:https?:)?//(?:www\.)?dailymotion\.com/[^"\']++ "[^>]*+>.+?</a>\s*+ )?
	(?: <i>.*?<a[^>]+?href=" (?:https?:)?//(?:www\.)?dailymotion\.com/[^"\']++ "[^>]*+>.+?</a>\s*+</i> )?#ix';

	$regexes[] = '#&lt;iframe(?:[^&]|&(?!gt;))+?src=" (?:https?:)?//(?:www\.)?dailymotion\.com/embed/video/([^"\'/]++) "(?:[^&]|&(?!gt;))*+&gt;\s*+&lt;/iframe&gt;\s*+(?:&lt;br\s*+/&gt;)?\s*+
	(?: &lt;a(?:[^&]|&(?!gt;))+?href=" (?:https?:)?//(?:www\.)?dailymotion\.com/[^"\']++ "(?:[^&]|&(?!gt;))*+&gt;.+?&lt;/a&gt;\s*+ )?
	(?: &lt;i&gt;.*?&lt;a(?:[^&]|&(?!gt;))+?href=" (?:https?:)?//(?:www\.)?dailymotion\.com/[^"\']++ "(?:[^&]|&(?!gt;))*+&gt;.+?&lt;/a&gt;\s*+&lt;/i&gt; )?#ix';

	foreach ( $regexes as $regex ) {
		if ( ! preg_match_all( $regex, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			$url           = esc_url( sprintf( 'https://dailymotion.com/video/%s', $match[1] ) );
			$replace_regex = sprintf( '#\s*%s\s*#', preg_quote( $match[0], '#' ) );
			$content       = preg_replace( $replace_regex, sprintf( "\n\n%s\n\n", $url ), $content );

			/** This action is documented in modules/shortcodes/youtube.php */
			do_action( 'jetpack_embed_to_shortcode', 'dailymotion', $url );
		}
	}

	return $content;
}
add_filter( 'pre_kses', 'jetpack_dailymotion_embed_reversal' );
