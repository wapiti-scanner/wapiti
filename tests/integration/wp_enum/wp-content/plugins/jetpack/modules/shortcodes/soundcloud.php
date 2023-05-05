<?php
/**
 * SoundCloud Shortcode
 * Based on this plugin: https://wordpress.org/plugins/soundcloud-shortcode/
 *
 * Credits:
 * Original version: Johannes Wagener <johannes@soundcloud.com>
 * Options support: Tiffany Conroy <tiffany@soundcloud.com>
 * HTML5 & oEmbed support: Tim Bormans <tim@soundcloud.com>
 *
 * Examples:
 * [soundcloud]http://soundcloud.com/forss/flickermood[/soundcloud]
 * [soundcloud url="https://api.soundcloud.com/tracks/156661852" params="auto_play=false&amp;hide_related=false&amp;visual=false" width="100%" height="450" iframe="true" /]
 * [soundcloud url="https://api.soundcloud.com/tracks/156661852" params="auto_play=false&amp;hide_related=false&amp;visual=true" width="100%" height="450" iframe="true" /]
 * [soundcloud url="https://soundcloud.com/closetorgan/paul-is-dead" width=400 height=400]
 * [soundcloud url="https://soundcloud.com/closetorgan/sets/smells-like-lynx-africa-private"]
 * [soundcloud url="https://soundcloud.com/closetorgan/sets/smells-like-lynx-africa-private" color="00cc11"]
 * <iframe width="100%" height="450" scrolling="no" frameborder="no" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/150745932&amp;auto_play=false&amp;hide_related=false&amp;show_comments=true&amp;show_user=true&amp;show_reposts=false&amp;visual=true"></iframe>
 *
 * @package automattic/jetpack
 */

/**
 * SoundCloud shortcode handler
 *
 * @param  string|array $atts        The attributes passed to the shortcode like [soundcloud attr1="value" /].
 *                                   Is an empty string when no arguments are given.
 * @param  string       $content     The content between non-self closing [soundcloud]...[/soundcloud] tags.
 *
 * @return string                  Widget embed code HTML
 */
function soundcloud_shortcode( $atts, $content = null ) {
	global $wp_embed;

	// Custom shortcode options.
	$shortcode_options = array_merge(
		array( 'url' => trim( $content ) ),
		is_array( $atts ) ? $atts : array()
	);

	// The "url" option is required.
	if ( empty( $shortcode_options['url'] ) ) {
		if ( current_user_can( 'edit_posts' ) ) {
			return esc_html__( 'Please specify a Soundcloud URL.', 'jetpack' );
		} else {
			return '<!-- Missing Soundcloud URL -->';
		}
	}

	// If the shortcode is displayed in a WPCOM notification, display a simple link only.
	if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
		require_once WP_CONTENT_DIR . '/lib/display-context.php';
		$context = A8C\Display_Context\get_current_context();
		if ( A8C\Display_Context\NOTIFICATIONS === $context ) {
			return sprintf(
				'<a href="%1$s" target="_blank" rel="noopener noreferrer">%1$s</a>',
				esc_url( $shortcode_options['url'] )
			);
		}
	}

	// Turn shortcode option "param" (param=value&param2=value) into array of params.
	$shortcode_params = array();
	if ( isset( $shortcode_options['params'] ) ) {
		parse_str( html_entity_decode( $shortcode_options['params'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 ), $shortcode_params );
		$shortcode_options = array_merge(
			$shortcode_options,
			$shortcode_params
		);
		unset( $shortcode_options['params'] );
	}

	$options = shortcode_atts(
		// This list used to include an 'iframe' option. We don't include it anymore as we don't support the Flash player anymore.
		array(
			'url'           => '',
			'width'         => soundcloud_get_option( 'player_width' ),
			'height'        => soundcloud_url_has_tracklist( $shortcode_options['url'] ) ? soundcloud_get_option( 'player_height_multi' ) : soundcloud_get_option( 'player_height' ),
			'auto_play'     => soundcloud_get_option( 'auto_play' ),
			'hide_related'  => false,
			'visual'        => false,
			'show_comments' => soundcloud_get_option( 'show_comments' ),
			'color'         => soundcloud_get_option( 'color' ),
			'show_user'     => false,
			'show_reposts'  => false,
		),
		$shortcode_options,
		'soundcloud'
	);

	// "width" needs to be an integer.
	if ( ! empty( $options['width'] ) && ! preg_match( '/^\d+$/', $options['width'] ) ) {
		// set to 0 so oEmbed will use the default 100% and WordPress themes will leave it alone.
		$options['width'] = 0;
	}
	// Set default width if not defined.
	$width = ! empty( $options['width'] ) ? absint( $options['width'] ) : '100%';

	// Set default height if not defined.
	if (
		empty( $options['height'] )
		|| (
			// "height" needs to be an integer.
			! empty( $options['height'] )
			&& ! preg_match( '/^\d+$/', $options['height'] )
		)
	) {
		if (
			soundcloud_url_has_tracklist( $options['url'] )
			|| 'true' === $options['visual']
		) {
			$height = 450;
		} else {
			$height = 166;
		}
	} else {
		$height = absint( $options['height'] );
	}

	// Set visual to false when displaying the smallest player.
	if ( '20' === $options['height'] ) {
		$options['visual'] = false;
	}

	if (
		class_exists( 'Jetpack_AMP_Support' )
		&& Jetpack_AMP_Support::is_amp_request()
		&& ! empty( $options['url'] )
		&& 'api.soundcloud.com' !== wp_parse_url( $options['url'], PHP_URL_HOST )
	) {
		// Defer to oEmbed if an oEmbeddable URL is provided.
		return $wp_embed->shortcode( $options, $options['url'] );
	}

	// Build our list of Soundcloud parameters.
	$query_args = array(
		'url' => rawurlencode( $options['url'] ),
	);

	// Add our options, if they are set to true or false.
	foreach ( $options as $name => $value ) {
		if ( 'true' === $value ) {
			$query_args[ $name ] = 'true';
		}

		if ( 'false' === $value || false === $value ) {
			$query_args[ $name ] = 'false';
		}
	}

	// Add the color parameter if it was specified and is a valid color.
	if ( ! empty( $options['color'] ) ) {
		$color = sanitize_hex_color_no_hash( $options['color'] );
		if ( ! empty( $color ) ) {
			$query_args['color'] = $color;
		}
	}

	// Build final embed URL.
	$url = add_query_arg(
		$query_args,
		'https://w.soundcloud.com/player/'
	);

	return sprintf(
		'<iframe width="%1$s" height="%2$d" scrolling="no" frameborder="no" src="%3$s"></iframe>',
		esc_attr( $width ),
		esc_attr( $height ),
		$url
	);
}
add_shortcode( 'soundcloud', 'soundcloud_shortcode' );

/**
 * Plugin options getter
 *
 * @param  string|array $option  Option name.
 * @param  mixed        $default Default value.
 *
 * @return mixed                   Option value
 */
function soundcloud_get_option( $option, $default = false ) {
	$value = get_option( 'soundcloud_' . $option );

	return '' === $value ? $default : $value;
}

/**
 * Decide if a url has a tracklist
 *
 * @param string $url Soundcloud URL.
 *
 * @return boolean
 */
function soundcloud_url_has_tracklist( $url ) {
	return preg_match( '/^(.+?)\/(sets|groups|playlists)\/(.+?)$/', $url );
}

/**
 * SoundCloud Embed Reversal
 *
 * Converts a generic HTML embed code from SoundClound into a
 * WordPress.com-compatibly shortcode.
 *
 * @param string $content HTML content.
 *
 * @return string Parsed content.
 */
function jetpack_soundcloud_embed_reversal( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'w.soundcloud.com/player' ) ) {
		return $content;
	}

	$regexes = array();

	$regexes[] = '#<iframe[^>]+?src="((?:https?:)?//w\.soundcloud\.com/player/[^"\']++)"[^>]*+>\s*?</iframe>#i';
	$regexes[] = '#&lt;iframe(?:[^&]|&(?!gt;))+?src="((?:https?:)?//w\.soundcloud\.com/player/[^"\']++)"(?:[^&]|&(?!gt;))*+&gt;\s*?&lt;/iframe&gt;#i';

	foreach ( $regexes as $regex ) {
		if ( ! preg_match_all( $regex, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {

			// if pasted from the visual editor - prevent double encoding.
			$match[1] = str_replace( '&amp;amp;', '&amp;', $match[1] );

			$args = wp_parse_url( html_entity_decode( $match[1], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 ), PHP_URL_QUERY );
			$args = wp_parse_args( $args );

			if ( ! preg_match( '#^(?:https?:)?//api\.soundcloud\.com/.+$#i', $args['url'], $url_matches ) ) {
				continue;
			}

			if ( ! preg_match( '#height="(\d+)"#i', $match[0], $hmatch ) ) {
				$height = '';
			} else {
				$height = ' height="' . (int) $hmatch[1] . '"';
			}

			unset( $args['url'] );
			$params = 'params="';
			if ( count( $args ) > 0 ) {
				foreach ( $args as $key => $value ) {
					$params .= esc_html( $key ) . '=' . esc_html( $value ) . '&amp;';
				}
				$params = substr( $params, 0, -5 );
			}
			$params .= '"';

			$shortcode = '[soundcloud url="' . esc_url( $url_matches[0] ) . '" ' . $params . ' width="100%"' . $height . ' iframe="true" /]';

			$replace_regex = sprintf( '#\s*%s\s*#', preg_quote( $match[0], '#' ) );
			$content       = preg_replace( $replace_regex, sprintf( "\n\n%s\n\n", $shortcode ), $content );

			/** This action is documented in modules/shortcodes/youtube.php */
			do_action( 'jetpack_embed_to_shortcode', 'soundcloud', $url_matches[0] );
		}
	}

	return $content;
}
add_filter( 'pre_kses', 'jetpack_soundcloud_embed_reversal' );
