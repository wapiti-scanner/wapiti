<?php
/**
 * Getty shortcode
 *
 * [getty src="82278805" width="$width" height="$height"]
 * <div class="getty embed image" style="background-color:#fff;display:inline-block;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#a7a7a7;font-size:11px;width:100%;max-width:462px;"><div style="padding:0;margin:0;text-align:left;"><a href="http://www.gettyimages.com/detail/82278805" target="_blank" style="color:#a7a7a7;text-decoration:none;font-weight:normal !important;border:none;display:inline-block;">Embed from Getty Images</a></div><div style="overflow:hidden;position:relative;height:0;padding:80.086580% 0 0 0;width:100%;"><iframe src="//embed.gettyimages.com/embed/82278805?et=jGiu6FXXSpJDGf1SnwLV2g&sig=TFVNFtqghwNw5iJQ1MFWnI8f4Y40_sfogfZLhai6SfA=" width="462" height="370" scrolling="no" frameborder="0" style="display:inline-block;position:absolute;top:0;left:0;width:100%;height:100%;"></iframe></div><p style="margin:0;"></p></div>
 *
 * @package automattic/jetpack
 */

if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	add_action( 'init', 'jetpack_getty_enable_embeds' );
} else {
	jetpack_getty_enable_embeds();
}

/**
 * Register Getty as oembed provider. Add filter to reverse iframes to shortcode. Register [getty] shortcode.
 *
 * @since 4.5.0
 * @since 5.8.0 removed string parameter.
 */
function jetpack_getty_enable_embeds() {

	// Support their oEmbed Endpoint.
	wp_oembed_add_provider( '#https?://www\.gettyimages\.com/detail/.*#i', 'https://embed.gettyimages.com/oembed/', true );
	wp_oembed_add_provider( '#https?://(www\.)?gty\.im/.*#i', 'https://embed.gettyimages.com/oembed/', true );

	// Allow iframes to be filtered to short code (so direct copy+paste can be done).
	add_filter( 'pre_kses', 'wpcom_shortcodereverse_getty' );

	// Actually display the Getty Embed.
	add_shortcode( 'getty', 'jetpack_getty_shortcode' );
}

/**
 * Filters the oEmbed provider URL for Getty URLs to include site URL host as
 * caller if available, falling back to "wordpress.com". Must be applied at
 * time of embed in case that `init` is too early (WP.com REST API).
 *
 * @module shortcodes
 *
 * @since 5.8.0
 *
 * @see WP_oEmbed::fetch
 *
 * @return string oEmbed provider URL
 */
add_filter( 'oembed_fetch_url', 'getty_add_oembed_endpoint_caller' );

/**
 * Filter the embeds to add a caller parameter.
 *
 * @param string $provider URL of the oEmbed provider.
 */
function getty_add_oembed_endpoint_caller( $provider ) {
	// By time filter is called, original provider URL has had url, maxwidth,
	// maxheight query parameters added.
	if ( 0 !== strpos( $provider, 'https://embed.gettyimages.com/oembed/' ) ) {
		return $provider;
	}

	// Set the caller argument to pass to Getty's oembed provider.
	if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {

		// Only include caller for non-private sites.
		if ( ! function_exists( 'is_private_blog' ) || ! is_private_blog() ) {
			$host = wp_parse_url( get_bloginfo( 'url' ), PHP_URL_HOST );
		}

		// Fall back to WordPress.com.
		if ( empty( $host ) ) {
			$host = 'wordpress.com';
		}
	} else {
		$host = wp_parse_url( get_home_url(), PHP_URL_HOST );
	}

	return add_query_arg( 'caller', $host, $provider );
}

/**
 * Compose shortcode based on Getty iframes.
 *
 * @since 4.5.0
 *
 * @param string $content Post content.
 *
 * @return mixed
 */
function wpcom_shortcodereverse_getty( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, '.gettyimages.com/' ) ) {
		return $content;
	}

	$regexp     = '!<iframe\s+src=[\'"](https?:)?//embed\.gettyimages\.com/embed(/|/?\?assets=)([a-z0-9_-]+(,[a-z0-9_-]+)*)[^\'"]*?[\'"]((?:\s+\w+=[\'"][^\'"]*[\'"])*)((?:[\s\w]*))></iframe>!i';
	$regexp_ent = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $regexp, ENT_NOQUOTES ) );

	// Markup pattern for 2017 embed syntax with significant differences from the prior pattern.
	$regexp_2017     = '!<a.+?class=\'gie-(single|slideshow)\'.+?gie\.widgets\.load\({([^}]+)}\).+?embed-cdn\.gettyimages\.com/widgets\.js.+?</script>!';
	$regexp_2017_ent = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $regexp_2017, ENT_NOQUOTES ) );

	foreach ( compact( 'regexp_2017', 'regexp_2017_ent', 'regexp', 'regexp_ent' ) as $reg => $regexp ) {
		if ( ! preg_match_all( $regexp, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			if ( 'regexp_2017' === $reg || 'regexp_2017_ent' === $reg ) {
				// Extract individual keys from the matched JavaScript object.
				$params = $match[2];
				if ( ! preg_match_all( '!(?P<key>\w+)\s*:\s*([\'"](?P<value>[^\'"]*?)(px)?[\'"])!', $params, $key_matches, PREG_SET_ORDER ) ) {
					continue;
				}

				foreach ( $key_matches as $key_match ) {
					switch ( $key_match['key'] ) {
						case 'items':
							$ids = $key_match['value'];
							break;
						case 'w':
							$width = (int) $key_match['value'];
							break;
						case 'h':
							$height = (int) $key_match['value'];
							break;
						case 'tld':
							$tld = $key_match['value'];
							break;
					}
				}
			} else {
				$params = $match[5];
				if ( 'regexp_ent' === $reg ) {
					$params = html_entity_decode( $params, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 );
				}
				$params = wp_kses_hair( $params, array( 'http' ) );

				$ids    = esc_html( $match[3] );
				$width  = isset( $params['width'] ) ? (int) $params['width']['value'] : 0;
				$height = isset( $params['height'] ) ? (int) $params['height']['value'] : 0;
			}

			if ( empty( $ids ) ) {
				continue;
			}

			$shortcode = '[getty src="' . esc_attr( $ids ) . '"';
			if ( ! empty( $width ) ) {
				$shortcode .= ' width="' . esc_attr( $width ) . '"';
			}
			if ( ! empty( $height ) ) {
				$shortcode .= ' height="' . esc_attr( $height ) . '"';
			}

			/*
			 * While it does not appear to have any practical impact, Getty has
			 * requested that we include TLD in the embed request
			 */
			if ( ! empty( $tld ) ) {
				$shortcode .= ' tld="' . esc_attr( $tld ) . '"';
			}
			$shortcode .= ']';

			$content = str_replace( $match[0], $shortcode, $content );
		}
	}

	// strip out enclosing div and any other markup.
	$regexp     = '%<div class="getty\s[^>]*+>.*?<div[^>]*+>(\[getty[^\]]*+\])\s*</div>.*?</div>%is';
	$regexp_ent = str_replace( array( '&amp;#0*58;', '[^&gt;]' ), array( '&amp;#0*58;|&#0*58;', '[^&]' ), htmlspecialchars( $regexp, ENT_NOQUOTES ) );

	foreach ( compact( 'regexp', 'regexp_ent' ) as $reg => $regexp ) {
		if ( ! preg_match_all( $regexp, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			$content = str_replace( $match[0], $match[1], $content );
		}
	}

	/** This action is documented in modules/widgets/social-media-icons.php */
	do_action( 'jetpack_bump_stats_extras', 'html_to_shortcode', 'getty' );

	return $content;
}

/**
 * Parse shortcode arguments and render its output.
 *
 * @since 4.5.0
 *
 * @param array  $atts    Shortcode parameters.
 * @param string $content Content enclosed by shortcode tags.
 *
 * @return string
 */
function jetpack_getty_shortcode( $atts, $content = '' ) {

	if ( ! empty( $content ) ) {
		$src = $content;
	} elseif ( ! empty( $atts['src'] ) ) {
		$src = $atts['src'];
	} elseif ( ! empty( $atts[0] ) ) {
		$src = $atts[0];
	} else {
		return '<!-- Missing Getty Source ID -->';
	}

	$src = preg_replace( '/^([\da-z-]+(,[\da-z-]+)*).*$/', '$1', $src );

	$params = array(
		'width'  => isset( $atts['width'] ) ? (int) $atts['width'] : null,
		'height' => isset( $atts['height'] ) ? (int) $atts['height'] : null,
	);

	if ( ! empty( $atts['tld'] ) ) {
		$params['tld'] = $atts['tld'];
	}

	return wp_oembed_get( 'https://gty.im/' . $src, array_filter( $params ) );
}
