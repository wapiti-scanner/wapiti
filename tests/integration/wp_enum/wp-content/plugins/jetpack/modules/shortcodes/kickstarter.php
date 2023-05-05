<?php
/**
 * Kickstarter shortcode
 *
 * Usage:
 * [kickstarter url="https://www.kickstarter.com/projects/peaktoplateau/yak-wool-baselayers-from-tibet-to-the-world" width="480" height=""]
 *
 * @package automattic/jetpack
 */

add_shortcode( 'kickstarter', 'jetpack_kickstarter_shortcode' );
add_filter( 'pre_kses', 'jetpack_kickstarter_embed_to_shortcode' );

/**
 * Parse shortcode arguments and render its output.
 *
 * @since 4.5.0
 *
 * @param array $atts Shortcode parameters.
 *
 * @return string
 */
function jetpack_kickstarter_shortcode( $atts ) {
	if ( empty( $atts['url'] ) ) {
		return '';
	}

	$url = esc_url_raw( $atts['url'] );
	if ( ! preg_match( '#^(www\.)?kickstarter\.com$#i', wp_parse_url( $url, PHP_URL_HOST ) ) ) {
		return '<!-- Invalid Kickstarter URL -->';
	}

	global $wp_embed;
	return $wp_embed->shortcode( $atts, $url );
}

/**
 * Converts Kickstarter iframe embeds to a shortcode.
 *
 * EG: <iframe width="480" height="360" src="http://www.kickstarter.com/projects/deweymac/dewey-mac-kid-detective-book-make-diy-and-stem-spy/widget/video.html" frameborder="0" scrolling="no"> </iframe>
 *
 * @since 4.5.0
 *
 * @param string $content Entry content that possibly includes a Kickstarter embed.
 *
 * @return string
 */
function jetpack_kickstarter_embed_to_shortcode( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'www.kickstarter.com/projects' ) ) {
		return $content;
	}

	$regexp     = '!<iframe((?:\s+\w+=[\'"][^\'"]*[\'"])*)\s+src=[\'"](http://www\.kickstarter\.com/projects/[^/]+/[^/]+)/[^\'"]+[\'"]((?:\s+\w+=[\'"][^\'"]*[\'"])*)>[\s]*</iframe>!i';
	$regexp_ent = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $regexp, ENT_NOQUOTES ) ); // phpcs:ignore

	foreach ( array( 'regexp', 'regexp_ent' ) as $reg ) {
		if ( ! preg_match_all( $$reg, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			$url = esc_url( $match[2] );

			$params = $match[1] . $match[3];

			if ( 'regexp_ent' === $reg ) {
				$params = html_entity_decode( $params, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 );
			}

			$params = wp_kses_hair( $params, array( 'http' ) );

			$width = isset( $params['width'] ) ? (int) $params['width']['value'] : 0;

			$shortcode = '[kickstarter url=' . $url . ( ( ! empty( $width ) ) ? " width=$width" : '' ) . ']';
			$content   = str_replace( $match[0], $shortcode, $content );
		}
	}

	return $content;
}
