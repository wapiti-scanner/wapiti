<?php
/**
 * Archive.org book shortcode.
 *
 * Usage:
 * [archiveorg Experime1940]
 * [archiveorg http://archive.org/details/Experime1940 poster=http://archive.org/images/map.png]
 * [archiveorg id=Experime1940 width=640 height=480 autoplay=1]

 * <iframe src="http://archive.org/embed/Experime1940&autoplay=1&poster=http://archive.org/images/map.png" width="640" height="480" frameborder="0" webkitallowfullscreen="true" mozallowfullscreen="true" allowfullscreen></iframe>
 *
 * @package automattic/jetpack
 */

/**
 * Get ID of requested archive.org embed.
 *
 * @since 4.5.0
 *
 * @param array $atts Shortcode attributes.
 *
 * @return int|string
 */
function jetpack_shortcode_get_archiveorg_id( $atts ) {
	if ( isset( $atts[0] ) ) {
		$atts[0] = trim( $atts[0], '=' );
		if ( preg_match( '#archive.org/(details|embed)/(.+)/?$#i', $atts[0], $match ) ) {
			$id = $match[2];
		} else {
			$id = $atts[0];
		}
		return $id;
	}
	return 0;
}

/**
 * Convert an archive.org shortcode into an embed code.
 *
 * @since 4.5.0
 *
 * @param array $atts An array of shortcode attributes.
 * @return string The embed code for the archive.org video.
 */
function jetpack_archiveorg_shortcode( $atts ) {
	global $content_width;

	if ( isset( $atts[0] ) && empty( $atts['id'] ) ) {
		$atts['id'] = jetpack_shortcode_get_archiveorg_id( $atts );
	}

	$atts = shortcode_atts(
		array(
			'id'       => '',
			'width'    => 640,
			'height'   => 480,
			'autoplay' => 0,
			'poster'   => '',
		),
		$atts
	);

	if ( ! $atts['id'] ) {
		return '<!-- error: missing archive.org ID -->';
	}

	$id = $atts['id'];

	if ( ! $atts['width'] ) {
		$width = absint( $content_width );
	} else {
		$width = (int) $atts['width'];
	}

	if ( ! $atts['height'] ) {
		$height = round( ( $width / 640 ) * 360 );
	} else {
		$height = (int) $atts['height'];
	}

	if ( $atts['autoplay'] ) {
		$autoplay = '&autoplay=1';
	} else {
		$autoplay = '';
	}

	if ( $atts['poster'] ) {
		$poster = '&poster=' . $atts['poster'];
	} else {
		$poster = '';
	}

	return sprintf(
		'<div class="embed-archiveorg" style="text-align:center;"><iframe title="%s" src="%s" width="%s" height="%s" style="border:0;" webkitallowfullscreen="true" mozallowfullscreen="true" allowfullscreen></iframe></div>',
		esc_attr__( 'Archive.org', 'jetpack' ),
		esc_url( "https://archive.org/embed/{$id}{$autoplay}{$poster}" ),
		esc_attr( $width ),
		esc_attr( $height )
	);
}

add_shortcode( 'archiveorg', 'jetpack_archiveorg_shortcode' );

/**
 * Compose shortcode from archive.org iframe.
 *
 * @since 4.5.0
 *
 * @param string $content Post content.
 *
 * @return mixed
 */
function jetpack_archiveorg_embed_to_shortcode( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'archive.org/embed/' ) ) {
		return $content;
	}

	$regexp = '!<iframe\s+src=[\'"]https?://archive\.org/embed/([^\'"]+)[\'"]((?:\s+\w+(=[\'"][^\'"]*[\'"])?)*)></iframe>!i';

	if ( ! preg_match_all( $regexp, $content, $matches, PREG_SET_ORDER ) ) {
		return $content;
	}

	foreach ( $matches as $match ) {
		$url = explode( '&amp;', $match[1] );
		$id  = 'id=' . $url[0];

		$autoplay  = '';
		$poster    = '';
		$url_count = count( $url );

		for ( $ii = 1; $ii < $url_count; $ii++ ) {
			if ( 'autoplay=1' === $url[ $ii ] ) {
				$autoplay = ' autoplay="1"';
			}

			$map_matches = array();
			if ( preg_match( '/^poster=(.+)$/', $url[ $ii ], $map_matches ) ) {
				$poster = " poster=\"{$map_matches[1]}\"";
			}
		}

		$params = $match[2];

		$params = wp_kses_hair( $params, array( 'http' ) );

		$width  = isset( $params['width'] ) ? (int) $params['width']['value'] : 0;
		$height = isset( $params['height'] ) ? (int) $params['height']['value'] : 0;

		$wh = '';
		if ( $width && $height ) {
			$wh = ' width=' . $width . ' height=' . $height;
		}

		$shortcode = '[archiveorg ' . $id . $wh . $autoplay . $poster . ']';
		$content   = str_replace( $match[0], $shortcode, $content );
	}

	return $content;
}

add_filter( 'pre_kses', 'jetpack_archiveorg_embed_to_shortcode' );
