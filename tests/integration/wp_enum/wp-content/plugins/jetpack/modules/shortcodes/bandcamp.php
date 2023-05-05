<?php
/**
 * Shortcode handler for [bandcamp], which inserts a bandcamp.com
 * music player (iframe, html5)
 *
 * [bandcamp album=119385304]
 * [bandcamp album=3462839126  bgcol=FFFFFF linkcol=4285BB size=venti]
 * [bandcamp track=2446959313]
 *
 * @package automattic/jetpack
 */

/**
 * Display the Bandcamp shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function shortcode_handler_bandcamp( $atts ) {
	// there are no default values, but specify here anyway to explicitly list supported atts.
	$attributes = shortcode_atts(
		array(
			'album'       => null,     // integer album id.
			'track'       => null,     // integer track id.
			'video'       => null,     // integer track id for video player.
			'size'        => 'venti',  // one of the supported sizes.
			'bgcol'       => 'FFFFFF', // hex, no '#' prefix.
			'linkcol'     => null,     // hex, no '#' prefix.
			'layout'      => null,     // encoded layout url.
			'width'       => null,     // integer with optional "%".
			'height'      => null,     // integer with optional "%".
			'notracklist' => null,     // may be string "true" (defaults false).
			'tracklist'   => null,     // may be string "false" (defaults true).
			// phpcs:ignore Squiz.PHP.CommentedOutCode.Found -- false positive
			'artwork'     => null,     // may be string "false" (alternately: "none") or "small" (default is large).
			'minimal'     => null,     // may be string "true" (defaults false).
			'theme'       => null,     // may be theme identifier string ("light"|"dark" so far).
			'package'     => null,     // integer package id.
			't'           => null,     // integer track number.
			'tracks'      => null,     // comma separated list of allowed tracks.
			'esig'        => null,      // hex, no '#' prefix.
		),
		$atts,
		'bandcamp'
	);

	$sizes = array(
		'venti'      => array(
			'width'  => 400,
			'height' => 100,
		),
		'grande'     => array(
			'width'  => 300,
			'height' => 100,
		),
		'grande2'    => array(
			'width'  => 300,
			'height' => 355,
		),
		'grande3'    => array(
			'width'  => 300,
			'height' => 415,
		),
		'tall_album' => array(
			'width'  => 150,
			'height' => 295,
		),
		'tall_track' => array(
			'width'  => 150,
			'height' => 270,
		),
		'tall2'      => array(
			'width'  => 150,
			'height' => 450,
		),
		'short'      => array(
			'width'  => 46,
			'height' => 23,
		),
		'large'      => array(
			'width'  => 350,
			'height' => 470,
		),
		'medium'     => array(
			'width'  => 450,
			'height' => 120,
		),
		'small'      => array(
			'width'  => 350,
			'height' => 42,
		),
	);

	$sizekey = $attributes['size'];
	$height  = null;
	$width   = null;

	$is_video = false;

	/*
	 * Build iframe url.  For audio players, args are appended as
	 * extra path segments for historical reasons having to
	 * do with an IE-only flash bug which required this URL
	 * to contain no querystring.  Delay the actual joining
	 * of args into a string until after we decide if it's
	 * a video player or an audio player
	 */
	$argparts = array();

	if ( ! isset( $attributes['album'] ) && ! isset( $attributes['track'] ) && ! isset( $attributes['video'] ) ) {
		return "[bandcamp: shortcode must include 'track', 'album', or 'video' param]";
	}

	if ( isset( $attributes['track'] ) && is_numeric( $attributes['track'] ) ) {
		$track = esc_attr( $attributes['track'] );
		array_push( $argparts, "track={$track}" );
	} elseif ( isset( $attributes['video'] ) && is_numeric( $attributes['video'] ) ) {
		$track    = esc_attr( $attributes['video'] ); // videos are referenced by track id.
		$url      = '//bandcamp.com/EmbeddedPlayer/v=2';
		$is_video = true;
		array_push( $argparts, "track={$track}" );
	}
	if ( isset( $attributes['album'] ) && is_numeric( $attributes['album'] ) ) {
		$album = esc_attr( $attributes['album'] );
		array_push( $argparts, "album={$album}" );
	}

	if ( 'tall' === $sizekey ) {
		if ( isset( $attributes['album'] ) ) {
			$sizekey .= '_album';
		} else {
			$sizekey .= '_track';
		}
	}

	// if size specified that we don't recognize, fall back on venti.
	if ( empty( $sizes[ $sizekey ] ) ) {
		$sizekey            = 'venti';
		$attributes['size'] = 'venti';
	}

	/*
	 * use strict regex for digits + optional % instead of absint for height/width
	 * 'width' and 'height' params in the iframe url get the exact string from the shortcode
	 * args, whereas the inline style attribute must have "px" added to it if it has no "%"
	 */
	if ( isset( $attributes['width'] ) && preg_match( '|^([0-9]+)(%)?$|', $attributes['width'], $matches ) ) {
		$width    = $attributes['width'];
		$csswidth = $attributes['width'];
		if ( count( $matches ) < 3 ) {
			$csswidth .= 'px';
		}
	}
	if ( isset( $attributes['height'] ) && preg_match( '|^([0-9]+)(%)?$|', $attributes['height'], $matches ) ) {
		$height    = $attributes['height'];
		$cssheight = $attributes['height'];
		if ( count( $matches ) < 3 ) {
			$cssheight .= 'px';
		}
	}

	if ( ! $height ) {
		$height    = $sizes[ $sizekey ]['height'];
		$cssheight = $height . 'px';
	}

	if ( ! $width ) {
		$width    = $sizes[ $sizekey ]['width'];
		$csswidth = $width . 'px';
	}

	if ( isset( $attributes['layout'] ) ) {
		array_push( $argparts, "layout={$attributes['layout']}" );
	} elseif ( isset( $attributes['size'] ) && preg_match( '|^[a-zA-Z0-9]+$|', $attributes['size'] ) ) {
		array_push( $argparts, "size={$attributes['size']}" );
	}

	if ( isset( $attributes['bgcol'] ) && preg_match( '|^[0-9A-Fa-f]+$|', $attributes['bgcol'] ) ) {
		array_push( $argparts, "bgcol={$attributes['bgcol']}" );
	}

	if ( isset( $attributes['linkcol'] ) && preg_match( '|^[0-9A-Fa-f]+$|', $attributes['linkcol'] ) ) {
		array_push( $argparts, "linkcol={$attributes['linkcol']}" );
	}

	if ( isset( $attributes['package'] ) && preg_match( '|^[0-9]+$|', $attributes['package'] ) ) {
		array_push( $argparts, "package={$attributes['package']}" );
	}

	if ( isset( $attributes['t'] ) && preg_match( '|^[0-9]+$|', $attributes['t'] ) ) {
		array_push( $argparts, "t={$attributes['t']}" );
	}

	if ( 'true' === $attributes['notracklist'] ) {
		array_push( $argparts, 'notracklist=true' );
	}

	// 'tracklist' arg deprecates 'notracklist=true' to be less weird.  note, behavior
	// if both are specified is undefined
	switch ( $attributes['tracklist'] ) {
		case 'false':
		case 'none':
			array_push( $argparts, 'tracklist=false' );
			break;
	}

	switch ( $attributes['artwork'] ) {
		case 'false':
		case 'none':
		case 'small':
			array_push( $argparts, 'artwork=' . $attributes['artwork'] );
			break;
	}

	if ( 'true' === $attributes['minimal'] ) {
		array_push( $argparts, 'minimal=true' );
	}

	if ( isset( $attributes['theme'] ) && preg_match( '|^[a-zA-Z_]+$|', $attributes['theme'] ) ) {
		array_push( $argparts, "theme={$attributes['theme']}" );
	}

	// param 'tracks' is signed digest param 'esig'.
	if ( isset( $attributes['tracks'] ) && preg_match( '|^[0-9\,]+$|', $attributes['tracks'] ) ) {
		if ( isset( $attributes['esig'] ) && preg_match( '|^[0-9A-Fa-f]+$|', $attributes['esig'] ) ) {
			array_push( $argparts, "tracks={$attributes['tracks']}" );
			array_push( $argparts, "esig={$attributes['esig']}" );
		}
	}

	if ( $is_video ) {
		$url         = '//bandcamp.com/VideoEmbed?' . join( '&', $argparts );
		$extra_attrs = " mozallowfullscreen='1' webkitallowfullscreen='1' allowfullscreen='1'";
	} else {
		$url         = '//bandcamp.com/EmbeddedPlayer/v=2/' . join( '/', $argparts ) . '/';
		$extra_attrs = '';
	}

	$iframe = '<iframe width="%s" height="%s" style="position: relative; display: block; width: %s; height: %s;" src="%s" allowtransparency="true" frameborder="0"%s></iframe>';
	$iframe = sprintf( $iframe, esc_attr( $width ), esc_attr( $height ), esc_attr( $csswidth ), esc_attr( $cssheight ), esc_url( $url ), $extra_attrs );

	return $iframe;
}

add_shortcode( 'bandcamp', 'shortcode_handler_bandcamp' );
