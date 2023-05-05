<?php
/**
 * Ustream.tv shortcode
 *
 * Example:
 * [ustream id=1524 live=1]
 * [ustreamsocial id=12980237 width="500"]
 *
 * Embed code example, from http://www.ustream.tv/leolaporte
 * <iframe src="http://www.ustream.tv/embed/recorded/1524?v=3&#038;wmode=direct" width="480" height="296" scrolling="no" frameborder="0" style="border: 0 none transparent;"></iframe>
 *
 * @package automattic/jetpack
 */

add_shortcode( 'ustream', 'ustream_shortcode' );
add_shortcode( 'ustreamsocial', 'ustreamsocial_shortcode' );

/**
 * Parse shortcode arguments and render output for ustream single video.
 *
 * @since 4.5.0
 *
 * @param array $atts array of user-supplied arguments.
 *
 * @return string HTML output.
 */
function ustream_shortcode( $atts ) {
	if ( isset( $atts[0] ) ) {
		return '<!-- ustream error: bad parameters -->';
	}

	$defaults = array(
		'width'     => 480,
		'height'    => 296,
		'id'        => 0,
		'live'      => 0,
		'highlight' => 0,
		'version'   => 3,
		'hwaccel'   => 1,
	);
	$atts     = array_map( 'intval', shortcode_atts( $defaults, $atts ) );

	if ( 0 >= $atts['id'] ) {
		return '<!-- ustream error: bad video ID -->';
	}

	if ( 0 >= $atts['height'] ) {
		return '<!-- ustream error: height invalid -->';
	}

	if ( 0 >= $atts['width'] ) {
		return '<!-- ustream error: width invalid -->';
	}

	if ( $atts['live'] ) {
		$recorded = '';
	} else {
		$recorded = 'recorded/';
	}

	if ( ! $atts['live'] && ( 0 < $atts['highlight'] ) ) {
		$highlight = sprintf( '/highlight/%d', esc_attr( $atts['highlight'] ) );
	} else {
		$highlight = '';
	}

	$url_base = sprintf(
		'https://www.ustream.tv/embed/%s%d%s',
		$recorded,
		esc_attr( $atts['id'] ),
		$highlight
	);

	$video_options = array(
		'html5ui' => 1,
		'v'       => absint( $atts['version'] ),
	);

	if ( 0 < $atts['hwaccel'] ) {
		$video_options['wmode'] = 'direct';
	}

	$url = add_query_arg(
		$video_options,
		$url_base
	);

	$output = sprintf(
		'<iframe src="%1$s" width="%2$d" height="%3$d" scrolling="no" style="border: 0 none transparent;"></iframe>',
		esc_url( $url ),
		absint( $atts['width'] ),
		absint( $atts['height'] )
	);

	return $output;
}

/**
 * Parse shortcode arguments and render output for ustream's Social Stream.
 *
 * @since 4.5.0
 *
 * @param array $atts array of user-supplied arguments.
 *
 * @return string HTML output.
 */
function ustreamsocial_shortcode( $atts ) {
	$defaults = array(
		'id'     => 0,
		'height' => 420,
		'width'  => 320,
	);
	$atts     = array_map( 'intval', shortcode_atts( $defaults, $atts ) );

	if ( 0 >= $atts['id'] ) {
		return '<!-- ustreamsocial error: bad social stream ID -->';
	}

	if ( 0 >= $atts['height'] ) {
		return '<!-- ustreamsocial error: height invalid -->';
	}

	if ( 0 >= $atts['width'] ) {
		return '<!-- ustreamsocial error: width invalid -->';
	}

	$url = 'https://www.ustream.tv/socialstream/' . esc_attr( $atts['id'] );

	return sprintf(
		'<iframe id="SocialStream" src="%1$s" class="" name="SocialStream" width="%2$d" height="%3$d" scrolling="no" allowtransparency="true" style="visibility: visible; margin-top: 0; margin-bottom: 0; border: 0;"></iframe>',
		esc_url( $url ),
		absint( $atts['width'] ),
		absint( $atts['height'] )
	);
}
