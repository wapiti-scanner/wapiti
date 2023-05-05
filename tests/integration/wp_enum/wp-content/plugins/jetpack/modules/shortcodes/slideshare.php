<?php
/**
 * Slideshare shortcode
 *
 * Formats:
 * Old style (still compatible): [slideshare id=5342235&doc=camprock-101002163655-phpapp01&w=300&h=200]
 * New style: [slideshare id=5342235&w=300&h=200&fb=0&mw=0&mh=0&sc=no]
 *
 * Legend:
 *  id    = Document ID provided by Slideshare
 *  w     = Width of iFrame     (int)
 *  h     = Height of iFrame    (int)
 *  fb    = iFrame frameborder  (int)
 *  mw    = iFrame marginwidth  (int)
 *  mh    = iFrame marginheight (int)
 *  sc    = iFrame Scrollbar    (yes/no)
 *  pro   = Slideshare Pro      (yes/no)
 *  style = Inline CSS          (string)
 *
 * @package automattic/jetpack
 */

/**
 * Register and display shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function slideshare_shortcode( $atts ) {
	global $content_width;

	$params = shortcode_new_to_old_params( $atts );
	parse_str( $params, $arguments );

	if ( empty( $arguments ) ) {
		return '<!-- SlideShare error: no arguments -->';
	}

	$attr = shortcode_atts(
		array(
			'id'    => '',
			'w'     => '',
			'h'     => '',
			'fb'    => '',
			'mw'    => '',
			'mh'    => '',
			'sc'    => '',
			'pro'   => '',
			'style' => '',
		),
		$arguments
	);

	// check that the Slideshare ID contains letters, numbers and query strings.
	$pattern = '/[^-_a-zA-Z0-9?=&]/';
	if ( empty( $attr['id'] ) || preg_match( $pattern, $attr['id'] ) ) {
		return '<!-- SlideShare error: id is missing or has illegal characters -->';
	}

	// check the width/height.
	$w = (int) $attr['w'];

	// If no width was specified (or uses the wrong format), and if we have a $content_width, use that.
	if ( empty( $w ) && ! empty( $content_width ) ) {
		$w = (int) $content_width;
	} elseif ( $w < 300 || $w > 1600 ) { // If width was specified, but is too small/large, set default value.
		$w = 425;
	} else {
		$w = (int) $w;
	}

	$h = ceil( $w * 348 / 425 ); // Note: user-supplied height is ignored.

	if ( ! empty( $attr['pro'] ) ) {
		$source = 'https://www.slideshare.net/slidesharepro/' . $attr['id'];
	} else {
		$source = 'https://www.slideshare.net/slideshow/embed_code/' . $attr['id'];
	}

	if ( isset( $attr['rel'] ) ) {
		$source = add_query_arg( 'rel', (int) $attr['rel'], $source );
	}

	if ( ! empty( $attr['startSlide'] ) ) {
		$source = add_query_arg( 'startSlide', (int) $attr['startSlide'], $source );
	}

	$player = sprintf( "<iframe src='%s' width='%d' height='%d'", esc_url( $source ), $w, $h );

	// check the frameborder.
	if ( ! empty( $attr['fb'] ) || '0' === $attr['fb'] ) {
		$player .= " frameborder='" . (int) $attr['fb'] . "'";
	}

	$is_amp = ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() );

	if ( ! $is_amp ) {
		// check the margin width; if not empty, cast as int.
		if ( ( ! empty( $attr['mw'] ) || '0' === $attr['mw'] ) ) {
			$player .= " marginwidth='" . (int) $attr['mw'] . "'";
		}

		// check the margin height, if not empty, cast as int.
		if ( ( ! empty( $attr['mh'] ) || '0' === $attr['mh'] ) ) {
			$player .= " marginheight='" . (int) $attr['mh'] . "'";
		}
	}

	if ( ! empty( $attr['style'] ) ) {
		$player .= " style='" . esc_attr( $attr['style'] ) . "'";
	}

	// check the scrollbar; cast as a lowercase string for comparison.
	if ( ! empty( $attr['sc'] ) ) {
		$sc = strtolower( $attr['sc'] );

		if ( in_array( $sc, array( 'yes', 'no' ), true ) ) {
			$player .= " scrolling='" . $sc . "'";
		}
	}

	$player .= ' sandbox="allow-popups allow-scripts allow-same-origin allow-presentation" allowfullscreen webkitallowfullscreen mozallowfullscreen></iframe>';

	/**
	 * Filter the returned SlideShare shortcode.
	 *
	 * @module shortcodes
	 *
	 * @since 4.7.0
	 *
	 * @param string $player The iframe to return.
	 * @param array  $atts   The attributes specified in the shortcode.
	 */
	return apply_filters( 'jetpack_slideshare_shortcode', $player, $atts );
}
add_shortcode( 'slideshare', 'slideshare_shortcode' );
