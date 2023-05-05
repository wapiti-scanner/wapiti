<?php
/**
 * VR Viewer Shortcode
 * converts [vr] shortcode to an iframe viewer hosted on vr.me.sh
 *
 * @package automattic/jetpack
 */

/**
 * Scrub URL paramaters for VR viewer
 *
 * @param array $params {
 *     parameter array which is passed to the jetpack_vr_viewer.
 *
 *     @type string $url url of 360 media
 *     @type string $guid     guid for videopress
 *     @type string $view     cinema, 360 - controls if panaroma view, or 360
 *     @type string $rotation number for rotating media
 *     @type string $preview  show preview image or not
 * }
 *
 * @return array|false $url_params Array of URL parameters.
 */
function jetpack_vr_viewer_get_viewer_url_params( $params ) {
	$url_params = array();

	if ( isset( $params['rotation'] ) ) {
		$url_params['rotation'] = (int) $params['rotation'];
	}

	if ( isset( $params['view'] ) && in_array( $params['view'], array( 'cinema', '360' ), true ) ) {
		$url_params['view'] = $params['view'];
	}

	if ( isset( $params['preview'] ) && $params['preview'] ) {
		$url_params['preview'] = 1;
	}

	if ( isset( $params['url'] ) ) {
		return array_merge( $url_params, array( 'url' => $params['url'] ) );
	} elseif ( isset( $params['guid'] ) ) {
		return array_merge( $url_params, array( 'guid' => $params['guid'] ) );
	}

	return false;
}

/**
 * Get padding for IFRAME depending on view type
 *
 * @param string $view string cinema, 360 - default cinema.
 *
 * @return string $css padding
 */
function jetpack_vr_viewer_iframe_padding( $view ) {
	if ( '360' === $view ) {
		return '100%'; // 1:1 square aspect for 360
	}

	return '50%'; // 2:1 panorama aspect
}

/**
 * Create HTML for VR Viewer IFRAME and wrapper
 * The viewer code is hosted on vr.me.sh site which is then displayed
 * within posts via an IFRAME. This function returns the IFRAME html.
 *
 * @param array $url_params {
 *     parameter array which is passed to the jetpack_vr_viewer.
 *
 *     @type string $url url of 360 media
 *     @type string $guid     guid for videopress
 *     @type string $view     cinema, 360 - controls if panaroma view, or 360
 *     @type string $rotation number for rotating media
 *     @type string $preview  show preview image or not
 * }
 *
 * @return string $rtn an iframe for viewer.
 */
function jetpack_vr_viewer_get_html( $url_params ) {
	global $content_width;

	$iframe = add_query_arg( $url_params, 'https://vr.me.sh/view/' );

	// set some defaults.
	$maxwidth = ( is_numeric( $content_width ) && $content_width > 0 ) ? $content_width : 720;
	$view     = ( isset( $url_params['view'] ) ) ? $url_params['view'] : 'cinema';

	// If the shortcode is displayed in a WPCOM notification, display a simple link only.
	if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
		require_once WP_CONTENT_DIR . '/lib/display-context.php';
		$context = A8C\Display_Context\get_current_context();
		if ( A8C\Display_Context\NOTIFICATIONS === $context ) {
			return sprintf(
				'<a href="%1$s" target="_blank" rel="noopener noreferrer">%1$s</a>',
				esc_url( $iframe )
			);
		}
	}

	$rtn  = '<div style="position: relative; max-width: ' . $maxwidth . 'px; margin-left: auto; margin-right: auto; overflow: hidden; margin-bottom: 1em;">';
	$rtn .= '<div style="padding-top: ' . jetpack_vr_viewer_iframe_padding( $view ) . ';"></div>';
	$rtn .= '<iframe style="position: absolute; top: 0; right: 0; bottom: 0; left: 0; height: 100%" allowfullscreen="true" frameborder="0" width="100%" height="300" src="' . esc_url( $iframe ) . '">';
	$rtn .= '</iframe>';
	$rtn .= '</div>';

	return $rtn;
}

/**
 * Convert [vr] shortcode to viewer
 *
 * Shortcode example:
 * [vr url="https://en-blog.files.wordpress.com/2016/12/regents_park.jpg" view="360"]
 *
 * VR Viewer embed code:
 * <div style="position: relative; max-width: 720px; margin-left: auto; margin-right: auto; overflow: hidden;">
 * <div style="padding-top: 100%;"></div>
 * <iframe style="position: absolute; top: 0; right: 0; bottom: 0; left: 0; height: 100%" allowfullscreen="true" frameborder="0" width="100%" height="400" src="https://vr.me.sh/view/?view=360&amp;url=https://en-blog.files.wordpress.com/2016/12/regents_park.jpg">
 * </iframe>
 * </div>
 *
 * @param array $atts Shortcode attributes.
 *
 * @return html - complete vr viewer html
 */
function jetpack_vr_viewer_shortcode( $atts ) {
	$params = shortcode_atts(
		array(
			0          => null,
			'url'      => null,
			'src'      => null,
			'guid'     => null,
			'rotation' => null,
			'view'     => null,
			'preview'  => false,
		),
		$atts
	);

	// We offer a few ways to specify the URL.
	if ( $params[0] ) {
		$params['url'] = $params[0];
	} elseif ( $params['src'] ) {
		$params['url'] = $params['src'];
	}

	$url_params = jetpack_vr_viewer_get_viewer_url_params( $params );
	if ( $url_params ) {
		return jetpack_vr_viewer_get_html( $url_params );
	}

	// add check for user.
	if ( current_user_can( 'edit_posts' ) ) {
		return '[vr] shortcode requires a data source to be given';
	} else {
		return '';
	}
}
add_shortcode( 'vr', 'jetpack_vr_viewer_shortcode' );
