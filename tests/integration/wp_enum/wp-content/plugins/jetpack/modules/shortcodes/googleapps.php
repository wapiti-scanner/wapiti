<?php
/**
 * Google Docs and Google Calendar Shortcode
 *
 * Presentation:
 * <iframe src="https://docs.google.com/present/embed?id=dhfhrphh_123drp8s65c&interval=15&autoStart=true&loop=true&size=l" frameborder="0" width="700" height="559"></iframe>
 * <iframe src="https://docs.google.com/presentation/embed?id=13ItX4jV0SOSdr-ZjHarcpTh9Lr4omfsHAp87jpxv8-0&start=false&loop=false&delayms=3000" frameborder="0" width="960" height="749" allowfullscreen="true" mozallowfullscreen="true" webkitallowfullscreen="true"></iframe>
 *
 * Document:
 * <iframe src="https://docs.google.com/document/pub?id=1kDatklacdZ_tZUOpWtt_ONzY97Ldj2zFcuO9LBY2Ln4&amp;embedded=true"></iframe>
 * <iframe src="https://docs.google.com/document/d/1kDatklacdZ_tZUOpWtt_ONzY97Ldj2zFcuO9LBY2Ln4/pub?embedded=true"></iframe>
 * <iframe src="https://docs.google.com/document/d/e/2PACX-1vRkpIdasKL-eKXDjJgpEONduUspZTz0YmKaajfie0eJYnzikuyusuG1_V8X8T9XflN9l8A1oCM2sgEA/pub?embedded=true"></iframe>
 *
 * External document:
 * <iframe width=100% height=560px frameborder=0 src=https://docs.google.com/a/pranab.in/viewer?a=v&pid=explorer&chrome=false&embedded=true&srcid=1VTMwdgGiDMt8MCr75-YkQP-4u9WmEp1Qvf6C26KYBgFilxU2qndpd-VHhBIn&hl=en></iframe>
 *
 * Spreadsheet Form:
 * <iframe src="https://spreadsheets.google.com/embeddedform?formkey=dEVOYnMzZG5jMUpGbjFMYjFYNVB3NkE6MQ" width="760" height="710" frameborder="0" marginheight="0" marginwidth="0">Loading...</iframe>
 *
 * Spreadsheet Widget:
 * <iframe width='500' height='300' frameborder='0' src='https://spreadsheets1.google.com/a/petedavies.com/pub?hl=en&hl=en&key=0AjSij7nlnXvKdHNsNjRSWG12YmVfOEFwdlMxQ3J1S1E&single=true&gid=0&output=html&widget=true'></iframe>
 * <iframe width='500' height='300' frameborder='0' src='https://spreadsheets.google.com/spreadsheet/pub?hl=en&hl=en&key=0AhInIwfvYrIUdGJiTXhtUEhBSFVPUzdRZU5OMDlqdnc&output=html&widget=true'></iframe>
 *
 * Calendar:
 * <iframe src="https://www.google.com/calendar/embed?src=serjant%40gmail.com&ctz=Europe/Sofia" style="border: 0" width="800" height="600" frameborder="0" scrolling="no"></iframe>
 * <iframe src="http://www.google.com/calendar/hosted/belcastro.com/embed?src=n8nr8sd6v9hnus3nmlk7ed1238%40group.calendar.google.com&ctz=Europe/Zurich" style="border: 0" width="800" height="600" frameborder="0" scrolling="no"></iframe>
 *
 * Customized calendar:
 * <iframe src="https://www.google.com/calendar/embed?title=asdf&amp;showTitle=0&amp;showNav=0&amp;showDate=0&amp;showPrint=0&amp;showTabs=0&amp;showCalendars=0&amp;
 * showTz=0&amp;mode=AGENDA&amp;height=300&amp;wkst=2&amp;hl=fi&amp;bgcolor=%23ffcccc&amp;src=m52gdmbgelo3itf00u1v44g0ns%40group.calendar.google.com&amp;color=%234E5D6C&amp;
 * src=serjant%40gmail.com&amp;color=%235229A3&amp;ctz=Europe%2FRiga" style=" border:solid 1px #777 " width="500" height="300" frameborder="0" scrolling="no"></iframe>
 *
 * Generic
 * <iframe src="https://docs.google.com/file/d/0B0SIdZW7iu-zX1RWREJpMXVHZVU/preview" width="640" height="480"></iframe>
 *
 * @package automattic/jetpack
 */

add_filter( 'pre_kses', 'googleapps_embed_to_shortcode' );
add_shortcode( 'googleapps', 'googleapps_shortcode' );

/**
 * Reverse iframe embed to shortcode mapping HTML attributes to shortcode attributes.
 *
 * @since 4.5.0
 *
 * @param string $content Post content.
 *
 * @return mixed
 */
function googleapps_embed_to_shortcode( $content ) {
	if (
		! is_string( $content )
		|| false === stripos( $content, '<iframe' )
		&& false === stripos( $content, '.google.com' )
	) {
		return $content;
	}

	$regexp            = '#<iframe((?:\s+\w+="[^"]*")*?)\s*src="https?://(docs|drive|spreadsheets\d*|calendar|www)*\.google\.com/(?!maps)([-\w\./]+)(?:\?)?([^"]+)?"\s*((?:\s+\w+="[^"]*")*?)>.*?</iframe>#i';
	$regexp_ent        = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $regexp, ENT_NOQUOTES ) );
	$regexp_squot      = str_replace( '"', "'", $regexp );
	$regexp_ent_squot  = str_replace( '"', "'", $regexp_ent );
	$regexp_noquot     = '!<iframe(.*?)src=https://(docs|drive)\.google\.com/[-\.\w/]*?(viewer)\?(.*?)>(.*?)</iframe>!';
	$regexp_ent_noquot = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $regexp_noquot, ENT_NOQUOTES ) );

	foreach ( compact( 'regexp', 'regexp_ent', 'regexp_squot', 'regexp_ent_squot', 'regexp_noquot', 'regexp_ent_noquot' ) as $reg => $regexp ) {
		if ( ! preg_match_all( $regexp, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			$params = $match[1] . $match[5];
			if ( in_array( $reg, array( 'regexp_ent', 'regexp_ent_squot' ), true ) ) {
				$params = html_entity_decode( $params, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 );
			}

			$params = wp_kses_hair( $params, array( 'http' ) );

			$width  = 0;
			$height = 0;

			if ( isset( $params['width'] ) ) {
				$width = (int) $params['width']['value'];
			}

			if ( isset( $params['height'] ) ) {
				$height = (int) $params['height']['value'];
			}

			// allow the user to specify width greater than 200 inside text widgets.
			if (
				$width > 400
				// We don't need to check a nonce here. A nonce is already checked "further up" in most code paths.
				// In the case where no nonce is ever checked, setting this $_POST parameter doesn't do anything the submitter couldn't already do (set the width/height).
				&& isset( $_POST['widget-text'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			) {
				$width  = 200;
				$height = 200;
			}

			$attributes = '';
			if ( isset( $params['width'] ) && '100%' === $params['width']['value'] ) {
				$width = '100%';
			}

			if ( $width ) {
				$attributes = ' width="' . $width . '"';
			}

			if ( $height ) {
				$attributes .= ' height="' . $height . '"';
			}

			$domain = 'spreadsheets';
			if ( in_array( $match[2], array( 'docs', 'drive', 'www', 'calendar' ), true ) ) {
				$domain = $match[2];
			}

			// Make sure this is actually something that the shortcode supports. If it's not, leave the HTML alone.
			if ( ! googleapps_validate_domain_and_dir( $domain, $match[3] ) ) {
				continue;
			}

			/** This action is documented in modules/widgets/social-media-icons.php */
			do_action( 'jetpack_bump_stats_extras', 'html_to_shortcode', googleapps_service_name( $domain, $match[3] ) );

			$content = str_replace( $match[0], '[googleapps domain="' . $domain . '" dir="' . $match[3] . '" query="' . esc_attr( $match[4] ) . '"' . $attributes . ' /]', $content );
		}
	}

	return $content;
}

/**
 * Parse shortcode attributes and output a Google Docs embed.
 *
 * @since 4.5.0
 *
 * @param array $atts Shortcode attributes.
 *
 * @return string
 */
function googleapps_shortcode( $atts ) {
	global $content_width;

	$attr = shortcode_atts(
		array(
			'width'  => '100%',
			'height' => '560',
			'domain' => 'docs',
			'dir'    => 'document',
			'query'  => '',
			'src'    => '',
		),
		$atts
	);

	if ( is_numeric( $content_width ) && $content_width > 0 && is_numeric( $attr['width'] ) && $attr['width'] > $content_width ) {
		$attr['width'] = $content_width;
	}

	if ( is_numeric( $content_width ) && $content_width > 0 && '560' === $attr['height'] ) {
		$attr['height'] = floor( $content_width * 3 / 4 );
	}

	if ( isset( $atts[0] ) && $atts[0] ) {
		$attr['src'] = $atts[0];
	}

	if ( $attr['src'] && preg_match( '!https?://(docs|drive|spreadsheets\d*|calendar|www)*\.google\.com/([-\w\./]+)\?([^"]+)!', $attr['src'], $matches ) ) {
		$attr['domain'] = $matches[1];
		$attr['dir']    = $matches[2];
		parse_str( htmlspecialchars_decode( $matches[3], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 ), $query_ar );
		$query_ar['chrome']   = 'false';
		$query_ar['embedded'] = 'true';
		$attr['query']        = http_build_query( $query_ar );
	}

	if ( ! googleapps_validate_domain_and_dir( $attr['domain'], $attr['dir'] ) ) {
		return '<!-- Unsupported URL -->';
	}

	$attr['query'] = $attr['dir'] . '?' . $attr['query'];

	/** This action is documented in modules/widgets/social-media-icons.php */
	do_action( 'jetpack_bump_stats_extras', 'embeds', googleapps_service_name( $attr['domain'], $attr['dir'] ) );

	return sprintf(
		'<iframe src="%s" frameborder="0" width="%s" height="%s" marginheight="0" marginwidth="0" allowfullscreen="true" mozallowfullscreen="true" webkitallowfullscreen="true"></iframe>',
		esc_url( 'https://' . $attr['domain'] . '.google.com/' . $attr['query'] ),
		esc_attr( $attr['width'] ),
		esc_attr( $attr['height'] )
	);
}

/**
 * Check that the domain blogs to a Google Apps domain.
 *
 * @since 4.5.0
 *
 * @param string $domain Google subdomain.
 * @param string $dir    Subdirectory of the shared URL.
 *
 * @return bool
 */
function googleapps_validate_domain_and_dir( $domain, $dir ) {
	if ( ! in_array( $domain, array( 'docs', 'drive', 'www', 'spreadsheets', 'calendar' ), true ) ) {
		return false;
	}

	// Calendars.
	if ( ( 'www' === $domain || 'calendar' === $domain ) && 'calendar/' !== substr( $dir, 0, 9 ) ) {
		return false;
	}

	// Docs.
	if ( in_array( $domain, array( 'docs', 'drive' ), true ) && ! preg_match( '![-\.\w/]*(presentation/embed|presentation/d/(.*)|present/embed|document/pub|spreadsheets/d/(.*)|document/d/(e/)?[\w-]+/pub|file/d/[\w-]+/preview|viewer|forms/d/(.*)/viewform|spreadsheet/\w+)$!', $dir ) ) {
		return false;
	}

	// Spreadsheets.
	if ( 'spreadsheets' === $domain && ! preg_match( '!^([-\.\w/]+/pub|[-\.\w/]*embeddedform)$!', $dir ) ) {
		return false;
	}

	return true;
}

/**
 * Get the name of the service we'll be embedding.
 *
 * @since 4.5.0
 *
 * @param string $domain Google subdomain.
 * @param string $dir    Subdirectory of the shared URL.
 *
 * @return string
 */
function googleapps_service_name( $domain, $dir ) {
	switch ( $domain ) {
		case 'drive':
		case 'docs':
			$service_name = ( 'present/embed' === $dir ) ? 'googledocs_presentation' : 'googledocs_document';
			break;
		case 'spreadsheets':
			$service_name = ( 'embeddedform' === $dir ) ? 'googledocs_form' : 'googledocs_spreadsheet';
			break;
		case 'calendar':
		default:
			$service_name = 'google_calendar';
	}

	return $service_name;
}
