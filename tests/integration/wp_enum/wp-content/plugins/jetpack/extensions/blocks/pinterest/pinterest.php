<?php
/**
 * Pinterest Block.
 *
 * @since 8.0.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Pinterest;

use Automattic\Jetpack\Blocks;
use WP_Error;

const FEATURE_NAME = 'pinterest';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;
const URL_PATTERN  = '#^https?://(?:www\.)?(?:[a-z]{2}\.)?pinterest\.[a-z.]+/pin/(?P<pin_id>[^/]+)/?#i'; // Taken from AMP plugin, originally from Jetpack.
// This is the validate Pinterest URLs, converted from URL_REGEX in extensions/blocks/pinterest/index.js.
const PINTEREST_URL_REGEX = '/^https?:\/\/(?:www\.)?(?:[a-z]{2}\.)?(?:pinterest\.[a-z.]+|pin\.it)\/([^\/]+)(\/[^\/]+)?/i';
// This looks for matches in /foo/ of https://www.pinterest.ca/foo/.
const REMAINING_URL_PATH_REGEX = '/^\/([^\/]+)\/?$/';
// This looks for matches with /foo/bar/ of https://www.pinterest.ca/foo/bar/.
const REMAINING_URL_PATH_WITH_SUBPATH_REGEX = '/^\/([^\/]+)\/([^\/]+)\/?$/';

/**
 * Determines the Pinterest embed type from the URL.
 *
 * @param string $url the URL to check.
 * @returns {string} The pin type. Empty string if it isn't a valid Pinterest URL.
 */
function pin_type( $url ) {
	if ( null === $url || ! preg_match( PINTEREST_URL_REGEX, $url ) ) {
		return '';
	}

	$path = wp_parse_url( $url, PHP_URL_PATH );

	if ( ! $path ) {
		return '';
	}

	if ( substr( $path, 0, 5 ) === '/pin/' ) {
		return 'embedPin';
	}

	if ( preg_match( REMAINING_URL_PATH_REGEX, $path ) ) {
		return 'embedUser';
	}

	if ( preg_match( REMAINING_URL_PATH_WITH_SUBPATH_REGEX, $path ) ) {
		return 'embedBoard';
	}

	return '';
}

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array( 'render_callback' => __NAMESPACE__ . '\load_assets' )
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Fetch info for a Pin.
 *
 * This is using the same pin info API as AMP is using client-side in the amp-pinterest component.
 * Successful API responses are cached in a transient for 1 month. Unsuccessful responses are cached for 1 hour.
 *
 * @link https://github.com/ampproject/amphtml/blob/b5dea36e0b8bd012585d50839766a084f99a3685/extensions/amp-pinterest/0.1/pin-widget.js#L83-L97
 * @param string $pin_id Pin ID.
 * @return array|WP_Error Pin info or error on failure.
 */
function fetch_pin_info( $pin_id ) {
	$transient_id = substr( "jetpack_pin_info_{$pin_id}", 0, 172 );

	$info = get_transient( $transient_id );
	if ( is_array( $info ) || is_wp_error( $info ) ) {
		return $info;
	}

	$pin_info_api_url = add_query_arg(
		array(
			'pin_ids'     => rawurlencode( $pin_id ),
			'sub'         => 'wwww',
			'base_scheme' => 'https',
		),
		'https://widgets.pinterest.com/v3/pidgets/pins/info/'
	);

	$response = wp_remote_get( esc_url_raw( $pin_info_api_url ) );
	if ( is_wp_error( $response ) ) {
		set_transient( $transient_id, $response, HOUR_IN_SECONDS );
		return $response;
	}

	$error = null;
	$body  = json_decode( wp_remote_retrieve_body( $response ), true );
	if ( ! is_array( $body ) || ! isset( $body['status'] ) ) {
		$error = new WP_Error( 'bad_json_response', '', compact( 'pin_id' ) );
	} elseif ( 'success' !== $body['status'] || ! isset( $body['data'][0] ) ) {
		$error = new WP_Error( 'unsuccessful_request', '', compact( 'pin_id' ) );
	} elseif ( ! isset( $body['data'][0]['images']['237x'] ) ) {
		// See <https://github.com/ampproject/amphtml/blob/b5dea36e0b8bd012585d50839766a084f99a3685/extensions/amp-pinterest/0.1/pin-widget.js#L106>.
		$error = new WP_Error( 'missing_required_image', '', compact( 'pin_id' ) );
	}

	if ( $error ) {
		set_transient( $transient_id, $error, HOUR_IN_SECONDS );
		return $error;
	} else {
		$data = $body['data'][0];
		set_transient( $transient_id, $data, MONTH_IN_SECONDS );
		return $data;
	}
}

/**
 * Render a Pin using the amp-pinterest component.
 *
 * This does not render boards or user profiles.
 *
 * Since AMP components need to be statically sized to be valid (so as to avoid layout shifting), there are quite a few
 * hard-coded numbers as taken from the CSS for the AMP component.
 *
 * @param array $attr Block attributes.
 * @return string Markup for <amp-pinterest>.
 */
function render_amp_pin( $attr ) {
	$info = null;
	if ( preg_match( URL_PATTERN, $attr['url'], $matches ) ) {
		$info = fetch_pin_info( $matches['pin_id'] );
	}

	if ( is_array( $info ) ) {
		$image       = $info['images']['237x'];
		$title       = isset( $info['rich_metadata']['title'] ) ? $info['rich_metadata']['title'] : null;
		$description = isset( $info['rich_metadata']['description'] ) ? $info['rich_metadata']['description'] : null;

		// This placeholder will appear while waiting for the amp-pinterest component to initialize (or if it fails to initialize due to JS being disabled).
		$placeholder = sprintf(
			// The AMP_Img_Sanitizer will convert his to <amp-img> while also supplying `noscript > img` as fallback when JS is disabled.
			'<a href="%s" placeholder><img src="%s" alt="%s" layout="fill" object-fit="contain" object-position="top left"></a>',
			esc_url( $attr['url'] ),
			esc_url( $image['url'] ),
			esc_attr( $title )
		);

		$amp_padding     = 5;   // See <https://github.com/ampproject/amphtml/blob/b5dea36e0b8bd012585d50839766a084f99a3685/extensions/amp-pinterest/0.1/amp-pinterest.css#L269>.
		$amp_fixed_width = 237; // See <https://github.com/ampproject/amphtml/blob/b5dea36e0b8bd012585d50839766a084f99a3685/extensions/amp-pinterest/0.1/amp-pinterest.css#L270>.
		$pin_info_height = 60;  // Minimum Obtained by measuring the height of the .-amp-pinterest-embed-pin-text element.

		// Add height based on how much description there is. There are roughly 30 characters on a line of description text.
		$has_description = false;
		if ( ! empty( $info['description'] ) ) {
			$desc_padding_top = 5;  // See <https://github.com/ampproject/amphtml/blob/b5dea36e0b8bd012585d50839766a084f99a3685/extensions/amp-pinterest/0.1/amp-pinterest.css#L342>.
			$pin_info_height += $desc_padding_top;

			// Trim whitespace on description if there is any left, use to calculate the likely rows of text.
			$description = trim( $info['description'] );
			if ( strlen( $description ) > 0 ) {
				$has_description  = true;
				$desc_line_height = 17; // See <https://github.com/ampproject/amphtml/blob/b5dea36e0b8bd012585d50839766a084f99a3685/extensions/amp-pinterest/0.1/amp-pinterest.css#L341>.
				$pin_info_height += ceil( strlen( $description ) / 30 ) * $desc_line_height;
			}
		}

		if ( ! empty( $info['repin_count'] ) ) {
			$pin_stats_height = 16;  // See <https://github.com/ampproject/amphtml/blob/b5dea36e0b8bd012585d50839766a084f99a3685/extensions/amp-pinterest/0.1/amp-pinterest.css#L322>.
			$pin_info_height += $pin_stats_height;
		}

		// When Pin description is empty, make sure title and description from rich metadata are supplied for accessibility and discoverability.
		$title = $has_description ? '' : implode( "\n", array_filter( array( $title, $description ) ) );

		$amp_pinterest = sprintf(
			'<amp-pinterest style="%1$s" data-do="embedPin" data-url="%2$s" width="%3$d" height="%4$d" title="%5$s">%6$s</amp-pinterest>',
			esc_attr( 'line-height:1.5; font-size:21px' ), // Override styles from theme due to precise height calculations above.
			esc_url( $attr['url'] ),
			$amp_fixed_width + ( $amp_padding * 2 ),
			$image['height'] + $pin_info_height + ( $amp_padding * 2 ),
			esc_attr( $title ),
			$placeholder
		);
	} else {
		// Fallback embed when info is not available.
		$amp_pinterest = sprintf(
			'<amp-pinterest data-do="embedPin" data-url="%1$s" width="%2$d" height="%3$d">%4$s</amp-pinterest>',
			esc_url( $attr['url'] ),
			450, // Fallback width.
			750, // Fallback height.
			sprintf(
				'<a placeholder href="%s">%s</a>',
				esc_url( $attr['url'] ),
				esc_html( $attr['url'] )
			)
		);
	}

	return sprintf(
		'<div class="wp-block-jetpack-pinterest">%s</div>',
		$amp_pinterest
	);
}

/**
 * Pinterest block registration/dependency declaration.
 *
 * @param array  $attr    Array containing the Pinterest block attributes.
 * @param string $content String containing the Pinterest block content.
 *
 * @return string
 */
function load_assets( $attr, $content ) {
	if ( ! jetpack_is_frontend() ) {
		return $content;
	}
	if ( Blocks::is_amp_request() ) {
		return render_amp_pin( $attr );
	} else {
		$url  = $attr['url'];
		$type = pin_type( $url );

		if ( ! $type ) {
			return '';
		}

		wp_enqueue_script( 'pinterest-pinit', 'https://assets.pinterest.com/js/pinit.js', array(), JETPACK__VERSION, true );
		return sprintf(
			'
			<div class="%1$s">
				<a data-pin-do="%2$s" href="%3$s"></a>
			</div>
		',
			esc_attr( Blocks::classes( FEATURE_NAME, $attr ) ),
			esc_attr( $type ),
			esc_url( $url )
		);
	}
}
