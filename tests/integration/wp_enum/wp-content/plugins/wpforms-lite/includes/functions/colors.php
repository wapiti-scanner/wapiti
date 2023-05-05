<?php
/**
 * Helper functions to work with colors.
 *
 * @since 1.8.0
 */

/**
 * Detect if we should use a light or dark color based on the color given.
 *
 * @link https://docs.woocommerce.com/wc-apidocs/source-function-wc_light_or_dark.html#608-627
 *
 * @since 1.2.5
 *
 * @param mixed  $color Color value.
 * @param string $dark  Dark color value (default: '#000000').
 * @param string $light Light color value (default: '#FFFFFF').
 *
 * @return string
 */
function wpforms_light_or_dark( $color, $dark = '#000000', $light = '#FFFFFF' ) {

	$hex = str_replace( '#', '', $color );

	$c_r = hexdec( substr( $hex, 0, 2 ) );
	$c_g = hexdec( substr( $hex, 2, 2 ) );
	$c_b = hexdec( substr( $hex, 4, 2 ) );

	$brightness = ( ( $c_r * 299 ) + ( $c_g * 587 ) + ( $c_b * 114 ) ) / 1000;

	return $brightness > 155 ? $dark : $light;
}

/**
 * Convert hex color value to RGB.
 *
 * @since 1.7.9
 *
 * @param string $hex Color value in hex format.
 *
 * @return string Color value in RGB format.
 */
function wpforms_hex_to_rgb( $hex ) {

	$hex = ltrim( $hex, '#' );

	// Convert shorthand colors to full format, e.g. "FFF" -> "FFFFFF".
	$rgb_parts = preg_replace( '~^(.)(.)(.)$~', '$1$1$2$2$3$3', $hex );

	return sprintf(
		'%1$d, %2$d, %3$d',
		hexdec( $rgb_parts[0] . $rgb_parts[1] ),
		hexdec( $rgb_parts[2] . $rgb_parts[3] ),
		hexdec( $rgb_parts[4] . $rgb_parts[5] )
	);
}
