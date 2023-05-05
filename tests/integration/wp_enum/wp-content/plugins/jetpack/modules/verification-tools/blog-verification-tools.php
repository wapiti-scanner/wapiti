<?php
/**
 * Handles site verification services.
 *
 * @package jetpack
 */

/**
 * Return an array of supported verification services.
 * Add new services to this function.
 *
 * @return array - an array of supported services.
 */
function jetpack_verification_services() {
	return array(
		'google'    => array(
			'name'   => 'Google Search Console',
			'key'    => 'google-site-verification',
			'format' => 'dBw5CvburAxi537Rp9qi5uG2174Vb6JwHwIRwPSLIK8',
			'url'    => 'https://www.google.com/webmasters/tools/',
		),
		'bing'      => array(
			'name'   => 'Bing Webmaster Center',
			'key'    => 'msvalidate.01',
			'format' => '12C1203B5086AECE94EB3A3D9830B2E',
			'url'    => 'https://www.bing.com/toolbox/webmaster/',
		),
		'pinterest' => array(
			'name'   => 'Pinterest Site Verification',
			'key'    => 'p:domain_verify',
			'format' => 'f100679e6048d45e4a0b0b92dce1efce',
			'url'    => 'https://pinterest.com/website/verify/',
		),
		'yandex'    => array(
			'name'   => 'Yandex.Webmaster',
			'key'    => 'yandex-verification',
			'format' => '44d68e1216009f40',
			'url'    => 'https://webmaster.yandex.com/sites/',
		),
		'facebook'  => array(
			'name'   => 'Facebook Domain Verification',
			'key'    => 'facebook-domain-verification',
			'format' => 'rvv8b23jxlp1lq41I9rwsvpzncy1fd',
			'url'    => 'https://business.facebook.com/settings/',
		),
	);
}

/**
 * Register Jetpack verification settings.
 */
function jetpack_verification_options_init() {
	register_setting(
		'verification_services_codes_fields',
		'verification_services_codes',
		array( 'sanitize_callback' => 'jetpack_verification_validate' )
	);
}
add_action( 'admin_init', 'jetpack_verification_options_init' );
add_action( 'rest_api_init', 'jetpack_verification_options_init' );

/**
 * Print the site verification meta in the page head.
 */
function jetpack_verification_print_meta() {
	$verification_services_codes = Jetpack_Options::get_option_and_ensure_autoload( 'verification_services_codes', '0' );
	if ( is_array( $verification_services_codes ) ) {
		$ver_output = "<!-- Jetpack Site Verification Tags -->\n";
		foreach ( jetpack_verification_services() as $name => $service ) {
			if ( is_array( $service ) && ! empty( $verification_services_codes[ "$name" ] ) ) {
				if ( preg_match( '#^<meta name="([a-z0-9_\-.:]+)?" content="([a-z0-9_-]+)?" />$#i', $verification_services_codes[ "$name" ], $matches ) ) {
					$verification_code = $matches[2];
				} else {
					$verification_code = $verification_services_codes[ "$name" ];
				}
				$ver_tag = sprintf( '<meta name="%s" content="%s" />', esc_attr( $service['key'] ), esc_attr( $verification_code ) );
				/**
				 * Filter the meta tag template used for all verification tools.
				 *
				 * @module verification-tools
				 *
				 * @since 3.0.0
				 *
				 * @param string $ver_tag Verification Tool meta tag.
				 */
				$ver_output .= apply_filters( 'jetpack_site_verification_output', $ver_tag );
				$ver_output .= "\n";
			}
		}
		echo $ver_output; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}
}
add_action( 'wp_head', 'jetpack_verification_print_meta', 1 );
