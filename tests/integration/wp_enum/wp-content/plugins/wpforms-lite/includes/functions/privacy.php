<?php
/**
 * Helper functions related to privacy, geolocation and user data.
 *
 * @since 1.8.0
 */

/**
 * Get the user IP address.
 *
 * @since 1.2.5
 * @since 1.7.3 Improve the IP detection quality by taking care of proxies (e.g. when the site is behind Cloudflare).
 *
 * Code based on the:
 *   - WordPress method \WP_Community_Events::get_unsafe_client_ip
 *   - Cloudflare documentation https://support.cloudflare.com/hc/en-us/articles/206776727
 *
 * @return string
 */
function wpforms_get_ip() {

	$ip = '127.0.0.1';

	$address_headers = [
		'HTTP_TRUE_CLIENT_IP',
		'HTTP_CF_CONNECTING_IP',
		'HTTP_X_REAL_IP',
		'HTTP_CLIENT_IP',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_X_CLUSTER_CLIENT_IP',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED',
		'REMOTE_ADDR',
	];

	foreach ( $address_headers as $header ) {
		if ( empty( $_SERVER[ $header ] ) ) {
			continue;
		}

		/*
		 * HTTP_X_FORWARDED_FOR can contain a chain of comma-separated addresses, with or without spaces.
		 * The first address is the original client. It can't be trusted for authenticity,
		 * but we don't need to for this purpose.
		 */

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$address_chain = explode( ',', wp_unslash( $_SERVER[ $header ] ) );
		$ip            = filter_var( trim( $address_chain[0] ), FILTER_VALIDATE_IP );

		break;
	}

	/**
	 * Filter detected IP address.
	 *
	 * @since 1.2.5
	 *
	 * @param string $ip IP address.
	 */
	return filter_var( apply_filters( 'wpforms_get_ip', $ip ), FILTER_VALIDATE_IP );
}

/**
 * Determine if collecting user's IP is allowed by GDPR setting (globally or per form).
 * Majority of our users have GDPR disabled.
 * So we remove this data from the request only when it's not needed:
 * 1) when GDPR is enabled AND globally disabled user details storage;
 * 2) when GDPR is enabled AND IP address processing is disabled on per form basis.
 *
 * @since 1.6.6
 *
 * @param array $form_data Form settings.
 *
 * @return bool
 */
function wpforms_is_collecting_ip_allowed( $form_data = [] ) {

	if (
		wpforms_setting( 'gdpr', false ) &&
		(
			wpforms_setting( 'gdpr-disable-details', false ) ||
			( ! empty( $form_data ) && ! empty( $form_data['settings']['disable_ip'] ) )
		)
	) {
		return false;
	}

	return true;
}

/**
 * Determine if collecting cookies is allowed by GDPR setting.
 *
 * @since 1.7.5
 *
 * @return bool
 */
function wpforms_is_collecting_cookies_allowed() {

	return ! ( wpforms_setting( 'gdpr', false ) && wpforms_setting( 'gdpr-disable-uuid', false ) );
}
