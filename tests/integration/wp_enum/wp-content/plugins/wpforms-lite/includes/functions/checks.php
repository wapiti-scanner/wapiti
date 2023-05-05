<?php
/**
 * Helper functions to perform various checks across the core plugin and addons.
 *
 * @since 1.8.0
 */

use TrueBV\Punycode;

/**
 * Check if a string is a valid URL.
 *
 * @since 1.0.0
 * @since 1.5.8 Changed the pattern used to validate the URL.
 *
 * @param string $url Input URL.
 *
 * @return bool
 */
function wpforms_is_url( $url ) {

	// The pattern taken from https://gist.github.com/dperini/729294.
	// It is the best choice according to the https://mathiasbynens.be/demo/url-regex.
	$pattern = '%^(?:(?:(?:https?|ftp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z0-9\x{00a1}-\x{ffff}][a-z0-9\x{00a1}-\x{ffff}_-]{0,62})?[a-z0-9\x{00a1}-\x{ffff}]\.)+(?:[a-z\x{00a1}-\x{ffff}]{2,}\.?))(?::\d{2,5})?(?:[/?#]\S*)?$%iu';

	if ( preg_match( $pattern, trim( $url ) ) ) {
		return true;
	}

	return false;
}

/**
 * Verify that an email is valid.
 * See the linked RFC.
 *
 * @see https://www.rfc-editor.org/rfc/inline-errata/rfc3696.html
 *
 * @since 1.7.3
 *
 * @param string $email Email address to verify.
 *
 * @return string|false Returns a valid email address on success, false on failure.
 */
function wpforms_is_email( $email ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

	static $punycode;

	// Do not allow callables, arrays and objects.
	if ( ! is_scalar( $email ) ) {
		return false;
	}

	// Allow smart tags in the email address.
	if ( preg_match( '/{.+?}/', $email ) ) {
		return $email;
	}

	// Email can't be longer than 254 octets,
	// otherwise it can't be used to send an email address (limitation in the MAIL and RCPT commands).
	// 1 octet = 8 bits = 1 byte.
	if ( strlen( $email ) > 254 ) {
		return false;
	}

	$email_arr = explode( '@', $email );

	if ( count( $email_arr ) !== 2 ) {
		return false;
	}

	list( $local, $domain ) = $email_arr;

	/**
	 * RFC requires local part to be no longer than 64 octets.
	 * Punycode library checks for 63 octets.
	 *
	 * @link https://github.com/true/php-punycode/blob/master/src/Punycode.php#L182.
	 */
	if ( strlen( $local ) > 63 ) {
		return false;
	}

	$domain_arr = explode( '.', $domain );

	foreach ( $domain_arr as $domain_label ) {
		$domain_label = trim( $domain_label );

		if ( ! $domain_label ) {
			return false;
		}

		// The RFC says: 'A DNS label may be no more than 63 octets long'.
		if ( strlen( $domain_label ) > 63 ) {
			return false;
		}
	}

	if ( ! $punycode ) {
		$punycode = new Punycode();
	}

	/**
	 * The wp_mail() uses phpMailer, which uses is_email() as verification callback.
	 * For verification, phpMailer sends the email address where the domain part is punycode encoded only.
	 * We follow here the same principle.
	 */
	$email_check = $local . '@' . $punycode->encode( $domain );

	// Other limitations are checked by the native WordPress function is_email().
	return is_email( $email_check ) ? $local . '@' . $domain : false;
}

/**
 * Check whether the string is json-encoded.
 *
 * @since 1.7.5
 *
 * @param string $string A string.
 *
 * @return bool
 */
function wpforms_is_json( $string ) {

	return (
		is_string( $string ) &&
		is_array( json_decode( $string, true ) ) &&
		json_last_error() === JSON_ERROR_NONE
	);
}

/**
 * Check whether the current page is in AMP mode or not.
 * We need to check for specific functions, as there is no special AMP header.
 *
 * @since 1.4.1
 *
 * @param bool $check_theme_support Whether theme support should be checked. Defaults to true.
 *
 * @return bool
 */
function wpforms_is_amp( $check_theme_support = true ) {

	$is_amp = false;

	if (
		// AMP by Automattic; ampforwp.
		( function_exists( 'is_amp_endpoint' ) && is_amp_endpoint() ) ||
		// Better AMP.
		( function_exists( 'is_better_amp' ) && is_better_amp() )
	) {
		$is_amp = true;
	}

	if ( $is_amp && $check_theme_support ) {
		$is_amp = current_theme_supports( 'amp' );
	}

	return apply_filters( 'wpforms_is_amp', $is_amp );
}

/**
 * Helper function to determine if loading on WPForms related admin page.
 *
 * Here we determine if the current administration page is owned/created by
 * WPForms. This is done in compliance with WordPress best practices for
 * development, so that we only load required WPForms CSS and JS files on pages
 * we create. As a result we do not load our assets admin wide, where they might
 * conflict with other plugins needlessly, also leading to a better, faster user
 * experience for our users.
 *
 * @since 1.3.9
 *
 * @param string $slug Slug identifier for a specific WPForms admin page.
 * @param string $view Slug identifier for a specific WPForms admin page view ("subpage").
 *
 * @return bool
 */
function wpforms_is_admin_page( $slug = '', $view = '' ) {

	// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash

	// Check against basic requirements.
	if (
		! is_admin() ||
		empty( $_REQUEST['page'] ) ||
		strpos( $_REQUEST['page'], 'wpforms' ) === false
	) {
		return false;
	}

	// Check against page slug identifier.
	if (
		( ! empty( $slug ) && $_REQUEST['page'] !== 'wpforms-' . $slug ) ||
		( empty( $slug ) && $_REQUEST['page'] === 'wpforms-builder' )
	) {
		return false;
	}

	// Check against sub-level page view.
	if (
		! empty( $view ) &&
		( empty( $_REQUEST['view'] ) || $_REQUEST['view'] !== $view )
	) {
		return false;
	}

	// phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash

	return true;
}

/**
 * Check if a string is empty.
 *
 * @since 1.5.0
 *
 * @param string $string String to test.
 *
 * @return bool
 */
function wpforms_is_empty_string( $string ) {

	return is_string( $string ) && $string === '';
}

/**
 * Determine if the request is WPForms AJAX.
 *
 * @since 1.8.0
 *
 * @return bool
 */
function wpforms_is_ajax() {

	if ( ! wp_doing_ajax() ) {
		return false;
	}

	// Make sure the request targets admin-ajax.php.
	if ( isset( $_SERVER['SCRIPT_FILENAME'] ) && basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_FILENAME'] ) ) ) !== 'admin-ajax.php' ) {
		return false;
	}

	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';

	return strpos( $action, 'wpforms_' ) === 0;
}

/**
 * Determine if request is frontend AJAX.
 *
 * @since 1.5.8.2
 * @since 1.6.5 Added filterable frontend ajax actions list as a fallback to missing referer cases.
 * @since 1.6.7.1 Removed a requirement for an AJAX action to be a WPForms action if referer is not missing.
 * @since 1.8.0 Added clear separation between frontend and admin AJAX requests, see `wpforms_is_admin_ajax()`.
 *
 * @return bool
 */
function wpforms_is_frontend_ajax() {

	if ( wpforms_is_ajax() && ! wpforms_is_admin_ajax() ) {
		return true;
	}

	// Try detecting a frontend AJAX call indirectly by comparing the current action
	// with a known frontend actions list in case there's no HTTP referer.

	$ref = wp_get_raw_referer();

	if ( $ref ) {
		return false;
	}

	$frontend_actions = [
		'wpforms_submit',
		'wpforms_file_upload_speed_test',
		'wpforms_upload_chunk_init',
		'wpforms_upload_chunk',
		'wpforms_file_chunks_uploaded',
		'wpforms_remove_file',
		'wpforms_restricted_email',
		'wpforms_form_locker_unique_answer',
		'wpforms_form_abandonment',
	];

	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';

	/**
	 * Allow modifying the list of frontend AJAX actions.
	 *
	 * This filter may be running as early as `plugins_loaded` hook.
	 * Please mind the hooks order when using it.
	 *
	 * @since 1.6.5
	 *
	 * @param array $frontend_actions A list of frontend actions.
	 */
	$frontend_actions = (array) apply_filters( 'wpforms_is_frontend_ajax_frontend_actions', $frontend_actions );

	return in_array( $action, $frontend_actions, true );
}

/**
 * Determine if request is admin AJAX.
 *
 * @since 1.8.0
 *
 * @return bool
 */
function wpforms_is_admin_ajax() {

	if ( ! wpforms_is_ajax() ) {
		return false;
	}

	$ref = wp_get_raw_referer();

	if ( ! $ref ) {
		return false;
	}

	$path       = wp_parse_url( $ref, PHP_URL_PATH );
	$admin_path = wp_parse_url( admin_url(), PHP_URL_PATH );

	// Is an admin AJAX call if HTTP referer contain an admin path.
	return strpos( $path, $admin_path ) !== false;
}

/**
 * Check if Gutenberg is active.
 *
 * @since 1.6.2
 *
 * @return bool True if Gutenberg is active.
 */
function wpforms_is_gutenberg_active() {

	$gutenberg    = false;
	$block_editor = false;

	if ( has_filter( 'replace_editor', 'gutenberg_init' ) ) {
		// Gutenberg is installed and activated.
		$gutenberg = true;
	}

	if ( version_compare( $GLOBALS['wp_version'], '5.0-beta', '>' ) ) {
		// Block editor.
		$block_editor = true;
	}

	if ( ! $gutenberg && ! $block_editor ) {
		return false;
	}

	include_once ABSPATH . 'wp-admin/includes/plugin.php';

	if ( is_plugin_active( 'disable-gutenberg/disable-gutenberg.php' ) ) {
		return ! disable_gutenberg();
	}

	if ( is_plugin_active( 'classic-editor/classic-editor.php' ) ) {
		return get_option( 'classic-editor-replace' ) === 'block';
	}

	return true;
}

/**
 * Determines whether the current request is a WP CLI request.
 *
 * @since 1.7.6
 *
 * @return bool
 */
function wpforms_doing_wp_cli() {

	return defined( 'WP_CLI' ) && WP_CLI;
}
