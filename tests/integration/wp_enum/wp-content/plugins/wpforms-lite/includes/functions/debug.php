<?php
/**
 * Helper logging and debug functions.
 *
 * @since 1.8.0
 */

use WPForms\Logger\Log;

/**
 * Check whether plugin works in a debug mode.
 *
 * @since 1.2.3
 *
 * @return bool
 */
function wpforms_debug() {

	$debug = false;

	if ( ( defined( 'WPFORMS_DEBUG' ) && true === WPFORMS_DEBUG ) && is_super_admin() ) {
		$debug = true;
	}

	return apply_filters( 'wpforms_debug', $debug );
}

/**
 * Helper function to display debug data.
 *
 * @since 1.0.0
 *
 * @param mixed $data What to dump, can be any type.
 * @param bool  $echo Whether to print or return. Default is to print.
 *
 * @return string|void
 */
function wpforms_debug_data( $data, $echo = true ) {

	if ( ! wpforms_debug() ) {
		return;
	}

	if ( is_array( $data ) || is_object( $data ) ) {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_print_r
		$data = print_r( $data, true );
	}

	$output = sprintf(
		'<style>
			.wpforms-debug {
				line-height: 0;
			}
			.wpforms-debug textarea {
				background: #f6f7f7 !important;
				margin: 20px 0 0 0;
				width: 100%%;
				height: 500px;
				font-size: 12px;
				font-family: Consolas, Menlo, Monaco, monospace;
				direction: ltr;
				unicode-bidi: embed;
				line-height: 1.4;
				padding: 10px;
				border-radius: 0;
				border-color: #c3c4c7;
				box-sizing: border-box;
			}
			.postbox .wpforms-debug {
				padding-top: 12px;
			}
			.postbox .wpforms-debug:first-of-type {
				padding-top: 6px;
			}
			.postbox .wpforms-debug textarea {
				margin-top: 0 !important;
			}
		</style>
		<div class="wpforms-debug">
			<textarea readonly>=================== WPFORMS DEBUG ===================%s</textarea>
		</div>',
		"\n\n" . $data
	);

	/**
	 * Allow developers to determine whether the debug data should be displayed.
	 * Works only in debug mode (`WPFORMS_DEBUG` constant is `true`).
	 *
	 * @since 1.6.8
	 *
	 * @param bool $allow_display True by default.
	 */
	$allow_display = apply_filters( 'wpforms_debug_data_allow_display', true );

	if ( $echo && $allow_display ) {
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $output;
	} else {
		return $output;
	}
}

/**
 * Log helper.
 *
 * @since 1.0.0
 *
 * @param string $title   Title of a log message.
 * @param mixed  $message Content of a log message.
 * @param array  $args    Expected keys: form_id, meta, parent.
 */
function wpforms_log( $title = '', $message = '', $args = [] ) {

	// Skip if logs disabled in Tools -> Logs.
	if ( ! wpforms_setting( 'logs-enable', false ) ) {
		return;
	}

	// Require log title.
	if ( empty( $title ) ) {
		return;
	}

	/**
	 * Compare error levels to determine if we should log.
	 * Current supported levels:
	 * - Conditional Logic (conditional_logic)
	 * - Entries (entry)
	 * - Errors (error)
	 * - Payments (payment)
	 * - Providers (provider)
	 * - Security (security)
	 * - Spam (spam)
	 * - Log (log)
	 */
	$types = ! empty( $args['type'] ) ? (array) $args['type'] : [ 'error' ];

	// Skip invalid logs types.
	$log_types = Log::get_log_types();

	foreach ( $types as $key => $type ) {
		if ( ! isset( $log_types[ $type ] ) ) {
			unset( $types[ $key ] );
		}
	}

	if ( empty( $types ) ) {
		return;
	}

	// Make arrays and objects look nice.
	if ( is_array( $message ) || is_object( $message ) ) {
		$message = '<pre>' . print_r( $message, true ) . '</pre>'; // phpcs:ignore
	}

	// Filter logs types from Tools -> Logs page.
	$logs_types = wpforms_setting( 'logs-types', false );

	if ( $logs_types && empty( array_intersect( $logs_types, $types ) ) ) {
		return;
	}

	// Filter user roles from Tools -> Logs page.
	$current_user       = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
	$current_user_id    = $current_user ? $current_user->ID : 0;
	$current_user_roles = $current_user ? $current_user->roles : [];
	$logs_user_roles    = wpforms_setting( 'logs-user-roles', false );

	if ( $logs_user_roles && empty( array_intersect( $logs_user_roles, $current_user_roles ) ) ) {
		return;
	}

	// Filter logs users from Tools -> Logs page.
	$logs_users = wpforms_setting( 'logs-users', false );

	if ( $logs_users && ! in_array( $current_user_id, $logs_users, true ) ) {
		return;
	}

	$log = wpforms()->get( 'log' );

	if ( ! method_exists( $log, 'add' ) ) {
		return;
	}
	// Create log entry.
	$log->add(
		$title,
		$message,
		$types,
		isset( $args['form_id'] ) ? absint( $args['form_id'] ) : 0,
		isset( $args['parent'] ) ? absint( $args['parent'] ) : 0,
		$current_user_id
	);
}

/**
 * Wrapper for set_time_limit to see if it is enabled.
 *
 * @since 1.6.4
 *
 * @param int $limit Time limit.
 */
function wpforms_set_time_limit( $limit = 0 ) {

	if ( function_exists( 'set_time_limit' ) && false === strpos( ini_get( 'disable_functions' ), 'set_time_limit' ) && ! ini_get( 'safe_mode' ) ) { // phpcs:ignore PHPCompatibility.IniDirectives.RemovedIniDirectives.safe_modeDeprecatedRemoved
		@set_time_limit( $limit ); // @codingStandardsIgnoreLine
	}
}
