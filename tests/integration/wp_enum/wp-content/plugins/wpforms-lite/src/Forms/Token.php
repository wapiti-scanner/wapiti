<?php

namespace WPForms\Forms;

/**
 * Class Token.
 *
 * This token class generates tokens that are used in our Anti-Spam checking mechanism.
 *
 * @since 1.6.2
 */
class Token {

	/**
	 * Initialise the actions for the Anti-spam.
	 *
	 * @since 1.6.2
	 */
	public function init() {

		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.6.2
	 */
	public function hooks() {

		add_filter( 'wpforms_frontend_form_atts', [ $this, 'add_token_to_form_atts' ], 10, 2 );
	}

	/**
	 * Return a valid token.
	 *
	 * @since 1.6.2
	 * @since 1.7.1 Added the $form_data argument.
	 *
	 * @param mixed $current   True to use current time, otherwise a timestamp string.
	 * @param array $form_data Form data and settings.
	 *
	 * @return string Token.
	 */
	public function get( $current = true, $form_data = [] ) {

		// If $current was not passed, or it is true, we use the current timestamp.
		// If $current was passed in as a string, we'll use that passed in timestamp.
		if ( $current !== true ) {
			$time = $current;
		} else {
			$time = time();
		}

		// Format the timestamp to be less exact, as we want to deal in days.
		// June 19th, 2020 would get formatted as: 1906202017125.
		// Day of the month, month number, year, day number of the year, week number of the year.
		$token_data = gmdate( 'dmYzW', $time );

		if ( ! empty( $form_data['id'] ) ) {
			$token_data .= "::{$form_data['id']}";
		}

		// Combine our token date and our token salt, and md5 it.
		return md5( $token_data . \WPForms\Helpers\Crypto::get_secret_key() );
	}

	/**
	 * Generate the array of valid tokens to check for. These include two days
	 * before the current date to account for long cache times.
	 *
	 * These two filters are available if a user wants to extend the times.
	 * 'wpforms_form_token_check_before_today'
	 * 'wpforms_form_token_check_after_today'
	 *
	 * @since 1.6.2
	 * @since 1.7.1 Added the $form_data argument.
	 *
	 * @param array $form_data Form data and settings.
	 *
	 * @return array Array of all valid tokens to check against.
	 */
	public function get_valid_tokens( $form_data = [] ) {

		$current_date = time();

		// Create our array of times to check before today. A user with a longer
		// cache time can extend this. A user with a shorter cache time can remove times.
		$valid_token_times_before = apply_filters(
			'wpforms_form_token_check_before_today',
			[
				( 2 * DAY_IN_SECONDS ), // Two days ago.
				( 1 * DAY_IN_SECONDS ), // One day ago.
			]
		);

		// Mostly to catch edge cases like the form page loading and submitting on two different days.
		// This probably won't be filtered by users too much, but they could extend it.
		$valid_token_times_after = apply_filters(
			'wpforms_form_token_check_after_today',
			[
				( 45 * MINUTE_IN_SECONDS ), // Add in 45 minutes past today to catch some midnight edge cases.
			]
		);

		// Built up our valid tokens.
		$valid_tokens = [];

		// Add in all the previous times we check.
		foreach ( $valid_token_times_before as $time ) {
			$valid_tokens[] = $this->get( $current_date - $time, $form_data );
		}

		// Add in our current date.
		$valid_tokens[] = $this->get( $current_date, $form_data );

		// Add in the times after our check.
		foreach ( $valid_token_times_after as $time ) {
			$valid_tokens[] = $this->get( $current_date + $time, $form_data );
		}

		return $valid_tokens;
	}

	/**
	 * Check if the given token is valid or not.
	 *
	 * Tokens are valid for some period of time (see wpforms_token_validity_in_hours
	 * and wpforms_token_validity_in_days to extend the validation period).
	 * By default tokens are valid for day.
	 *
	 * @since 1.6.2
	 * @since 1.7.1 Added the $form_data argument.
	 *
	 * @param string $token     Token to validate.
	 * @param array  $form_data Form data and settings.
	 *
	 * @return bool Whether the token is valid or not.
	 */
	public function verify( $token, $form_data = [] ) {

		// Check to see if our token is inside the valid tokens.
		return in_array( $token, $this->get_valid_tokens( $form_data ), true );
	}

	/**
	 * Add the token to the form attributes.
	 *
	 * @since 1.6.2
	 * @since 1.7.1 Added the $form_data argument.
	 *
	 * @param array $attrs     Form attributes.
	 * @param array $form_data Form data and settings.
	 *
	 * @return array Form attributes.
	 */
	public function add_token_to_form_atts( array $attrs, array $form_data ) {

		$attrs['atts']['data-token'] = $this->get( true, $form_data );

		return $attrs;
	}

	/**
	 * Validate Anti-spam if enabled.
	 *
	 * @since 1.6.2
	 *
	 * @param array $form_data Form data.
	 * @param array $fields    Fields.
	 * @param array $entry     Form entry.
	 *
	 * @return bool|string True or a string with the error.
	 */
	public function validate( array $form_data, array $fields, array $entry ) {

		// Bail out if we don't have the antispam setting.
		if ( empty( $form_data['settings']['antispam'] ) ) {
			return true;
		}

		// Bail out if the antispam setting isn't enabled.
		if ( $form_data['settings']['antispam'] !== '1' ) {
			return true;
		}

		$valid = isset( $entry['token'] ) && $this->verify( $entry['token'], $form_data );
		$valid = $this->process_antispam_filter_wrapper( $valid, $fields, $entry, $form_data );

		if ( ! $valid ) {
			return $this->get_missing_token_message();
		}

		return true;
	}

	/**
	 * Helper to run our filter on all the responses for the antispam checks.
	 *
	 * @since 1.6.2
	 *
	 * @param bool  $is_valid_not_spam Is valid entry or not.
	 * @param array $fields            Form Fields.
	 * @param array $entry             Form entry.
	 * @param array $form_data         Form Data.
	 *
	 * @return bool Is valid or not.
	 */
	public function process_antispam_filter_wrapper( $is_valid_not_spam, array $fields, array $entry, array $form_data ) {

		return apply_filters( 'wpforms_process_antispam', $is_valid_not_spam, $fields, $entry, $form_data );
	}

	/**
	 * Helper to get the missing token message.
	 *
	 * @since 1.6.2.1
	 *
	 * @return string missing token message.
	 */
	private function get_missing_token_message() {

		return $this->get_error_message( esc_html__( 'This page isn\'t loading JavaScript properly, and the form will not be able to submit.', 'wpforms-lite' ) );
	}

	/**
	 * Helper to get the invalid token message.
	 *
	 * @since 1.6.2.1
	 *
	 * @return string Invalid token message.
	 */
	private function get_invalid_token_message() {

		return $this->get_error_message( esc_html__( 'Form token is invalid. Please refresh the page.', 'wpforms-lite' ) );
	}

	/**
	 * Get error message depends on user.
	 *
	 * @since 1.6.4.1
	 *
	 * @param string $text Message text.
	 *
	 * @return string
	 */
	private function get_error_message( $text ) {

		return wpforms_current_user_can() ? $text . $this->maybe_get_support_text() : $this->get_non_logged_user_error_message();
	}

	/**
	 * Non logged user error message.
	 *
	 * @since 1.6.4.1
	 *
	 * @return string
	 */
	private function get_non_logged_user_error_message() {

		return esc_html__( 'The form was unable to submit. Please contact the site administrator.', 'wpforms-lite' );
	}

	/**
	 * If a user is a super admin, add a support link to the message.
	 *
	 * @since 1.6.2.1
	 *
	 * @return string Support text if super admin, empty string if not.
	 */
	private function maybe_get_support_text() {

		// If user isn't a super admin, don't return any text.
		if ( ! is_super_admin() ) {
			return '';
		}

		// If the user is an admin, return text with a link to support.
		// We add a space here to separate the sentences, but outside of the localized
		// text to avoid it being removed.
		return ' ' . sprintf(
			// translators: placeholders are links.
			esc_html__( 'Please check out our %1$stroubleshooting guide%2$s for details on resolving this issue.', 'wpforms-lite' ),
			'<a href="https://wpforms.com/docs/getting-support-wpforms/">',
			'</a>'
		);
	}
}
