<?php

namespace WPForms\Forms;

/**
 * Class Submission.
 *
 * @since 1.7.4
 */
class Submission {

	/**
	 * The form fields.
	 *
	 * @since 1.7.4
	 *
	 * @var array
	 */
	protected $fields;

	/**
	 * The form entry.
	 *
	 * @since 1.7.4
	 *
	 * @var array
	 */
	private $entry;

	/**
	 * The form ID.
	 *
	 * @since 1.7.4
	 *
	 * @var int
	 */
	private $form_id;

	/**
	 * The form data.
	 *
	 * @since 1.7.4
	 *
	 * @var array
	 */
	protected $form_data;

	/**
	 * The date.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	private $date;

	/**
	 * Register the submission data.
	 *
	 * @since 1.7.4
	 *
	 * @param array $fields    The form fields.
	 * @param array $entry     The form entry.
	 * @param int   $form_id   The form ID.
	 * @param array $form_data The form data.
	 */
	public function register( array $fields, array $entry, $form_id, array $form_data = [] ) {

		$this->fields    = $fields;
		$this->entry     = $entry;
		$this->form_id   = $form_id;
		$this->form_data = $form_data;
		$this->date      = gmdate( 'Y-m-d H:i:s' );
	}

	/**
	 * Prepare the submission data.
	 *
	 * @since 1.7.4
	 *
	 * @return array|void
	 */
	public function prepare_entry_data() {

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName, WPForms.Comments.ParamTagHooks.InvalidParamTagsQuantity

		/**
		 * Provide the opportunity to disable entry saving.
		 *
		 * @since 1.0.0
		 *
		 * @param bool  $entry_save Entry save flag. Defaults to true.
		 * @param array $fields     Fields data.
		 * @param array $entry      Entry data.
		 * @param array $form_data  Form data.
		 */
		if ( ! apply_filters( 'wpforms_entry_save', true, $this->fields, $this->entry, $this->form_data ) ) {
			return;
		}

		/**
		 * Filter the entry data before saving.
		 *
		 * @since 1.0.0
		 *
		 * @param array $fields    Fields data.
		 * @param array $entry     Entry data.
		 * @param array $form_data Form data.
		 */
		$fields     = apply_filters( 'wpforms_entry_save_data', $this->fields, $this->entry, $this->form_data );
		$user_id    = is_user_logged_in() ? get_current_user_id() : 0;
		$user_ip    = wpforms_get_ip();
		$user_agent = ! empty( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 256 ) : '';
		$user_uuid  = wpforms_is_collecting_cookies_allowed() && ! empty( $_COOKIE['_wpfuuid'] ) ? sanitize_key( $_COOKIE['_wpfuuid'] ) : '';

		/**
		 * Allow developers disable saving user IP and User Agent within the entry.
		 *
		 * @since 1.5.1
		 *
		 * @param bool  $disable   True if you need to disable storing IP and UA within the entry. Defaults to false.
		 * @param array $fields    Fields data.
		 * @param array $form_data Form data.
		 */
		$is_ip_disabled = apply_filters( 'wpforms_disable_entry_user_ip', '__return_false', $fields, $this->form_data );

		// If GDPR enhancements are enabled and user details are disabled
		// globally or in the form settings, discard the IP and UA.
		if (
			! $is_ip_disabled ||
			! wpforms_is_collecting_ip_allowed( $this->form_data )
		) {
			$user_agent = '';
			$user_ip    = '';
		}

		/**
		 * Information about the entry, that is ready to be saved into the main entries table,
		 * which is used for displaying a list of entries and partially for search.
		 *
		 * @since 1.5.9
		 *
		 * @param array $entry_data Information about the entry, that will be saved into the DB.
		 * @param array $form_data  Form data.
		 */
		return (array) apply_filters(
			'wpforms_entry_save_args',
			[
				'form_id'    => absint( $this->form_id ),
				'user_id'    => absint( $user_id ),
				'fields'     => wp_json_encode( $fields ),
				'ip_address' => sanitize_text_field( $user_ip ),
				'user_agent' => sanitize_text_field( $user_agent ),
				'date'       => $this->date,
				'user_uuid'  => sanitize_text_field( $user_uuid ),
			],
			$this->form_data
		);
		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName, WPForms.Comments.ParamTagHooks.InvalidParamTagsQuantity
	}
}
