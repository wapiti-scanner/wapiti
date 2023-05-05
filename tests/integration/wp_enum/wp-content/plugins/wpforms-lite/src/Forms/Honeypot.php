<?php

namespace WPForms\Forms;

/**
 * Class Honeypot.
 *
 * @since 1.6.2
 */
class Honeypot {

	/**
	 * Initialise the actions for the Honeypot.
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

		add_action( 'wpforms_frontend_output', [ $this, 'render' ], 15, 5 );
	}

	/**
	 * Return function to render the honeypot.
	 *
	 * @since 1.6.2
	 *
	 * @param array $form_data Form data and settings.
	 */
	public function render( $form_data ) {

		if (
			empty( $form_data['settings']['honeypot'] ) ||
			'1' !== $form_data['settings']['honeypot']
		) {
			return;
		}

		$names = [ 'Name', 'Phone', 'Comment', 'Message', 'Email', 'Website' ];

		echo '<div class="wpforms-field wpforms-field-hp">';

		echo '<label for="wpforms-' . $form_data['id'] . '-field-hp" class="wpforms-field-label">' . $names[ array_rand( $names ) ] . '</label>'; // phpcs:ignore

		echo '<input type="text" name="wpforms[hp]" id="wpforms-' . $form_data['id'] . '-field-hp" class="wpforms-field-medium">';  // phpcs:ignore

		echo '</div>';
	}

	/**
	 * Validate honeypot.
	 *
	 * @since 1.6.2
	 *
	 * @param array $form_data Form data.
	 * @param array $fields    Fields.
	 * @param array $entry     Form entry.
	 *
	 * @return bool|string False or an string with the error.
	 */
	public function validate( array $form_data, array $fields, array $entry ) {

		$honeypot = false;

		if (
			! empty( $form_data['settings']['honeypot'] ) &&
			'1' === $form_data['settings']['honeypot'] &&
			! empty( $entry['hp'] )
		) {
			$honeypot = esc_html__( 'WPForms honeypot field triggered.', 'wpforms-lite' );
		}

		// If we get passed an empty fields array, but we have the data in our form data, use it.
		if ( empty( $fields ) && isset( $form_data['fields'] ) ) {
			$fields = $form_data['fields'];
		}

		return apply_filters( 'wpforms_process_honeypot', $honeypot, $fields, $entry, $form_data );
	}
}
