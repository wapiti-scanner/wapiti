<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class AuthorEmail.
 *
 * @since 1.6.7
 */
class AuthorEmail extends SmartTag {

	/**
	 * Get smart tag value.
	 *
	 * @since 1.6.7
	 *
	 * @param array  $form_data Form data.
	 * @param array  $fields    List of fields.
	 * @param string $entry_id  Entry ID.
	 *
	 * @return string
	 */
	public function get_value( $form_data, $fields = [], $entry_id = '' ) {

		$email = get_the_author_meta( 'user_email' );

		if ( empty( $email ) && ! empty( $_POST['wpforms']['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$email = get_the_author_meta( 'user_email', absint( $_POST['wpforms']['author'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		}

		return ! empty( $email ) ? sanitize_email( $email ) : '';
	}
}
