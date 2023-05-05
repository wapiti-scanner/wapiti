<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class AuthorId.
 *
 * @since 1.6.7
 */
class AuthorId extends SmartTag {

	/**
	 * Get smart tag value.
	 *
	 * @since 1.6.7
	 *
	 * @param array  $form_data Form data.
	 * @param array  $fields    List of fields.
	 * @param string $entry_id  Entry ID.
	 *
	 * @return int
	 */
	public function get_value( $form_data, $fields = [], $entry_id = '' ) {

		$id = get_the_author_meta( 'ID' );

		if ( empty( $id ) && ! empty( $_POST['wpforms']['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$id = get_the_author_meta( 'ID', absint( $_POST['wpforms']['author'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		}

		return absint( $id );
	}
}
