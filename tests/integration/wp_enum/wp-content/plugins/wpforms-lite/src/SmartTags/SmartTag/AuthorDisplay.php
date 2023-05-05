<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class AuthorDisplay.
 *
 * @since 1.6.7
 */
class AuthorDisplay extends SmartTag {

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

		$name = get_the_author();

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		if ( empty( $name ) && ! empty( $_POST['wpforms']['author'] ) ) {
			$name = get_the_author_meta( 'display_name', absint( $_POST['wpforms']['author'] ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		return ! empty( $name ) ? esc_html( wp_strip_all_tags( $name ) ) : '';
	}
}
