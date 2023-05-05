<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class PageId.
 *
 * @since 1.6.7
 */
class PageId extends SmartTag {

	/**
	 * Get smart tag value.
	 *
	 * @since 1.6.7
	 *
	 * @param array  $form_data Form data.
	 * @param array  $fields    List of fields.
	 * @param string $entry_id  Entry ID.
	 *
	 * @return int|string
	 */
	public function get_value( $form_data, $fields = [], $entry_id = '' ) {

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['page_id'] ) ) {
			return absint( $_POST['page_id'] );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		// We should not return any value on pages that don't belong to the page type.
		return is_singular() || ( is_front_page() && is_page() ) ? get_the_ID() : '';
	}
}
