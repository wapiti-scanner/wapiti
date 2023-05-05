<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class PageUrl.
 *
 * @since 1.6.7
 */
class PageUrl extends SmartTag {

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

		// phpcs:ignore WordPress.Security.NonceVerification
		return empty( $_POST['page_url'] ) ? esc_url( wpforms_current_url() ) : esc_url( esc_url_raw( wp_unslash( $_POST['page_url'] ) ) );
	}
}
