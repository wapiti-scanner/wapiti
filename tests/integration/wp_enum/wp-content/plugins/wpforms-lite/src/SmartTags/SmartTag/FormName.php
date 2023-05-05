<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class FormName.
 *
 * @since 1.6.7
 */
class FormName extends SmartTag {

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

		// TODO: Remove the conditional after Form Page v1.5.0 addon release.
		// The Form Pages addon rewrites the form_title setting for it's internal needs,
		// so we want to first check if we have a saved title for the form, and if so,
		// we will use that for the form title smart tag.
		if ( isset( $form_data['settings']['form_name'] ) && $form_data['settings']['form_name'] !== '' ) {
			return esc_html( wp_strip_all_tags( $form_data['settings']['form_name'] ) );
		}

		if ( ! isset( $form_data['settings']['form_title'] ) || $form_data['settings']['form_title'] === '' ) {
			return '';
		}

		return esc_html( wp_strip_all_tags( $form_data['settings']['form_title'] ) );
	}
}
