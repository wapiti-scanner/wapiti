<?php

namespace WPForms\Lite\Admin\Education\Builder;

use \WPForms\Admin\Education;

/**
 * Builder/Fields Education for Lite.
 *
 * @since 1.6.6
 */
class Fields extends Education\Builder\Fields {

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_filter( 'wpforms_builder_fields_buttons', [ $this, 'add_fields' ], 500 );
		add_filter( 'wpforms_builder_field_button_attributes', [ $this, 'fields_attributes' ], 100, 2 );
		add_action( 'wpforms_field_options_after_advanced-options', [ $this, 'field_conditional_logic' ] );
	}

	/**
	 * Add fields.
	 *
	 * @since 1.6.6
	 *
	 * @param array $fields Form fields.
	 *
	 * @return array
	 */
	public function add_fields( $fields ) {

		foreach ( $fields as $group => $group_data ) {
			$edu_fields = $this->fields->get_by_group( $group );
			$edu_fields = $this->fields->set_values( $edu_fields, 'class', 'education-modal', 'empty' );

			foreach ( $edu_fields as $edu_field ) {

				// Skip if in the current group already exist field of this type.
				if ( ! empty( wp_list_filter( $group_data, [ 'type' => $edu_field['type'] ] ) ) ) {
					continue;
				}

				$addon = ! empty( $edu_field['addon'] ) ? $this->addons->get_addon( $edu_field['addon'] ) : [];

				if ( ! empty( $addon ) ) {
					$edu_field['license'] = isset( $addon['license_level'] ) ? $addon['license_level'] : '';
				}

				$fields[ $group ]['fields'][] = $edu_field;
			}
		}

		return $fields;
	}

	/**
	 * Display conditional logic settings section for fields inside the form builder.
	 *
	 * @since 1.6.6
	 *
	 * @param array $field Field data.
	 */
	public function field_conditional_logic( $field ) {

		// Certain fields don't support conditional logic.
		if ( in_array( $field['type'], [ 'pagebreak', 'divider', 'hidden' ], true ) ) {
			return;
		}
		?>

		<div class="wpforms-field-option-group wpforms-field-option-group-conditionals">
			<a href="#"
				class="wpforms-field-option-group-toggle education-modal"
				data-name="<?php esc_attr_e( 'Smart Conditional Logic', 'wpforms-lite' ); ?>"
				data-utm-content="Smart Conditional Logic">
				<?php esc_html_e( 'Smart Logic', 'wpforms-lite' ); ?>
			</a>
		</div>
		<?php
	}

	/**
	 * Adjust attributes on field buttons.
	 *
	 * @since 1.6.6
	 *
	 * @param array $atts  Button attributes.
	 * @param array $field Button properties.
	 *
	 * @return array Attributes array.
	 */
	public function fields_attributes( $atts, $field ) {

		$atts['data']['utm-content'] = ! empty( $field['name_en'] ) ? $field['name_en'] : '';

		if ( ! empty( $field['class'] ) && $field['class'] === 'education-modal' ) {
			$atts['class'][] = 'wpforms-not-available';
		}

		if ( empty( $field['addon'] ) ) {
			return $atts;
		}

		$addon = $this->addons->get_addon( $field['addon'] );

		if ( empty( $addon ) ) {
			return $atts;
		}

		if ( ! empty( $addon['video'] ) ) {
			$atts['data']['video'] = $addon['video'];
		}

		if ( ! empty( $field['license'] ) ) {
			$atts['data']['license'] = $field['license'];
		}

		return $atts;
	}
}
