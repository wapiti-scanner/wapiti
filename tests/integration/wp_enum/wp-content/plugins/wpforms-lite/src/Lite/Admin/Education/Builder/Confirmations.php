<?php

namespace WPForms\Lite\Admin\Education\Builder;

use WPForms_Builder_Panel_Settings;
use WPForms\Admin\Education\EducationInterface;

/**
 * Confirmations Education feature.
 *
 * @since 1.6.9
 */
class Confirmations implements EducationInterface {

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.6.9
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wpforms_is_admin_page( 'builder' );
	}

	/**
	 * Init.
	 *
	 * @since 1.6.9
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Load hooks.
	 *
	 * @since 1.6.9
	 */
	private function hooks() {

		add_action( 'wpforms_lite_form_settings_confirmations_single_after', [ $this, 'entry_preview_settings' ], 10, 2 );
	}

	/**
	 * Add education settings located in confirmation inside the message block.
	 *
	 * @since 1.6.9
	 *
	 * @param WPForms_Builder_Panel_Settings $settings Builder panel settings.
	 * @param int                            $field_id Field ID.
	 */
	public function entry_preview_settings( $settings, $field_id ) {

		wpforms_panel_field(
			'toggle',
			'confirmations',
			'message_entry_preview',
			$settings->form_data,
			esc_html__( 'Show entry preview after confirmation', 'wpforms-lite' ),
			[
				'input_id'    => 'wpforms-panel-field-confirmations-message_entry_preview-' . absint( $field_id ),
				'input_class' => 'wpforms-panel-field-confirmations-message_entry_preview education-modal',
				'parent'      => 'settings',
				'subsection'  => absint( $field_id ),
				'pro_badge'   => true,
				'data'        => [
					'action'      => 'upgrade',
					'name'        => esc_html__( 'Show Entry Preview', 'wpforms-lite' ),
					'utm-content' => 'Show Entry Preview',
					'licence'     => 'pro',
				],
				'attrs'       => [
					'disabled' => 'disabled',
				],
				'value'       => false,
			]
		);
	}
}
