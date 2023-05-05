<?php

namespace WPForms\Lite\Admin\Education\Builder;

use WPForms\Admin\Education\EducationInterface;
use WPForms_Builder_Panel_Settings;

/**
 * Notifications Education feature.
 *
 * @since 1.7.7
 */
class Notifications implements EducationInterface {

	/**
	 * Init.
	 *
	 * @since 1.7.7
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.7.7
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wpforms_is_admin_page( 'builder' );
	}

	/**
	 * Load hooks.
	 *
	 * @since 1.7.7
	 */
	private function hooks() {

		add_action( 'wpforms_lite_form_settings_notifications_block_content_after', [ $this, 'advanced_section' ], 10, 2 );
	}

	/**
	 * Output Notification Advanced section.
	 *
	 * @since 1.7.7
	 *
	 * @param WPForms_Builder_Panel_Settings $settings Builder panel settings.
	 * @param int                            $id       Notification id.
	 */
	public function advanced_section( $settings, $id ) {

		$file_upload_attachment_panel = wpforms_panel_field(
			'toggle',
			'notifications',
			'file_upload_attachment_enable',
			$settings->form_data,
			esc_html__( 'Enable File Upload Attachments', 'wpforms-lite' ),
			[
				'input_class' => 'notifications_enable_file_upload_attachment_toggle education-modal',
				'parent'      => 'settings',
				'subsection'  => $id,
				'pro_badge'   => true,
				'data'        => [
					'action'      => 'upgrade',
					'name'        => esc_html__( 'File Upload Attachments', 'wpforms-lite' ),
					'utm-content' => 'File Upload Attachments',
					'licence'     => 'pro',
				],
				'attrs'       => [
					'disabled' => 'disabled',
				],
				'value'       => false,
			],
			false
		);

		$entry_csv_attachment_panel = wpforms_panel_field(
			'toggle',
			'notifications',
			'entry_csv_attachment_enable',
			$settings->form_data,
			esc_html__( 'Enable Entry CSV Attachment', 'wpforms-lite' ),
			[
				'input_class' => 'notifications_enable_entry_csv_attachment_toggle education-modal',
				'parent'      => 'settings',
				'subsection'  => $id,
				'pro_badge'   => true,
				'data'        => [
					'action'      => 'upgrade',
					'name'        => esc_html__( 'Entry CSV Attachment', 'wpforms-lite' ),
					'utm-content' => 'Entry CSV Attachment',
					'licence'     => 'pro',
				],
				'attrs'       => [
					'disabled' => 'disabled',
				],
				'value'       => false,
			],
			false
		);

		// Wrap advanced settings to the unfoldable group.
		wpforms_panel_fields_group(
			$file_upload_attachment_panel . $entry_csv_attachment_panel,
			[
				'borders'    => [ 'top' ],
				'class'      => 'wpforms-builder-notifications-advanced',
				'default'    => 'opened',
				'group'      => 'settings_notifications_advanced',
				'title'      => esc_html__( 'Advanced', 'wpforms-lite' ),
				'unfoldable' => true,
			]
		);
	}
}
