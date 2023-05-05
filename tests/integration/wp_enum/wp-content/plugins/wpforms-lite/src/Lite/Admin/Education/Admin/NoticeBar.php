<?php

namespace WPForms\Lite\Admin\Education\Admin;

use \WPForms\Admin\Education;

/**
 * Admin/NoticeBar Education feature for Lite.
 *
 * @since 1.6.6
 */
class NoticeBar implements Education\EducationInterface {

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wpforms_is_admin_page();
	}

	/**
	 * Init.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		// Define hooks.
		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_action( 'wpforms_admin_header_before', [ $this, 'display' ] );
	}

	/**
	 * Notice bar display message.
	 *
	 * @since 1.6.6
	 */
	public function display() {

		$dismissed = get_user_meta( get_current_user_id(), 'wpforms_dismissed', true );

		if ( ! empty( $dismissed['edu-admin-notice-bar'] ) ) {
			return;
		}

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'education/admin/notice-bar',
			[
				'upgrade_link' => wpforms_admin_upgrade_link( 'notice-bar', 'Upgrade to WPForms Pro' ),
			],
			true
		);
	}
}
