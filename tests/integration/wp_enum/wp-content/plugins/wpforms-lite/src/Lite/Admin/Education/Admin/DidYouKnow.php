<?php

namespace WPForms\Lite\Admin\Education\Admin;

use WP_List_Table;
use WPForms\Admin\Education\EducationInterface;
use WPForms\Lite\Integrations\LiteConnect\LiteConnect;
use WPForms\Lite\Integrations\LiteConnect\Integration as LiteConnectIntegration;

/**
 * Admin/DidYouKnow Education feature.
 *
 * @since 1.7.4
 */
class DidYouKnow implements EducationInterface {

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.7.4
	 *
	 * @return bool
	 */
	public function allow_load() {

		// Load only on the `All Forms` admin page.
		return wpforms_is_admin_page( 'overview' );
	}

	/**
	 * Init.
	 *
	 * @since 1.7.4
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
	 * @since 1.7.4
	 */
	private function hooks() {

		add_action( 'wpforms_admin_overview_after_rows', [ $this, 'display' ] );
	}

	/**
	 * Messages.
	 *
	 * @since 1.7.4
	 *
	 * @return array
	 */
	private function messages() {

		return [
			[
				'slug'       => 'lite-connect',
				'is_allowed' => LiteConnect::is_allowed(),
				'cont_class' => LiteConnect::is_enabled() ? 'wpforms-education-lite-connect-setting wpforms-hidden' : 'wpforms-education-lite-connect-setting',
				'title'      => esc_html__( 'Entries are not stored in WPForms Lite', 'wpforms-lite' ),
				'desc'       => esc_html__( 'Entries are available through email notifications. If you enable Entry Backups, you can restore them once you upgrade to WPForms Pro.', 'wpforms-lite' ),
				'more_title' => esc_html__( 'Enable Entry Backups', 'wpforms-lite' ),
				'more_link'  => admin_url( 'admin.php?page=wpforms-settings' ),
				'icon'       => '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 20 14"><path fill="#fff" d="M16.78 6.1a3 3 0 0 0-4.47-3.56A4.97 4.97 0 0 0 3 5v.28A4.48 4.48 0 0 0 4.5 14H16a4 4 0 0 0 4-4c0-1.9-1.38-3.53-3.22-3.9Zm-4.37 2-.35.34A.75.75 0 0 1 11 8.4l-1-1.07v3.91c0 .44-.34.75-.75.75h-.5a.72.72 0 0 1-.75-.75v-3.9L6.97 8.4a.75.75 0 0 1-1.06.03l-.35-.35c-.31-.3-.31-.78 0-1.06l2.9-2.9a.74.74 0 0 1 1.04 0l2.9 2.9c.32.28.32.75 0 1.06Z"/></svg>',
				'item'       => 1,
				'enabled'    => [
					'cont_class' => LiteConnect::is_enabled() ? 'wpforms-education-lite-connect-enabled-info' : 'wpforms-education-lite-connect-enabled-info wpforms-hidden',
					'title'      => esc_html__( 'Entries Backups Are Enabled', 'wpforms-lite' ),
					'more_title' => esc_html__( 'Restore Form Entries', 'wpforms-lite' ),
					'more_link'  => wpforms_admin_upgrade_link( 'forms-overview', 'restore-entries' ),
					'more_class' => 'wpforms-is-enabled',
					'desc'       => $this->get_lite_connect_entries_since_info(),
				],
			],
		];
	}

	/**
	 * Random message.
	 *
	 * @since 1.7.4
	 */
	private function message_rnd() {

		$messages = $this->messages();

		return $messages[ array_rand( $messages ) ];
	}

	/**
	 * Display message.
	 *
	 * @since 1.7.4
	 *
	 * @param WP_List_Table $wp_list_table Instance of WP_List_Table.
	 */
	public function display( $wp_list_table ) {

		$dismissed = get_user_meta( get_current_user_id(), 'wpforms_dismissed', true );

		// Do not display the message if it was dismissed.
		if ( ! empty( $dismissed['edu-admin-did-you-know-overview'] ) ) {
			return;
		}

		$message = $this->message_rnd();

		// Display the message only if it is allowed.
		if ( isset( $message['is_allowed'] ) && empty( $message['is_allowed'] ) ) {
			return;
		}

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'education/admin/did-you-know',
			[
				'slug'               => ! empty( $message['slug'] ) ? $message['slug'] : '',
				'cols'               => $wp_list_table->get_column_count(),
				'icon'               => ! empty( $message['icon'] ) ? $message['icon'] : '',
				'title'              => ! empty( $message['title'] ) ? $message['title'] : esc_html__( 'Did You Know?', 'wpforms-lite' ),
				'desc'               => ! empty( $message['desc'] ) ? $message['desc'] : '',
				'more_title'         => ! empty( $message['more_title'] ) ? $message['more_title'] : esc_html__( 'Learn More', 'wpforms-lite' ),
				'more_link'          => ! empty( $message['more_link'] ) ? $message['more_link'] : '',
				'more_class'         => ! empty( $message['more_class'] ) ? $message['more_class'] : '',
				'cont_class'         => ! empty( $message['cont_class'] ) ? $message['cont_class'] : '',
				'enabled_title'      => ! empty( $message['enabled']['title'] ) ? $message['enabled']['title'] : esc_html__( 'Did You Know?', 'wpforms-lite' ),
				'enabled_desc'       => ! empty( $message['enabled']['desc'] ) ? $message['enabled']['desc'] : '',
				'enabled_more_title' => ! empty( $message['enabled']['more_title'] ) ? $message['enabled']['more_title'] : esc_html__( 'Learn More', 'wpforms-lite' ),
				'enabled_more_link'  => ! empty( $message['enabled']['more_link'] ) ? $message['enabled']['more_link'] : '',
				'enabled_more_class' => ! empty( $message['enabled']['more_class'] ) ? $message['enabled']['more_class'] : '',
				'enabled_cont_class' => ! empty( $message['enabled']['cont_class'] ) ? $message['enabled']['cont_class'] : '',
			],
			true
		);
	}

	/**
	 * Generate Lite Connect entries information.
	 *
	 * @since 1.7.4
	 *
	 * @return string
	 */
	private function get_lite_connect_entries_since_info() {

		$entries_count = LiteConnectIntegration::get_new_entries_count();
		$enabled_since = LiteConnectIntegration::get_enabled_since();

		$string = sprintf(
			esc_html( /* translators: %d - Backed up entries count. */
				_n(
					'%d entry backed up',
					'%d entries backed up',
					$entries_count,
					'wpforms-lite'
				)
			),
			absint( $entries_count )
		);

		if ( ! empty( $enabled_since ) ) {
			$string .= ' ' . sprintf(
				/* translators: %s - Time when Lite Connect was enabled. */
				esc_html__( 'since %s', 'wpforms-lite' ),
				esc_html( date_i18n( 'M j, Y', $enabled_since + get_option( 'gmt_offset' ) * 3600 ) )
			);
		}

		return $string;
	}
}
