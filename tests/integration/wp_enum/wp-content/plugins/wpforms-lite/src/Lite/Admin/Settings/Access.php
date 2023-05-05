<?php

namespace WPForms\Lite\Admin\Settings;

/**
 * Settings Access tab.
 *
 * @since 1.5.8
 */
class Access {

	/**
	 * View slug.
	 *
	 * @since 1.5.8
	 *
	 * @var string
	 */
	const SLUG = 'access';

	/**
	 * Constructor.
	 *
	 * @since 1.5.8
	 */
	public function __construct() {

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.5.8
	 */
	public function hooks() {

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );
		add_filter( 'wpforms_settings_tabs', [ $this, 'add_tab' ] );
		add_filter( 'wpforms_settings_defaults', [ $this, 'add_section' ] );
	}

	/**
	 * Enqueues.
	 *
	 * @since 1.5.8
	 */
	public function enqueues() {

		if ( ! wpforms_is_admin_page( 'settings', self::SLUG ) ) {
			return;
		}

		// Lity.
		wp_enqueue_style(
			'wpforms-lity',
			WPFORMS_PLUGIN_URL . 'assets/lib/lity/lity.min.css',
			null,
			'3.0.0'
		);

		wp_enqueue_script(
			'wpforms-lity',
			WPFORMS_PLUGIN_URL . 'assets/lib/lity/lity.min.js',
			[ 'jquery' ],
			'3.0.0',
			true
		);
	}

	/**
	 * Add Access tab.
	 *
	 * @since 1.5.8
	 *
	 * @param array $tabs Array of tabs.
	 *
	 * @return array Array of tabs.
	 */
	public function add_tab( $tabs ) {

		$tab = [
			self::SLUG => [
				'name'   => esc_html__( 'Access', 'wpforms-lite' ),
				'form'   => false,
				'submit' => false,
			],
		];

		return wpforms_list_insert_after( $tabs, 'geolocation', $tab );
	}

	/**
	 * Add Access settings section.
	 *
	 * @since 1.5.8
	 *
	 * @param array $settings Settings sections.
	 *
	 * @return array
	 */
	public function add_section( $settings ) {

		$section_rows = [
			'heading',
			'screenshots',
			'caps',
			'upgrade_to_pro',
		];

		foreach ( $section_rows as $section_row ) {

			$settings[ self::SLUG ][ self::SLUG . '-' . $section_row ] = [
				'id'       => self::SLUG . '-' . $section_row,
				'content'  => method_exists( $this, 'output_section_row_' . $section_row ) ? $this->{ 'output_section_row_' . $section_row }() : '',
				'type'     => 'content',
				'no_label' => true,
				'class'    => [ $section_row ],
			];
		}

		return $settings;
	}

	/**
	 * Generate and output section "Heading" row HTML.
	 *
	 * @since 1.5.8
	 */
	public function output_section_row_heading() {

		return sprintf(
			'<h4>%1$s<img src="%2$s" alt="%3$s"></h4><p>%4$s</p><p>%5$s</p>',
			esc_html__( 'Access Controls', 'wpforms-lite' ),
			esc_url( WPFORMS_PLUGIN_URL . 'assets/images/lite-settings-access/pro-plus.svg' ),
			esc_attr__( 'Pro+', 'wpforms-lite' ),
			esc_html__( 'Access controls allows you to manage and customize access to WPForms functionality.', 'wpforms-lite' ),
			esc_html__( 'You can easily grant or restrict access using the simple built-in controls, or use our official integrations with Members and User Role Editor plugins.', 'wpforms-lite' )
		);
	}

	/**
	 * Generate and output section "Screenshots" row HTML.
	 *
	 * @since 1.5.8
	 */
	public function output_section_row_screenshots() {

		$format = '<div class="cont">
			<img src="%1$s" srcset="%2$s 2x" alt="%6$s"/>
			<a href="%3$s" class="hover" data-lity data-lity-srcset="%4$s 2x" data-lity-desc="%6$s"></a>
			<span>%5$s</span>
		</div>';

		$images_url = WPFORMS_PLUGIN_URL . 'assets/images/lite-settings-access/';

		$content = sprintf(
			$format,
			esc_url( $images_url . 'thumbnail-access-controls.png' ),
			esc_url( $images_url . 'thumbnail-access-controls@2x.png' ),
			esc_url( $images_url . 'screenshot-access-controls.png' ),
			esc_url( $images_url . 'screenshot-access-controls@2x.png' ),
			esc_html__( 'Simple Built-in Controls', 'wpforms-lite' ),
			esc_attr( esc_html__( 'Simple Built-in Controls', 'wpforms-lite' ) )
		);

		$content .= sprintf(
			$format,
			esc_url( $images_url . 'thumbnail-members.png' ),
			esc_url( $images_url . 'thumbnail-members@2x.png' ),
			esc_url( $images_url . 'screenshot-members.png' ),
			esc_url( $images_url . 'screenshot-members@2x.png' ),
			esc_html__( 'Members Integration', 'wpforms-lite' ),
			esc_attr( esc_html__( 'Members Integration', 'wpforms-lite' ) )
		);

		$content .= sprintf(
			$format,
			esc_url( $images_url . 'thumbnail-user-role-editor.png' ),
			esc_url( $images_url . 'thumbnail-user-role-editor@2x.png' ),
			esc_url( $images_url . 'screenshot-user-role-editor.png' ),
			esc_url( $images_url . 'screenshot-user-role-editor@2x.png' ),
			esc_html__( 'User Role Editor Integration', 'wpforms-lite' ),
			esc_attr( esc_html__( 'User Role Editor Integration', 'wpforms-lite' ) )
		);

		return $content;
	}

	/**
	 * Generate and output section "Capabilities" row HTML.
	 *
	 * @since 1.5.8
	 */
	public function output_section_row_caps() {

		$caps = [
			[
				esc_html__( 'Create Forms', 'wpforms-lite' ),
				esc_html__( 'Edit Forms', 'wpforms-lite' ),
				esc_html__( 'Edit Others Forms', 'wpforms-lite' ),
				esc_html__( 'View Forms', 'wpforms-lite' ),
				esc_html__( 'View Others Forms', 'wpforms-lite' ),
			],
			[
				esc_html__( 'Delete Forms', 'wpforms-lite' ),
				esc_html__( 'Delete Others Forms', 'wpforms-lite' ),
				esc_html__( 'View Forms Entries', 'wpforms-lite' ),
				esc_html__( 'View Others Forms Entries', 'wpforms-lite' ),
			],
			[
				esc_html__( 'Edit Forms Entries', 'wpforms-lite' ),
				esc_html__( 'Edit Others Forms Entries', 'wpforms-lite' ),
				esc_html__( 'Delete Forms Entries', 'wpforms-lite' ),
				esc_html__( 'Delete Others Forms Entries', 'wpforms-lite' ),
			],
		];

		$content = '<p>' . esc_html__( 'Custom access to the following capabilities…', 'wpforms-lite' ) . '</p>';

		foreach ( $caps as $column ) {
			$content .= '<ul>';
			foreach ( $column as $cap ) {
				$content .= '<li>' . $cap . '</li>';
			}
			$content .= '</ul>';
		}

		return $content;
	}

	/**
	 * Generate and output section "Upgrade to Pro" row HTML.
	 *
	 * @since 1.5.8
	 */
	public function output_section_row_upgrade_to_pro() {

		return sprintf(
			'<a href="%1$s" target="_blank" rel="noopener noreferrer" class="wpforms-upgrade-modal wpforms-btn wpforms-btn-lg wpforms-btn-orange">%2$s</a>',
			esc_url( wpforms_admin_upgrade_link( 'Settings - Access', 'Access Controls' ) ),
			esc_html__( 'Upgrade to WPForms Pro', 'wpforms-lite' )
		);
	}
}
