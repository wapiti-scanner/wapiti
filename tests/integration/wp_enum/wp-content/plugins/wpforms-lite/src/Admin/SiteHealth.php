<?php

namespace WPForms\Admin;

/**
 * Site Health WPForms Info.
 *
 * @since 1.5.5
 */
class SiteHealth {

	/**
	 * Indicate if Site Health is allowed to load.
	 *
	 * @since 1.5.5
	 *
	 * @return bool
	 */
	private function allow_load() {

		global $wp_version;

		return version_compare( $wp_version, '5.2', '>=' );
	}

	/**
	 * Init Site Health.
	 *
	 * @since 1.5.5
	 */
	final public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Integration hooks.
	 *
	 * @since 1.5.5
	 */
	protected function hooks() {

		add_filter( 'debug_information', [ $this, 'add_info_section' ] );
	}

	/**
	 * Add WPForms section to Info tab.
	 *
	 * @since 1.5.5
	 *
	 * @param array $debug_info Array of all information.
	 *
	 * @return array Array with added WPForms info section.
	 */
	public function add_info_section( $debug_info ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

		$wpforms = [
			'label'  => 'WPForms',
			'fields' => [
				'version' => [
					'label' => esc_html__( 'Version', 'wpforms-lite' ),
					'value' => WPFORMS_VERSION,
				],
			],
		];

		// Install date.
		$activated  = get_option( 'wpforms_activated', [] );
		$gmt_offset = get_option( 'gmt_offset' ) * 3600;

		if ( ! empty( $activated['lite'] ) ) {
			$date = $activated['lite'] + $gmt_offset;

			$wpforms['fields']['lite'] = [
				'label' => esc_html__( 'Lite install date', 'wpforms-lite' ),
				'value' => date_i18n( 'M j, Y @ g:ia', $date ),
			];
		}

		if ( ! empty( $activated['pro'] ) ) {
			$date = $activated['pro'] + $gmt_offset;

			$wpforms['fields']['pro'] = [
				'label' => esc_html__( 'Pro install date', 'wpforms-lite' ),
				'value' => date_i18n( 'M j, Y @ g:ia', $date ),
			];
		}

		// Permissions for the upload directory.
		$upload_dir                      = wpforms_upload_dir();
		$wpforms['fields']['upload_dir'] = [
			'label' => esc_html__( 'Uploads directory', 'wpforms-lite' ),
			'value' => empty( $upload_dir['error'] ) && ! empty( $upload_dir['path'] ) && wp_is_writable( $upload_dir['path'] ) ? esc_html__( 'Writable', 'wpforms-lite' ) : esc_html__( 'Not writable', 'wpforms-lite' ),
		];

		// DB tables.
		$db_tables = wpforms()->get_existing_custom_tables();

		if ( $db_tables ) {
			$db_tables_str = empty( $db_tables ) ? esc_html__( 'Not found', 'wpforms-lite' ) : implode( ', ', $db_tables );

			$wpforms['fields']['db_tables'] = [
				'label'   => esc_html__( 'DB tables', 'wpforms-lite' ),
				'value'   => $db_tables_str,
				'private' => true,
			];
		}

		// Total forms.
		$wpforms['fields']['total_forms'] = [
			'label' => esc_html__( 'Total forms', 'wpforms-lite' ),
			'value' => wp_count_posts( 'wpforms' )->publish,
		];

		if ( ! wpforms()->is_pro() ) {

			$forms = wpforms()->get( 'form' )->get( '', [ 'fields' => 'ids' ] );

			if ( empty( $forms ) || ! is_array( $forms ) ) {
				$forms = [];
			}

			$count = 0;

			foreach ( $forms as $form_id ) {
				$count += (int) get_post_meta( $form_id, 'wpforms_entries_count', true );
			}

			$wpforms['fields']['total_submissions'] = [
				'label' => esc_html__( 'Total submissions (since v1.5.0)', 'wpforms-lite' ),
				'value' => $count,
			];
		}

		$debug_info['wpforms'] = $wpforms;

		return $debug_info;
	}
}
