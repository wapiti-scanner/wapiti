<?php

namespace WPForms\Admin\Dashboard;

/**
 * Class Widget.
 *
 * @since 1.7.3
 */
abstract class Widget {

	/**
	 * Instance slug.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const SLUG = 'dash_widget';

	/**
	 * Save a widget meta for a current user using AJAX.
	 *
	 * @since 1.7.4
	 */
	public function save_widget_meta_ajax() {

		check_ajax_referer( 'wpforms_' . static::SLUG . '_nonce' );

		$meta  = ! empty( $_POST['meta'] ) ? sanitize_key( $_POST['meta'] ) : '';
		$value = ! empty( $_POST['value'] ) ? absint( $_POST['value'] ) : 0;

		$this->widget_meta( 'set', $meta, $value );

		exit();
	}

	/**
	 * Get/set a widget meta.
	 *
	 * @since 1.7.4
	 *
	 * @param string $action Possible value: 'get' or 'set'.
	 * @param string $meta   Meta name.
	 * @param int    $value  Value to set.
	 *
	 * @return mixed
	 */
	protected function widget_meta( $action, $meta, $value = 0 ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

		$allowed_actions = [ 'get', 'set' ];

		if ( ! in_array( $action, $allowed_actions, true ) ) {
			return false;
		}

		$defaults = [
			'timespan'               => $this->get_timespan_default(),
			'active_form_id'         => 0,
			'hide_recommended_block' => 0,
			'hide_graph'             => 0,
			'color_scheme'           => 1, // 1 - wpforms, 2 - wp
			'graph_style'            => 2, // 1 - bar, 2 - line
		];

		if ( ! array_key_exists( $meta, $defaults ) ) {
			return false;
		}

		$meta_key = 'wpforms_' . static::SLUG . '_' . $meta;

		if ( $action === 'get' ) {
			$meta_value = absint( get_user_meta( get_current_user_id(), $meta_key, true ) );
			// Return a default value from $defaults if $meta_value is empty.

			return empty( $meta_value ) ? $defaults[ $meta ] : $meta_value;
		}

		$value = absint( $value );

		if ( $action === 'set' && ! empty( $value ) ) {
			return update_user_meta( get_current_user_id(), $meta_key, $value );
		}

		if ( $action === 'set' && empty( $value ) ) {
			return delete_user_meta( get_current_user_id(), $meta_key );
		}

		return false;
	}

	/**
	 * Get the default timespan option.
	 *
	 * @since 1.7.4
	 *
	 * @return int|null
	 */
	protected function get_timespan_default() {

		$options = $this->get_timespan_options();
		$default = reset( $options );

		return is_numeric( $default ) ? $default : null;
	}

	/**
	 * Get timespan options (in days).
	 *
	 * @since 1.7.4
	 *
	 * @return array
	 */
	protected function get_timespan_options() {

		$default = [ 7, 30 ];

		$options = $default;

		// Apply deprecated filters.
		if ( function_exists( 'apply_filters_deprecated' ) ) {
			// phpcs:disable WPForms.Comments.PHPDocHooks.RequiredHookDocumentation, WPForms.PHP.ValidateHooks.InvalidHookName
			$options = apply_filters_deprecated( 'wpforms_dash_widget_chart_timespan_options', [ $options ], '5.0', 'wpforms_dash_widget_timespan_options' );
			$options = apply_filters_deprecated( 'wpforms_dash_widget_forms_list_timespan_options', [ $options ], '5.0', 'wpforms_dash_widget_timespan_options' );
			// phpcs:enable WPForms.Comments.PHPDocHooks.RequiredHookDocumentation, WPForms.PHP.ValidateHooks.InvalidHookName
		} else {
			// phpcs:disable WPForms.Comments.PHPDocHooks.RequiredHookDocumentation, WPForms.PHP.ValidateHooks.InvalidHookName
			$options = apply_filters( 'wpforms_dash_widget_chart_timespan_options', $options );
			$options = apply_filters( 'wpforms_dash_widget_forms_list_timespan_options', $options );
			// phpcs:enable WPForms.Comments.PHPDocHooks.RequiredHookDocumentation, WPForms.PHP.ValidateHooks.InvalidHookName
		}

		if ( ! is_array( $options ) ) {
			$options = $default;
		}

		$widget_slug = static::SLUG;

		// phpcs:disable WPForms.Comments.PHPDocHooks.RequiredHookDocumentation, WPForms.PHP.ValidateHooks.InvalidHookName
		$options = apply_filters( "wpforms_{$widget_slug}_timespan_options", $options );
		// phpcs:enable WPForms.Comments.PHPDocHooks.RequiredHookDocumentation, WPForms.PHP.ValidateHooks.InvalidHookName
		if ( ! is_array( $options ) ) {
			return [];
		}

		$options = array_filter( $options, 'is_numeric' );

		return empty( $options ) ? $default : $options;
	}

	/**
	 * Widget settings HTML.
	 *
	 * @since 1.7.4
	 *
	 * @param bool $enabled Is form fields should be enabled.
	 */
	protected function widget_settings_html( $enabled = true ) {

		$graph_style  = $this->widget_meta( 'get', 'graph_style' );
		$color_scheme = $this->widget_meta( 'get', 'color_scheme' );

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'admin/dashboard/widget/settings',
			[
				'graph_style'  => $graph_style,
				'color_scheme' => $color_scheme,
				'enabled'      => $enabled,
			],
			true
		);
	}

	/**
	 * Return randomly chosen one of recommended plugins.
	 *
	 * @since 1.7.3
	 *
	 * @return array
	 */
	final protected function get_recommended_plugin() {

		$plugins = [
			'google-analytics-for-wordpress/googleanalytics.php' => [
				'name' => __( 'MonsterInsights', 'wpforms-lite' ),
				'slug' => 'google-analytics-for-wordpress',
				'more' => 'https://www.monsterinsights.com/',
				'pro'  => [
					'file' => 'google-analytics-premium/googleanalytics-premium.php',
				],
			],
			'all-in-one-seo-pack/all_in_one_seo_pack.php' => [
				'name' => __( 'AIOSEO', 'wpforms-lite' ),
				'slug' => 'all-in-one-seo-pack',
				'more' => 'https://aioseo.com/',
				'pro'  => [
					'file' => 'all-in-one-seo-pack-pro/all_in_one_seo_pack.php',
				],
			],
			'coming-soon/coming-soon.php'                 => [
				'name' => __( 'SeedProd', 'wpforms-lite' ),
				'slug' => 'coming-soon',
				'more' => 'https://www.seedprod.com/',
				'pro'  => [
					'file' => 'seedprod-coming-soon-pro-5/seedprod-coming-soon-pro-5.php',
				],
			],
			'wp-mail-smtp/wp_mail_smtp.php'               => [
				'name' => __( 'WP Mail SMTP', 'wpforms-lite' ),
				'slug' => 'wp-mail-smtp',
				'more' => 'https://wpmailsmtp.com/',
				'pro'  => [
					'file' => 'wp-mail-smtp-pro/wp_mail_smtp.php',
				],
			],
		];

		$installed = get_plugins();

		foreach ( $plugins as $id => $plugin ) {

			if ( isset( $installed[ $id ] ) ) {
				unset( $plugins[ $id ] );
			}

			if ( isset( $plugin['pro']['file'], $installed[ $plugin['pro']['file'] ] ) ) {
				unset( $plugins[ $id ] );
			}
		}

		return $plugins ? $plugins[ array_rand( $plugins ) ] : [];
	}

	/**
	 * Timespan select HTML.
	 *
	 * @since 1.7.4
	 *
	 * @param int  $active_form_id Currently preselected form ID.
	 * @param bool $enabled        If the select menu items should be enabled.
	 */
	protected function timespan_select_html( $active_form_id, $enabled = true ) {
		?>
		<select id="wpforms-dash-widget-timespan" class="wpforms-dash-widget-select-timespan" title="<?php esc_attr_e( 'Select timespan', 'wpforms-lite' ); ?>"
			<?php echo ! empty( $active_form_id ) ? 'data-active-form-id="' . absint( $active_form_id ) . '"' : ''; ?>>
			<?php $this->timespan_options_html( $this->get_timespan_options(), $enabled ); ?>
		</select>

		<?php
	}

	/**
	 * Timespan select options HTML.
	 *
	 * @since 1.7.4
	 *
	 * @param array $options Timespan options (in days).
	 * @param bool  $enabled If the select menu items should be enabled.
	 */
	protected function timespan_options_html( $options, $enabled = true ) {

		$timespan = $this->widget_meta( 'get', 'timespan' );

		foreach ( $options as $option ) :
			?>
			<option value="<?php echo absint( $option ); ?>" <?php selected( $timespan, absint( $option ) ); ?> <?php disabled( ! $enabled ); ?>>
				<?php /* translators: %d - Number of days. */ ?>
				<?php echo esc_html( sprintf( _n( 'Last %d day', 'Last %d days', absint( $option ), 'wpforms-lite' ), absint( $option ) ) ); ?>
			</option>
		<?php
		endforeach;
	}
}
