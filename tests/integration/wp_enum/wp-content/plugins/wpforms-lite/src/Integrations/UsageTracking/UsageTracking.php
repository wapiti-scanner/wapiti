<?php

namespace WPForms\Integrations\UsageTracking;

use WPForms\Admin\Builder\Templates;
use WPForms\Integrations\IntegrationInterface;

/**
 * Usage Tracker functionality to understand what's going on on client's sites.
 *
 * @since 1.6.1
 */
class UsageTracking implements IntegrationInterface {

	/**
	 * The slug that will be used to save the option of Usage Tracker.
	 *
	 * @since 1.6.1
	 */
	const SETTINGS_SLUG = 'usage-tracking-enabled';

	/**
	 * Indicate if current integration is allowed to load.
	 *
	 * @since 1.6.1
	 *
	 * @return bool
	 */
	public function allow_load() {

		/**
		 * Whether the Usage Tracking code is allowed to be loaded.
		 *
		 * @since 1.6.1
		 *
		 * @param bool $var Boolean value.
		 */
		return (bool) apply_filters( 'wpforms_usagetracking_is_allowed', true ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Whether Usage Tracking is enabled.
	 *
	 * @since 1.6.1
	 *
	 * @return bool
	 */
	public function is_enabled() {

		/**
		 * Whether the Usage Tracking is enabled.
		 *
		 * @since 1.6.1
		 *
		 * @param bool $var Boolean value taken from the DB.
		 */
		return (bool) apply_filters( 'wpforms_integrations_usagetracking_is_enabled', wpforms_setting( self::SETTINGS_SLUG ) );  // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Load an integration.
	 *
	 * @since 1.6.1
	 */
	public function load() {

		add_filter( 'wpforms_settings_defaults', [ $this, 'settings_misc_option' ], 4 );

		// Deregister the action if option is disabled.
		add_action(
			'wpforms_settings_updated',
			function () {

				if ( ! $this->is_enabled() ) {
					( new SendUsageTask() )->cancel();
				}
			}
		);

		// Register the action handler only if enabled.
		if ( $this->is_enabled() ) {
			add_filter(
				'wpforms_tasks_get_tasks',
				static function ( $tasks ) {

					$tasks[] = SendUsageTask::class;

					return $tasks;
				}
			);
		}
	}

	/**
	 * Add "Allow Usage Tracking" to WPForms settings.
	 *
	 * @since 1.6.1
	 *
	 * @param array $settings WPForms settings.
	 *
	 * @return array
	 */
	public function settings_misc_option( $settings ) {

		$settings['misc'][ self::SETTINGS_SLUG ] = [
			'id'   => self::SETTINGS_SLUG,
			'name' => esc_html__( 'Allow Usage Tracking', 'wpforms-lite' ),
			'desc' => esc_html__( 'By allowing us to track usage data, we can better help you, as we will know which WordPress configurations, themes, and plugins we should test.', 'wpforms-lite' ),
			'type' => 'checkbox',
		];

		return $settings;
	}

	/**
	 * Get the User Agent string that will be sent to the API.
	 *
	 * @since 1.6.1
	 *
	 * @return string
	 */
	public function get_user_agent() {

		return 'WPForms/' . WPFORMS_VERSION . '; ' . get_bloginfo( 'url' );
	}

	/**
	 * Get data for sending to the server.
	 *
	 * @since 1.6.1
	 *
	 * @return array
	 */
	public function get_data() {

		global $wpdb;

		$theme_data        = wp_get_theme();
		$activated_dates   = get_option( 'wpforms_activated', [] );
		$first_form_date   = get_option( 'wpforms_forms_first_created' );
		$forms             = $this->get_all_forms();
		$forms_total       = count( $forms );
		$entries_total     = $this->get_entries_total();
		$form_fields_count = $this->get_form_fields_count( $forms );

		$data = [
			// Generic data (environment).
			'url'                            => home_url(),
			'php_version'                    => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
			'wp_version'                     => get_bloginfo( 'version' ),
			'mysql_version'                  => $wpdb->db_version(),
			'server_version'                 => isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '',
			'is_ssl'                         => is_ssl(),
			'is_multisite'                   => is_multisite(),
			'is_wpcom'                       => defined( 'IS_WPCOM' ) && IS_WPCOM,
			'is_wpcom_vip'                   => ( defined( 'WPCOM_IS_VIP_ENV' ) && WPCOM_IS_VIP_ENV ) || ( function_exists( 'wpcom_is_vip' ) && wpcom_is_vip() ),
			'is_wp_cache'                    => defined( 'WP_CACHE' ) && WP_CACHE,
			'sites_count'                    => $this->get_sites_total(),
			'active_plugins'                 => $this->get_active_plugins(),
			'theme_name'                     => $theme_data->name,
			'theme_version'                  => $theme_data->version,
			'locale'                         => get_locale(),
			'timezone_offset'                => $this->get_timezone_offset(),
			// WPForms-specific data.
			'wpforms_version'                => WPFORMS_VERSION,
			'wpforms_license_key'            => wpforms_get_license_key(),
			'wpforms_license_type'           => $this->get_license_type(),
			'wpforms_license_status'         => $this->get_license_status(),
			'wpforms_is_pro'                 => wpforms()->is_pro(),
			'wpforms_entries_avg'            => $this->get_entries_avg( $forms_total, $entries_total ),
			'wpforms_entries_total'          => $entries_total,
			'wpforms_entries_last_7days'     => $this->get_entries_total( '7days' ),
			'wpforms_entries_last_30days'    => $this->get_entries_total( '30days' ),
			'wpforms_forms_total'            => $forms_total,
			'wpforms_form_fields_count'      => $form_fields_count,
			'wpforms_challenge_stats'        => get_option( 'wpforms_challenge', [] ),
			'wpforms_lite_installed_date'    => $this->get_installed( $activated_dates, 'lite' ),
			'wpforms_pro_installed_date'     => $this->get_installed( $activated_dates, 'pro' ),
			'wpforms_builder_opened_date'    => (int) get_option( 'wpforms_builder_opened_date', 0 ),
			'wpforms_settings'               => $this->get_settings(),
			'wpforms_integration_active'     => $this->get_forms_integrations( $forms ),
			'wpforms_payments_active'        => $this->get_payments_active( $forms ),
			'wpforms_multiple_confirmations' => count( $this->get_forms_with_multiple_confirmations( $forms ) ),
			'wpforms_multiple_notifications' => count( $this->get_forms_with_multiple_notifications( $forms ) ),
			'wpforms_ajax_form_submissions'  => count( $this->get_ajax_form_submissions( $forms ) ),
		];

		if ( ! empty( $first_form_date ) ) {
			$data['wpforms_forms_first_created'] = $first_form_date;
		}

		return $data;
	}

	/**
	 * Get the license type.
	 *
	 * @since 1.6.1
	 * @since 1.7.2 Clarified the license type.
	 * @since 1.7.9 Return only the license type, not the status.
	 *
	 * @return string
	 */
	private function get_license_type() {

		return wpforms()->is_pro() ? wpforms_get_license_type() : 'lite';
	}

	/**
	 * Get the license status.
	 *
	 * @since 1.7.9
	 *
	 * @return string
	 */
	private function get_license_status() {

		if ( ! wpforms()->is_pro() ) {
			return 'lite';
		}

		$license_type = wpforms_get_license_type();
		$license_key  = wpforms_get_license_key();

		if ( ! $license_type ) {
			return empty( $license_key ) ? 'no license' : 'not verified';
		}

		if ( wpforms_setting( 'is_expired', false, 'wpforms_license' ) ) {
			return 'expired';
		}

		if ( wpforms_setting( 'is_disabled', false, 'wpforms_license' ) ) {
			return 'disabled';
		}

		if ( wpforms_setting( 'is_invalid', false, 'wpforms_license' ) ) {
			return 'invalid';
		}

		// The correct type is returned in get_license_type(), so we "collapse" them here to a single value.
		if ( in_array( $license_type, [ 'basic', 'plus', 'pro', 'elite', 'ultimate', 'agency' ], true ) ) {
			$license_type = 'correct';
		}

		return $license_type;
	}

	/**
	 * Get all settings, except those with sensitive data.
	 *
	 * @since 1.6.1
	 *
	 * @return array
	 */
	private function get_settings() {

		// Remove keys with exact names that we don't need.
		$settings = array_diff_key(
			get_option( 'wpforms_settings', [] ),
			array_flip(
				[
					'stripe-test-secret-key',
					'stripe-test-publishable-key',
					'stripe-live-secret-key',
					'stripe-live-publishable-key',
					'authorize_net-test-api-login-id',
					'authorize_net-test-transaction-key',
					'authorize_net-live-api-login-id',
					'authorize_net-live-transaction-key',
					'square-location-id-sandbox',
					'square-location-id-production',
					'geolocation-google-places-api-key',
					'geolocation-algolia-places-application-id',
					'geolocation-algolia-places-search-only-api-key',
					'geolocation-mapbox-search-access-token',
					'recaptcha-site-key',
					'recaptcha-secret-key',
					'recaptcha-fail-msg',
					'hcaptcha-site-key',
					'hcaptcha-secret-key',
					'hcaptcha-fail-msg',
				]
			)
		);

		$data = [];

		// Remove keys with a vague names that we don't need.
		foreach ( $settings as $key => $value ) {
			if ( strpos( $key, 'validation-' ) !== false ) {
				continue;
			}

			$data[ $key ] = $value;
		}

		// Add favorite templates to the settings array.
		return array_merge( $data, $this->get_favorite_templates() );
	}

	/**
	 * Get timezone offset.
	 * We use `wp_timezone_string()` when it's available (WP 5.3+),
	 * otherwise fallback to the same code, copy-pasted.
	 *
	 * @see wp_timezone_string()
	 *
	 * @since 1.6.1
	 *
	 * @return string
	 */
	private function get_timezone_offset() {

		// It was added in WordPress 5.3.
		if ( function_exists( 'wp_timezone_string' ) ) {
			return wp_timezone_string();
		}

		/*
		 * The code below is basically a copy-paste from that function.
		 */

		$timezone_string = get_option( 'timezone_string' );

		if ( $timezone_string ) {
			return $timezone_string;
		}

		$offset  = (float) get_option( 'gmt_offset' );
		$hours   = (int) $offset;
		$minutes = ( $offset - $hours );

		$sign      = ( $offset < 0 ) ? '-' : '+';
		$abs_hour  = abs( $hours );
		$abs_mins  = abs( $minutes * 60 );
		$tz_offset = sprintf( '%s%02d:%02d', $sign, $abs_hour, $abs_mins );

		return $tz_offset;
	}

	/**
	 * Get the list of active plugins.
	 *
	 * @since 1.6.1
	 *
	 * @return array
	 */
	private function get_active_plugins() {

		if ( ! function_exists( 'get_plugins' ) ) {
			include ABSPATH . '/wp-admin/includes/plugin.php';
		}
		$active  = get_option( 'active_plugins', [] );
		$plugins = array_intersect_key( get_plugins(), array_flip( $active ) );

		return array_map(
			static function ( $plugin ) {

				if ( isset( $plugin['Version'] ) ) {
					return $plugin['Version'];
				}

				return 'Not Set';
			},
			$plugins
		);
	}

	/**
	 * Installed date.
	 *
	 * @since 1.6.1
	 *
	 * @param array  $activated_dates Input array with dates.
	 * @param string $key             Input key what you want to get.
	 *
	 * @return mixed
	 */
	private function get_installed( $activated_dates, $key ) {

		if ( ! empty( $activated_dates[ $key ] ) ) {
			return $activated_dates[ $key ];
		}

		return false;
	}

	/**
	 * Number of forms with some integrations active.
	 *
	 * @since 1.6.1
	 *
	 * @param array $forms List of forms.
	 *
	 * @return array List of forms with active integrations count.
	 */
	private function get_forms_integrations( $forms ) {

		$integrations = array_map(
			static function ( $form ) {

				if ( ! empty( $form->post_content['providers'] ) ) {
					return array_keys( $form->post_content['providers'] );
				}

				return false;
			},
			$forms
		);

		$integrations = array_filter( $integrations );

		if ( count( $integrations ) > 0 ) {
			$integrations = call_user_func_array( 'array_merge', array_values( $integrations ) );
		}

		return array_count_values( $integrations );
	}

	/**
	 * Number of forms with active payments.
	 *
	 * @since 1.6.1
	 *
	 * @param array $forms Input forms list.
	 *
	 * @return array List of forms with active payments count.
	 */
	private function get_payments_active( $forms ) {

		$payments = array_map(
			static function ( $form ) {

				if ( empty( $form->post_content['payments'] ) ) {
					return false;
				}

				$enabled = [];

				foreach ( $form->post_content['payments'] as $key => $value ) {
					if ( ! empty( $value['enable'] ) ) {
						$enabled[] = $key;
					}
				}

				return empty( $enabled ) ? false : $enabled;
			},
			$forms
		);

		$payments = array_filter( $payments );

		if ( count( $payments ) > 0 ) {
			$payments = call_user_func_array( 'array_merge', array_values( $payments ) );
		}

		return array_count_values( $payments );
	}

	/**
	 * Forms with multiple notifications.
	 *
	 * @since 1.6.1
	 *
	 * @param array $forms List of forms to check.
	 *
	 * @return array List of forms with multiple notifications.
	 */
	private function get_forms_with_multiple_notifications( $forms ) {

		return array_filter(
			$forms,
			static function ( $form ) {

				return ! empty( $form->post_content['settings']['notifications'] ) && count( $form->post_content['settings']['notifications'] ) > 1;
			}
		);
	}

	/**
	 * Forms with multiple confirmations.
	 *
	 * @since 1.6.1
	 *
	 * @param array $forms List of forms to check.
	 *
	 * @return array List of forms with multiple confirmations.
	 */
	private function get_forms_with_multiple_confirmations( $forms ) {

		return array_filter(
			$forms,
			static function ( $form ) {

				return ! empty( $form->post_content['settings']['confirmations'] ) && count( $form->post_content['settings']['confirmations'] ) > 1;
			}
		);
	}

	/**
	 * Forms with ajax submission option enabled.
	 *
	 * @since 1.6.1
	 *
	 * @param array $forms All forms.
	 *
	 * @return array
	 */
	private function get_ajax_form_submissions( $forms ) {

		return array_filter(
			$forms,
			static function ( $form ) {

				return ! empty( $form->post_content['settings']['ajax_submit'] );
			}
		);
	}

	/**
	 * Total number of sites.
	 *
	 * @since 1.6.1
	 *
	 * @return int
	 */
	private function get_sites_total() {

		return function_exists( 'get_blog_count' ) ? (int) get_blog_count() : 1;
	}

	/**
	 * Total number of entries.
	 *
	 * @since 1.6.1
	 *
	 * @param string $period Which period should be counted? Possible values: 7days, 30days.
	 *                       Everything else will mean "all" entries.
	 *
	 * @return int
	 */
	private function get_entries_total( $period = 'all' ) {

		if ( ! wpforms()->is_pro() ) {

			switch ( $period ) {
				case '7days':
				case '30days':
					$count = 0;
					break;

				default:
					global $wpdb;
					$count = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
						"SELECT SUM(meta_value)
						FROM {$wpdb->postmeta}
						WHERE meta_key = 'wpforms_entries_count';"
					);
			}

			return $count;
		}

		$args = [];

		switch ( $period ) {
			case '7days':
				$args = [
					'date' => [
						gmdate( 'Y-m-d', strtotime( '-7 days' ) ),
						gmdate( 'Y-m-d' ),
					],
				];
				break;

			case '30days':
				$args = [
					'date' => [
						gmdate( 'Y-m-d', strtotime( '-30 days' ) ),
						gmdate( 'Y-m-d' ),
					],
				];
				break;
		}

		return wpforms()->entry->get_entries( $args, true );
	}

	/**
	 * Forms field occurrences.
	 *
	 * @since 1.7.9
	 *
	 * @param array $forms List of forms.
	 *
	 * @return array List of field occurrences in all forms created.
	 */
	private function get_form_fields_count( $forms ) {

		// Bail early, in case there are no forms created yet!
		if ( empty( $forms ) ) {
			return [];
		}

		$fields         = array_map(
			static function( $form ) {

				return isset( $form->post_content['fields'] ) ? $form->post_content['fields'] : [];
			},
			$forms
		);
		$fields_flatten = array_merge( [], ...$fields );
		$field_types    = array_column( $fields_flatten, 'type' );

		return array_count_values( $field_types );
	}

	/**
	 * Average entries count.
	 *
	 * @since 1.6.1
	 *
	 * @param int $forms   Total forms count.
	 * @param int $entries Total entries count.
	 *
	 * @return int
	 */
	private function get_entries_avg( $forms, $entries ) {

		return $forms ? round( $entries / $forms ) : 0;
	}

	/**
	 * Get all forms.
	 *
	 * @since 1.6.1
	 *
	 * @return array
	 */
	private function get_all_forms() {

		$forms = wpforms()->get( 'form' )->get( '' );

		if ( ! is_array( $forms ) ) {
			return [];
		}

		return array_map(
			static function( $form ) {

				$form->post_content = wpforms_decode( $form->post_content );

				return $form;
			},
			$forms
		);
	}

	/**
	 * Get the favorite templates.
	 *
	 * @since 1.7.7
	 *
	 * @return array
	 */
	private function get_favorite_templates() {

		$settings  = [];
		$templates = (array) get_option( Templates::FAVORITE_TEMPLATES_OPTION, [] );

		foreach ( $templates as $user_templates ) {
			foreach ( $user_templates as $template => $v ) {
				$name              = 'fav_templates_' . str_replace( '-', '_', $template );
				$settings[ $name ] = empty( $settings[ $name ] ) ? 1 : ++ $settings[ $name ];
			}
		}

		return $settings;
	}
}
