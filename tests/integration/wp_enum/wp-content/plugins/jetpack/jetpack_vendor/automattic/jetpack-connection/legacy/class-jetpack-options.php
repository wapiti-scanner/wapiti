<?php
/**
 * Legacy Jetpack_Options class.
 *
 * @package automattic/jetpack-connection
 */

use Automattic\Jetpack\Constants;

/**
 * Class Jetpack_Options
 */
class Jetpack_Options {

	/**
	 * An array that maps a grouped option type to an option name.
	 *
	 * @var array
	 */
	private static $grouped_options = array(
		'compact' => 'jetpack_options',
		'private' => 'jetpack_private_options',
	);

	/**
	 * Returns an array of option names for a given type.
	 *
	 * @param string $type The type of option to return. Defaults to 'compact'.
	 *
	 * @return array
	 */
	public static function get_option_names( $type = 'compact' ) {
		switch ( $type ) {
			case 'non-compact':
			case 'non_compact':
				return array(
					'activated',
					'active_modules',
					'active_modules_initialized', // (bool) used to determine that all the default modules were activated, so we know how to act on a reconnection.
					'allowed_xsite_search_ids', // (array) Array of WP.com blog ids that are allowed to search the content of this site
					'available_modules',
					'do_activate',
					'edit_links_calypso_redirect', // (bool) Whether post/page edit links on front end should point to Calypso.
					'log',
					'slideshow_background_color',
					'widget_twitter',
					'wpcc_options',
					'relatedposts',
					'file_data',
					'autoupdate_plugins',          // (array)  An array of plugin ids ( eg. jetpack/jetpack ) that should be autoupdated
					'autoupdate_plugins_translations', // (array)  An array of plugin ids ( eg. jetpack/jetpack ) that should be autoupdated translation files.
					'autoupdate_themes',           // (array)  An array of theme ids ( eg. twentyfourteen ) that should be autoupdated
					'autoupdate_themes_translations', // (array)  An array of theme ids ( eg. twentyfourteen ) that should autoupdated translation files.
					'autoupdate_core',             // (bool)   Whether or not to autoupdate core
					'autoupdate_translations',     // (bool)   Whether or not to autoupdate all translations
					'json_api_full_management',    // (bool)   Allow full management (eg. Activate, Upgrade plugins) of the site via the JSON API.
					'sync_non_public_post_stati',  // (bool)   Allow synchronisation of posts and pages with non-public status.
					'site_icon_url',               // (string) url to the full site icon
					'site_icon_id',                // (int)    Attachment id of the site icon file
					'dismissed_manage_banner',     // (bool) Dismiss Jetpack manage banner allows the user to dismiss the banner permanently
					'unique_connection',           // (array)  A flag to determine a unique connection to wordpress.com two values "connected" and "disconnected" with values for how many times each has occured
					'unique_registrations',        // (integer) A counter of how many times the site was registered
					'protect_whitelist',           // (array) IP Address for the Protect module to ignore
					'sync_error_idc',              // (bool|array) false or array containing the site's home and siteurl at time of IDC error
					'sync_health_status',          // (bool|array) An array of data relating to Jetpack's sync health.
					'safe_mode_confirmed',         // (bool) True if someone confirms that this site was correctly put into safe mode automatically after an identity crisis is discovered.
					'migrate_for_idc',             // (bool) True if someone confirms that this site should migrate stats and subscribers from its previous URL
					'dismissed_connection_banner', // (bool) True if the connection banner has been dismissed
					'ab_connect_banner_green_bar', // (int) Version displayed of the A/B test for the green bar at the top of the connect banner.
					'onboarding',                  // (string) Auth token to be used in the onboarding connection flow
					'tos_agreed',                  // (bool)   Whether or not the TOS for connection has been agreed upon.
					'static_asset_cdn_files',      // (array) An nested array of files that we can swap out for cdn versions.
					'mapbox_api_key',              // (string) Mapbox API Key, for use with Map block.
					'mailchimp',                   // (string) Mailchimp keyring data, for mailchimp block.
					'xmlrpc_errors',               // (array) Keys are XML-RPC signature error codes. Values are truthy.
					'dismissed_wizard_banner',     // (int) (DEPRECATED) True if the Wizard banner has been dismissed.
				);

			case 'private':
				return array(
					'blog_token',  // (string) The Client Secret/Blog Token of this site.
					'user_token',  // (string) The User Token of this site. (deprecated)
					'user_tokens',  // (array)  User Tokens for each user of this site who has connected to jetpack.wordpress.com.
					'purchase_token', // (string) Token for logged out user purchases.
					'token_lock', // (string) Token lock in format `expiration_date|||site_url`.
				);

			case 'network':
				return array(
					'onboarding',                   // (string) Auth token to be used in the onboarding connection flow
					'file_data',                     // (array) List of absolute paths to all Jetpack modules
				);
		}

		return array(
			'id',                                  // (int)    The Client ID/WP.com Blog ID of this site.
			'publicize_connections',               // (array)  An array of Publicize connections from WordPress.com.
			'master_user',                         // (int)    The local User ID of the user who connected this site to jetpack.wordpress.com.
			'version',                             // (string) Used during upgrade procedure to auto-activate new modules. version:time.
			'old_version',                         // (string) Used to determine which modules are the most recently added. previous_version:time.
			'fallback_no_verify_ssl_certs',        // (int)    Flag for determining if this host must skip SSL Certificate verification due to misconfigured SSL.
			'time_diff',                           // (int)    Offset between Jetpack server's clocks and this server's clocks. Jetpack Server Time = time() + (int) Jetpack_Options::get_option( 'time_diff' )
			'public',                              // (int|bool) If we think this site is public or not (1, 0), false if we haven't yet tried to figure it out.
			'videopress',                          // (array)  VideoPress options array.
			'is_network_site',                     // (int|bool) If we think this site is a network or a single blog (1, 0), false if we haven't yet tried to figue it out.
			'social_links',                        // (array)  The specified links for each social networking site.
			'identity_crisis_whitelist',           // (array)  An array of options, each having an array of the values whitelisted for it.
			'gplus_authors',                       // (array)  The Google+ authorship information for connected users.
			'last_heartbeat',                      // (int)    The timestamp of the last heartbeat that fired.
			'hide_jitm',                           // (array)  A list of just in time messages that we should not show because they have been dismissed by the user.
			'custom_css_4.7_migration',            // (bool)   Whether Custom CSS has scanned for and migrated any legacy CSS CPT entries to the new Core format.
			'image_widget_migration',              // (bool)   Whether any legacy Image Widgets have been converted to the new Core widget.
			'gallery_widget_migration',            // (bool)   Whether any legacy Gallery Widgets have been converted to the new Core widget.
			'sso_first_login',                     // (bool)   Is this the first time the user logins via SSO.
			'dismissed_hints',                     // (array)  Part of Plugin Search Hints. List of cards that have been dismissed.
			'first_admin_view',                    // (bool)   Set to true the first time the user views the admin. Usually after the initial connection.
			'setup_wizard_questionnaire',          // (array)  (DEPRECATED) List of user choices from the setup wizard.
			'setup_wizard_status',                 // (string) (DEPRECATED) Status of the setup wizard.
			'licensing_error',                     // (string) Last error message occurred while attaching licenses that is yet to be surfaced to the user.
			'recommendations_banner_dismissed',    // (bool) Determines if the recommendations dashboard banner is dismissed or not.
			'recommendations_banner_enabled',      // (bool)   Whether the recommendations are enabled or not.
			'recommendations_data',                // (array)  The user choice and other data for the recommendations.
			'recommendations_step',                // (string) The current step of the recommendations.
			'recommendations_conditional',         // (array)  An array of action-based recommendations.
			'licensing_activation_notice_dismiss', // (array) The `last_detached_count` and the `last_dismissed_time` for the user-license activation notice.
			'has_seen_wc_connection_modal',        // (bool) Whether the site has displayed the WooCommerce Connection modal
			'partner_coupon',                      // (string) A Jetpack partner issued coupon to promote a sale together with Jetpack.
			'partner_coupon_added',                // (string) A date for when `partner_coupon` was added, so we can auto-purge after a certain time interval.
			'dismissed_backup_review_restore',     // (bool) Determines if the component review request is dismissed for successful restore requests.
			'dismissed_backup_review_backups',     // (bool) Determines if the component review request is dismissed for successful backup requests.
		);
	}

	/**
	 * Is the option name valid?
	 *
	 * @param string      $name  The name of the option.
	 * @param string|null $group The name of the group that the option is in. Default to null, which will search non_compact.
	 *
	 * @return bool Is the option name valid?
	 */
	public static function is_valid( $name, $group = null ) {
		if ( is_array( $name ) ) {
			$compact_names = array();
			foreach ( array_keys( self::$grouped_options ) as $_group ) {
				$compact_names = array_merge( $compact_names, self::get_option_names( $_group ) );
			}

			$result = array_diff( $name, self::get_option_names( 'non_compact' ), $compact_names );

			return empty( $result );
		}

		if ( $group === null || 'non_compact' === $group ) {
			if ( in_array( $name, self::get_option_names( $group ), true ) ) {
				return true;
			}
		}

		foreach ( array_keys( self::$grouped_options ) as $_group ) {
			if ( $group === null || $group === $_group ) {
				if ( in_array( $name, self::get_option_names( $_group ), true ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Checks if an option must be saved for the whole network in WP Multisite
	 *
	 * @param string $option_name Option name. It must come _without_ `jetpack_%` prefix. The method will prefix the option name.
	 *
	 * @return bool
	 */
	public static function is_network_option( $option_name ) {
		if ( ! is_multisite() ) {
			return false;
		}
		return in_array( $option_name, self::get_option_names( 'network' ), true );
	}

	/**
	 * Filters the requested option.
	 * This is a wrapper around `get_option_from_database` so that we can filter the option.
	 *
	 * @param string $name Option name. It must come _without_ `jetpack_%` prefix. The method will prefix the option name.
	 * @param mixed  $default (optional).
	 *
	 * @return mixed
	 */
	public static function get_option( $name, $default = false ) {
		/**
		 * Filter Jetpack Options.
		 * Can be useful in environments when Jetpack is running with a different setup
		 *
		 * @since 1.7.0
		 *
		 * @param string $value The value from the database.
		 * @param string $name Option name, _without_ `jetpack_%` prefix.
		 * @return string $value, unless the filters modify it.
		 */
		return apply_filters( 'jetpack_options', self::get_option_from_database( $name, $default ), $name );
	}

	/**
	 * Returns the requested option.  Looks in jetpack_options or jetpack_$name as appropriate.
	 *
	 * @param string $name Option name. It must come _without_ `jetpack_%` prefix. The method will prefix the option name.
	 * @param mixed  $default (optional).
	 *
	 * @return mixed
	 */
	private static function get_option_from_database( $name, $default = false ) {
		if ( self::is_valid( $name, 'non_compact' ) ) {
			if ( self::is_network_option( $name ) ) {
				return get_site_option( "jetpack_$name", $default );
			}

			return get_option( "jetpack_$name", $default );
		}

		foreach ( array_keys( self::$grouped_options ) as $group ) {
			if ( self::is_valid( $name, $group ) ) {
				return self::get_grouped_option( $group, $name, $default );
			}
		}

		trigger_error( sprintf( 'Invalid Jetpack option name: %s', esc_html( $name ) ), E_USER_WARNING ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error -- Don't wish to change legacy behavior.

		return $default;
	}

	/**
	 * Returns the requested option, and ensures it's autoloaded in the future.
	 * This does _not_ adjust the prefix in any way (does not prefix jetpack_%)
	 *
	 * @param string $name Option name.
	 * @param mixed  $default (optional).
	 *
	 * @return mixed
	 */
	public static function get_option_and_ensure_autoload( $name, $default ) {
		// In this function the name is not adjusted by prefixing jetpack_
		// so if it has already prefixed, we'll replace it and then
		// check if the option name is a network option or not.
		$jetpack_name      = preg_replace( '/^jetpack_/', '', $name, 1 );
		$is_network_option = self::is_network_option( $jetpack_name );
		$value             = $is_network_option ? get_site_option( $name ) : get_option( $name );

		if ( false === $value && false !== $default ) {
			if ( $is_network_option ) {
				add_site_option( $name, $default );
			} else {
				add_option( $name, $default );
			}
			$value = $default;
		}

		return $value;
	}

	/**
	 * Update grouped option
	 *
	 * @param string $group Options group.
	 * @param string $name Options name.
	 * @param mixed  $value Options value.
	 *
	 * @return bool Success or failure.
	 */
	private static function update_grouped_option( $group, $name, $value ) {
		$options = get_option( self::$grouped_options[ $group ] );
		if ( ! is_array( $options ) ) {
			$options = array();
		}
		$options[ $name ] = $value;

		return update_option( self::$grouped_options[ $group ], $options );
	}

	/**
	 * Updates the single given option.  Updates jetpack_options or jetpack_$name as appropriate.
	 *
	 * @param string $name Option name. It must come _without_ `jetpack_%` prefix. The method will prefix the option name.
	 * @param mixed  $value Option value.
	 * @param string $autoload If not compact option, allows specifying whether to autoload or not.
	 *
	 * @return bool Was the option successfully updated?
	 */
	public static function update_option( $name, $value, $autoload = null ) {
		/**
		 * Fires before Jetpack updates a specific option.
		 *
		 * @since 1.1.2
		 * @since-jetpack 3.0.0
		 *
		 * @param str $name The name of the option being updated.
		 * @param mixed $value The new value of the option.
		 */
		do_action( 'pre_update_jetpack_option_' . $name, $name, $value );
		if ( self::is_valid( $name, 'non_compact' ) ) {
			if ( self::is_network_option( $name ) ) {
				return update_site_option( "jetpack_$name", $value );
			}

			return update_option( "jetpack_$name", $value, $autoload );

		}

		foreach ( array_keys( self::$grouped_options ) as $group ) {
			if ( self::is_valid( $name, $group ) ) {
				return self::update_grouped_option( $group, $name, $value );
			}
		}

		trigger_error( sprintf( 'Invalid Jetpack option name: %s', esc_html( $name ) ), E_USER_WARNING ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error -- Don't want to change legacy behavior.

		return false;
	}

	/**
	 * Updates the multiple given options.  Updates jetpack_options and/or jetpack_$name as appropriate.
	 *
	 * @param array $array array( option name => option value, ... ).
	 */
	public static function update_options( $array ) {
		$names = array_keys( $array );

		foreach ( array_diff( $names, self::get_option_names(), self::get_option_names( 'non_compact' ), self::get_option_names( 'private' ) ) as $unknown_name ) {
			trigger_error( sprintf( 'Invalid Jetpack option name: %s', esc_html( $unknown_name ) ), E_USER_WARNING ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error -- Don't change legacy behavior.
			unset( $array[ $unknown_name ] );
		}

		foreach ( $names as $name ) {
			self::update_option( $name, $array[ $name ] );
		}
	}

	/**
	 * Deletes the given option.  May be passed multiple option names as an array.
	 * Updates jetpack_options and/or deletes jetpack_$name as appropriate.
	 *
	 * @param string|array $names Option names. They must come _without_ `jetpack_%` prefix. The method will prefix the option names.
	 *
	 * @return bool Was the option successfully deleted?
	 */
	public static function delete_option( $names ) {
		$result = true;
		$names  = (array) $names;

		if ( ! self::is_valid( $names ) ) {
			// phpcs:disable -- This line triggers a handful of errors; ignoring to avoid changing legacy behavior.
			trigger_error( sprintf( 'Invalid Jetpack option names: %s', print_r( $names, 1 ) ), E_USER_WARNING );
			// phpcs:enable
			return false;
		}

		foreach ( array_intersect( $names, self::get_option_names( 'non_compact' ) ) as $name ) {
			if ( self::is_network_option( $name ) ) {
				$result = delete_site_option( "jetpack_$name" );
			} else {
				$result = delete_option( "jetpack_$name" );
			}
		}

		foreach ( array_keys( self::$grouped_options ) as $group ) {
			if ( ! self::delete_grouped_option( $group, $names ) ) {
				$result = false;
			}
		}

		return $result;
	}

	/**
	 * Get group option.
	 *
	 * @param string $group Option group name.
	 * @param string $name Option name.
	 * @param mixed  $default Default option value.
	 *
	 * @return mixed Option.
	 */
	private static function get_grouped_option( $group, $name, $default ) {
		$options = get_option( self::$grouped_options[ $group ] );
		if ( is_array( $options ) && isset( $options[ $name ] ) ) {
			return $options[ $name ];
		}

		return $default;
	}

	/**
	 * Delete grouped option.
	 *
	 * @param string $group Option group name.
	 * @param array  $names Option names.
	 *
	 * @return bool Success or failure.
	 */
	private static function delete_grouped_option( $group, $names ) {
		$options = get_option( self::$grouped_options[ $group ], array() );

		$to_delete = array_intersect( $names, self::get_option_names( $group ), array_keys( $options ) );
		if ( $to_delete ) {
			foreach ( $to_delete as $name ) {
				unset( $options[ $name ] );
			}

			return update_option( self::$grouped_options[ $group ], $options );
		}

		return true;
	}

	/*
	 * Raw option methods allow Jetpack to get / update / delete options via direct DB queries, including options
	 * that are not created by the Jetpack plugin. This is helpful only in rare cases when we need to bypass
	 * cache and filters.
	 */

	/**
	 * Deletes an option via $wpdb query.
	 *
	 * @param string $name Option name.
	 *
	 * @return bool Is the option deleted?
	 */
	public static function delete_raw_option( $name ) {
		if ( self::bypass_raw_option( $name ) ) {
			return delete_option( $name );
		}
		global $wpdb;
		$result = $wpdb->query( $wpdb->prepare( "DELETE FROM $wpdb->options WHERE option_name = %s", $name ) );
		return $result;
	}

	/**
	 * Updates an option via $wpdb query.
	 *
	 * @param string $name Option name.
	 * @param mixed  $value Option value.
	 * @param bool   $autoload Specifying whether to autoload or not.
	 *
	 * @return bool Is the option updated?
	 */
	public static function update_raw_option( $name, $value, $autoload = false ) {
		if ( self::bypass_raw_option( $name ) ) {
			return update_option( $name, $value, $autoload );
		}
		global $wpdb;
		$autoload_value = $autoload ? 'yes' : 'no';

		$old_value = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT option_value FROM $wpdb->options WHERE option_name = %s LIMIT 1",
				$name
			)
		);
		if ( $old_value === $value ) {
			return false;
		}

		$serialized_value = maybe_serialize( $value );
		// below we used "insert ignore" to at least suppress the resulting error.
		$updated_num = $wpdb->query(
			$wpdb->prepare(
				"UPDATE $wpdb->options SET option_value = %s WHERE option_name = %s",
				$serialized_value,
				$name
			)
		);

		// Try inserting the option if the value doesn't exits.
		if ( ! $updated_num ) {
			$updated_num = $wpdb->query(
				$wpdb->prepare(
					"INSERT IGNORE INTO $wpdb->options ( option_name, option_value, autoload ) VALUES ( %s, %s, %s )",
					$name,
					$serialized_value,
					$autoload_value
				)
			);
		}
		return (bool) $updated_num;
	}

	/**
	 * Gets an option via $wpdb query.
	 *
	 * @since 1.1.2
	 * @since-jetpack 5.4.0
	 *
	 * @param string $name Option name.
	 * @param mixed  $default Default option value if option is not found.
	 *
	 * @return mixed Option value, or null if option is not found and default is not specified.
	 */
	public static function get_raw_option( $name, $default = null ) {
		if ( self::bypass_raw_option( $name ) ) {
			return get_option( $name, $default );
		}

		global $wpdb;
		$value = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT option_value FROM $wpdb->options WHERE option_name = %s LIMIT 1",
				$name
			)
		);
		$value = maybe_unserialize( $value );

		if ( null === $value && null !== $default ) {
			return $default;
		}

		return $value;
	}

	/**
	 * This function checks for a constant that, if present, will disable direct DB queries Jetpack uses to manage certain options and force Jetpack to always use Options API instead.
	 * Options can be selectively managed via a blocklist by filtering option names via the jetpack_disabled_raw_option filter.
	 *
	 * @param string $name Option name.
	 *
	 * @return bool
	 */
	public static function bypass_raw_option( $name ) {

		if ( Constants::get_constant( 'JETPACK_DISABLE_RAW_OPTIONS' ) ) {
			return true;
		}
		/**
		 * Allows to disable particular raw options.
		 *
		 * @since 1.1.2
		 * @since-jetpack 5.5.0
		 *
		 * @param array $disabled_raw_options An array of option names that you can selectively blocklist from being managed via direct database queries.
		 */
		$disabled_raw_options = apply_filters( 'jetpack_disabled_raw_options', array() );
		return isset( $disabled_raw_options[ $name ] );
	}

	/**
	 * Gets all known options that are used by Jetpack and managed by Jetpack_Options.
	 *
	 * @since 1.1.2
	 * @since-jetpack 5.4.0
	 *
	 * @param boolean $strip_unsafe_options If true, and by default, will strip out options necessary for the connection to WordPress.com.
	 * @return array An array of all options managed via the Jetpack_Options class.
	 */
	public static function get_all_jetpack_options( $strip_unsafe_options = true ) {
		$jetpack_options            = self::get_option_names();
		$jetpack_options_non_compat = self::get_option_names( 'non_compact' );
		$jetpack_options_private    = self::get_option_names( 'private' );

		$all_jp_options = array_merge( $jetpack_options, $jetpack_options_non_compat, $jetpack_options_private );

		if ( $strip_unsafe_options ) {
			// Flag some Jetpack options as unsafe.
			$unsafe_options = array(
				'id',                           // (int)    The Client ID/WP.com Blog ID of this site.
				'master_user',                  // (int)    The local User ID of the user who connected this site to jetpack.wordpress.com.
				'version',                      // (string) Used during upgrade procedure to auto-activate new modules. version:time

				// non_compact.
				'activated',

				// private.
				'register',
				'blog_token',                  // (string) The Client Secret/Blog Token of this site.
				'user_token',                  // (string) The User Token of this site. (deprecated)
				'user_tokens',
			);

			// Remove the unsafe Jetpack options.
			foreach ( $unsafe_options as $unsafe_option ) {
				$key = array_search( $unsafe_option, $all_jp_options, true );
				if ( false !== $key ) {
					unset( $all_jp_options[ $key ] );
				}
			}
		}

		return $all_jp_options;
	}

	/**
	 * Get all options that are not managed by the Jetpack_Options class that are used by Jetpack.
	 *
	 * @since 1.1.2
	 * @since-jetpack 5.4.0
	 *
	 * @return array
	 */
	public static function get_all_wp_options() {
		// A manual build of the wp options.
		return array(
			'sharing-options',
			'disabled_likes',
			'disabled_reblogs',
			'jetpack_comments_likes_enabled',
			'stats_options',
			'stats_dashboard_widget',
			'safecss_preview_rev',
			'safecss_rev',
			'safecss_revision_migrated',
			'nova_menu_order',
			'jetpack_portfolio',
			'jetpack_portfolio_posts_per_page',
			'jetpack_testimonial',
			'jetpack_testimonial_posts_per_page',
			'sharedaddy_disable_resources',
			'sharing-options',
			'sharing-services',
			'site_icon_temp_data',
			'featured-content',
			'site_logo',
			'jetpack_dismissed_notices',
			'jetpack-twitter-cards-site-tag',
			'jetpack-sitemap-state',
			'jetpack_sitemap_post_types',
			'jetpack_sitemap_location',
			'jetpack_protect_key',
			'jetpack_protect_blocked_attempts',
			'jetpack_protect_activating',
			'jetpack_connection_banner_ab',
			'jetpack_active_plan',
			'jetpack_activation_source',
			'jetpack_site_products',
			'jetpack_sso_match_by_email',
			'jetpack_sso_require_two_step',
			'jetpack_sso_remove_login_form',
			'jetpack_last_connect_url_check',
			'jpo_business_address',
			'jpo_site_type',
			'jpo_homepage_format',
			'jpo_contact_page',
			'jetpack_excluded_extensions',
		);
	}

	/**
	 * Gets all options that can be safely reset by CLI.
	 *
	 * @since 1.1.2
	 * @since-jetpack 5.4.0
	 *
	 * @return array array Associative array containing jp_options which are managed by the Jetpack_Options class and wp_options which are not.
	 */
	public static function get_options_for_reset() {
		$all_jp_options = self::get_all_jetpack_options();

		$wp_options = self::get_all_wp_options();

		$options = array(
			'jp_options' => $all_jp_options,
			'wp_options' => $wp_options,
		);

		return $options;
	}

	/**
	 * Delete all known options
	 *
	 * @since 1.1.2
	 * @since-jetpack 5.4.0
	 *
	 * @return void
	 */
	public static function delete_all_known_options() {
		// Delete all compact options.
		foreach ( (array) self::$grouped_options as $option_name ) {
			delete_option( $option_name );
		}

		// Delete all non-compact Jetpack options.
		foreach ( (array) self::get_option_names( 'non-compact' ) as $option_name ) {
			self::delete_option( $option_name );
		}

		// Delete all options that can be reset via CLI, that aren't Jetpack options.
		foreach ( (array) self::get_all_wp_options() as $option_name ) {
			delete_option( $option_name );
		}
	}
}
