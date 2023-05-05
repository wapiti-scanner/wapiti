<?php
/**
 * A modules class for Jetpack.
 *
 * @package automattic/jetpack-status
 */

namespace Automattic\Jetpack;

use Automattic\Jetpack\Constants as Constants;
use Automattic\Jetpack\IP\Utils as IP_Utils;

/**
 * Class Automattic\Jetpack\Modules
 *
 * Used to retrieve information about the current status of Jetpack modules.
 */
class Modules {

	/**
	 * Check whether or not a Jetpack module is active.
	 *
	 * @param string $module The slug of a Jetpack module.
	 * @return bool
	 */
	public function is_active( $module ) {
		return in_array( $module, self::get_active(), true );
	}

	/**
	 * Load module data from module file. Headers differ from WordPress
	 * plugin headers to avoid them being identified as standalone
	 * plugins on the WordPress plugins page.
	 *
	 * @param string $module The module slug.
	 */
	public function get( $module ) {
		static $modules_details;

		// This method relies heavy on auto-generated file found in Jetpack only: module-headings.php
		// If it doesn't exist, it's safe to assume none of this will be helpful.
		if ( ! function_exists( 'jetpack_has_no_module_info' ) ) {
			return false;
		}

		if ( jetpack_has_no_module_info( $module ) ) {
			return false;
		}

		$file = $this->get_path( $this->get_slug( $module ) );

		if ( isset( $modules_details[ $module ] ) ) {
			$mod = $modules_details[ $module ];
		} else {
			$mod = jetpack_get_module_info( $module );

			if ( null === $mod ) {
				// Try to get the module info from the file as a fallback.
				$mod = $this->get_file_data( $file, jetpack_get_all_module_header_names() );

				if ( empty( $mod['name'] ) ) {
					// No info for this module.
					return false;
				}
			}

			$mod['sort']                     = empty( $mod['sort'] ) ? 10 : (int) $mod['sort'];
			$mod['recommendation_order']     = empty( $mod['recommendation_order'] ) ? 20 : (int) $mod['recommendation_order'];
			$mod['deactivate']               = empty( $mod['deactivate'] );
			$mod['free']                     = empty( $mod['free'] );
			$mod['requires_connection']      = ( ! empty( $mod['requires_connection'] ) && 'No' === $mod['requires_connection'] ) ? false : true;
			$mod['requires_user_connection'] = ( empty( $mod['requires_user_connection'] ) || 'No' === $mod['requires_user_connection'] ) ? false : true;

			if ( empty( $mod['auto_activate'] ) || ! in_array( strtolower( $mod['auto_activate'] ), array( 'yes', 'no', 'public' ), true ) ) {
				$mod['auto_activate'] = 'No';
			} else {
				$mod['auto_activate'] = (string) $mod['auto_activate'];
			}

			if ( $mod['module_tags'] ) {
				$mod['module_tags'] = explode( ',', $mod['module_tags'] );
				$mod['module_tags'] = array_map( 'trim', $mod['module_tags'] );
			} else {
				$mod['module_tags'] = array( 'Other' );
			}

			if ( $mod['plan_classes'] ) {
				$mod['plan_classes'] = explode( ',', $mod['plan_classes'] );
				$mod['plan_classes'] = array_map( 'strtolower', array_map( 'trim', $mod['plan_classes'] ) );
			} else {
				$mod['plan_classes'] = array( 'free' );
			}

			if ( $mod['feature'] ) {
				$mod['feature'] = explode( ',', $mod['feature'] );
				$mod['feature'] = array_map( 'trim', $mod['feature'] );
			} else {
				$mod['feature'] = array( 'Other' );
			}

			$modules_details[ $module ] = $mod;

		}

		/**
		 * Filters the feature array on a module.
		 *
		 * This filter allows you to control where each module is filtered: Recommended,
		 * and the default "Other" listing.
		 *
		 * @since-jetpack 3.5.0
		 *
		 * @param array   $mod['feature'] The areas to feature this module:
		 *     'Recommended' shows on the main Jetpack admin screen.
		 *     'Other' should be the default if no other value is in the array.
		 * @param string  $module The slug of the module, e.g. sharedaddy.
		 * @param array   $mod All the currently assembled module data.
		 */
		$mod['feature'] = apply_filters( 'jetpack_module_feature', $mod['feature'], $module, $mod );

		/**
		 * Filter the returned data about a module.
		 *
		 * This filter allows overriding any info about Jetpack modules. It is dangerous,
		 * so please be careful.
		 *
		 * @since-jetpack 3.6.0
		 *
		 * @param array   $mod    The details of the requested module.
		 * @param string  $module The slug of the module, e.g. sharedaddy
		 * @param string  $file   The path to the module source file.
		 */
		return apply_filters( 'jetpack_get_module', $mod, $module, $file );
	}

	/**
	 * Like core's get_file_data implementation, but caches the result.
	 *
	 * @param string $file Absolute path to the file.
	 * @param array  $headers List of headers, in the format array( 'HeaderKey' => 'Header Name' ).
	 */
	public function get_file_data( $file, $headers ) {
		// Get just the filename from $file (i.e. exclude full path) so that a consistent hash is generated.
		$file_name = basename( $file );

		if ( ! Constants::is_defined( 'JETPACK__VERSION' ) ) {
			return get_file_data( $file, $headers );
		}

		$cache_key = 'jetpack_file_data_' . JETPACK__VERSION;

		$file_data_option = get_transient( $cache_key );

		if ( ! is_array( $file_data_option ) ) {
			delete_transient( $cache_key );
			$file_data_option = false;
		}

		if ( false === $file_data_option ) {
			$file_data_option = array();
		}

		$key           = md5( $file_name . maybe_serialize( $headers ) );
		$refresh_cache = is_admin() && isset( $_GET['page'] ) && 'jetpack' === substr( $_GET['page'], 0, 7 ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput

		// If we don't need to refresh the cache, and already have the value, short-circuit!
		if ( ! $refresh_cache && isset( $file_data_option[ $key ] ) ) {
			return $file_data_option[ $key ];
		}

		$data = get_file_data( $file, $headers );

		$file_data_option[ $key ] = $data;

		set_transient( $cache_key, $file_data_option, 29 * DAY_IN_SECONDS );

		return $data;
	}

	/**
	 * Get a list of activated modules as an array of module slugs.
	 */
	public function get_active() {
		$active = \Jetpack_Options::get_option( 'active_modules' );

		if ( ! is_array( $active ) ) {
			$active = array();
		}

		if ( class_exists( 'VaultPress' ) || function_exists( 'vaultpress_contact_service' ) ) {
			$active[] = 'vaultpress';
		} else {
			$active = array_diff( $active, array( 'vaultpress' ) );
		}

		// If protect is active on the main site of a multisite, it should be active on all sites.
		if ( ! in_array( 'protect', $active, true ) && is_multisite() && get_site_option( 'jetpack_protect_active' ) ) {
			$active[] = 'protect';
		}

		// If it's not available, it shouldn't be active.
		// We don't delete it from the options though, as it will be active again when a plugin gets reactivated.
		$active = array_intersect( $active, $this->get_available() );

		/**
		 * Allow filtering of the active modules.
		 *
		 * Gives theme and plugin developers the power to alter the modules that
		 * are activated on the fly.
		 *
		 * @since-jetpack 5.8.0
		 *
		 * @param array $active Array of active module slugs.
		 */
		$active = apply_filters( 'jetpack_active_modules', $active );

		return array_unique( $active );
	}

	/**
	 * Extract a module's slug from its full path.
	 *
	 * @param string $file Full path to a file.
	 *
	 * @return string Module slug.
	 */
	public function get_slug( $file ) {
		return str_replace( '.php', '', basename( $file ) );
	}

	/**
	 * List available Jetpack modules. Simply lists .php files in /modules/.
	 * Make sure to tuck away module "library" files in a sub-directory.
	 *
	 * @param bool|string $min_version Only return modules introduced in this version or later. Default is false, do not filter.
	 * @param bool|string $max_version Only return modules introduced before this version. Default is false, do not filter.
	 * @param bool|null   $requires_connection Pass a boolean value to only return modules that require (or do not require) a connection.
	 * @param bool|null   $requires_user_connection Pass a boolean value to only return modules that require (or do not require) a user connection.
	 *
	 * @return array $modules Array of module slugs
	 */
	public function get_available( $min_version = false, $max_version = false, $requires_connection = null, $requires_user_connection = null ) {
		static $modules = null;

		if ( ! class_exists( 'Jetpack' ) || ! Constants::is_defined( 'JETPACK__VERSION' ) || ! Constants::is_defined( 'JETPACK__PLUGIN_DIR' ) ) {
			return array_unique(
				/**
				 * Stand alone plugins need to use this filter to register the modules they interact with.
				 * This will allow them to activate and deactivate these modules even when Jetpack is not present.
				 * Note: Standalone plugins can only interact with modules that also exist in the Jetpack plugin, otherwise they'll lose the ability to control it if Jetpack is activated.
				 *
				 * @since 1.13.6
				 *
				 * @param array $modules The list of available modules as an array of slugs.
				 * @param bool $requires_connection Whether to list only modules that require a connection to work.
				 * @param bool $requires_user_connection Whether to list only modules that require a user connection to work.
				 */
				apply_filters( 'jetpack_get_available_standalone_modules', array(), $requires_connection, $requires_user_connection )
			);
		}

		if ( ! isset( $modules ) ) {
			$available_modules_option = \Jetpack_Options::get_option( 'available_modules', array() );
			// Use the cache if we're on the front-end and it's available...
			if ( ! is_admin() && ! empty( $available_modules_option[ JETPACK__VERSION ] ) ) {
				$modules = $available_modules_option[ JETPACK__VERSION ];
			} else {
				$files = ( new Files() )->glob_php( JETPACK__PLUGIN_DIR . 'modules' );

				$modules = array();

				foreach ( $files as $file ) {
					$slug    = $this->get_slug( $file );
					$headers = $this->get( $slug );

					if ( ! $headers ) {
						continue;
					}

					$modules[ $slug ] = $headers['introduced'];
				}

				\Jetpack_Options::update_option(
					'available_modules',
					array(
						JETPACK__VERSION => $modules,
					)
				);
			}
		}

		/**
		 * Filters the array of modules available to be activated.
		 *
		 * @since 2.4.0
		 *
		 * @param array $modules Array of available modules.
		 * @param string $min_version Minimum version number required to use modules.
		 * @param string $max_version Maximum version number required to use modules.
		 * @param bool|null $requires_connection Value of the Requires Connection filter.
		 * @param bool|null $requires_user_connection Value of the Requires User Connection filter.
		 */
		$mods = apply_filters( 'jetpack_get_available_modules', $modules, $min_version, $max_version, $requires_connection, $requires_user_connection );

		if ( ! $min_version && ! $max_version && $requires_connection === null && $requires_user_connection === null ) {
			return array_keys( $mods );
		}

		$r = array();
		foreach ( $mods as $slug => $introduced ) {
			if ( $min_version && version_compare( $min_version, $introduced, '>=' ) ) {
				continue;
			}

			if ( $max_version && version_compare( $max_version, $introduced, '<' ) ) {
				continue;
			}

			$mod_details = $this->get( $slug );

			if ( null !== $requires_connection && (bool) $requires_connection !== $mod_details['requires_connection'] ) {
				continue;
			}

			if ( null !== $requires_user_connection && (bool) $requires_user_connection !== $mod_details['requires_user_connection'] ) {
				continue;
			}

			$r[] = $slug;
		}

		return $r;
	}

	/**
	 * Is slug a valid module.
	 *
	 * @param string $module Module slug.
	 *
	 * @return bool
	 */
	public function is_module( $module ) {
		return ! empty( $module ) && ! validate_file( $module, $this->get_available() );
	}

	/**
	 * Update module status.
	 *
	 * @param string  $module - module slug.
	 * @param boolean $active - true to activate, false to deactivate.
	 * @param bool    $exit Should exit be called after deactivation.
	 * @param bool    $redirect Should there be a redirection after activation.
	 */
	public function update_status( $module, $active, $exit = true, $redirect = true ) {
		return $active ? $this->activate( $module, $exit, $redirect ) : $this->deactivate( $module );
	}

	/**
	 * Activate a module.
	 *
	 * @param string $module Module slug.
	 * @param bool   $exit Should exit be called after deactivation.
	 * @param bool   $redirect Should there be a redirection after activation.
	 *
	 * @return bool|void
	 */
	public function activate( $module, $exit = true, $redirect = true ) {
		/**
		 * Fires before a module is activated.
		 *
		 * @since 2.6.0
		 *
		 * @param string $module Module slug.
		 * @param bool $exit Should we exit after the module has been activated. Default to true.
		 * @param bool $redirect Should the user be redirected after module activation? Default to true.
		 */
		do_action( 'jetpack_pre_activate_module', $module, $exit, $redirect );

		if ( ! strlen( $module ) ) {
			return false;
		}

		// If it's already active, then don't do it again.
		$active = $this->get_active();
		foreach ( $active as $act ) {
			if ( $act === $module ) {
				return true;
			}
		}

		if ( ! $this->is_module( $module ) ) {
			return false;
		}

		// Jetpack plugin only
		if ( class_exists( 'Jetpack' ) ) {

			$module_data = $this->get( $module );

			$status = new Status();
			$state  = new CookieState();

			if ( ! \Jetpack::is_connection_ready() ) {
				if ( ! $status->is_offline_mode() && ! $status->is_onboarding() ) {
					return false;
				}

				// If we're not connected but in offline mode, make sure the module doesn't require a connection.
				if ( $status->is_offline_mode() && $module_data['requires_connection'] ) {
					return false;
				}
			}

			if ( class_exists( 'Jetpack_Client_Server' ) ) {
				$jetpack = \Jetpack::init();

				// Check and see if the old plugin is active.
				if ( isset( $jetpack->plugins_to_deactivate[ $module ] ) ) {
					// Deactivate the old plugins.
					$deactivated = array();
					foreach ( $jetpack->plugins_to_deactivate[ $module ] as $idx => $deactivate_me ) {
						if ( \Jetpack_Client_Server::deactivate_plugin( $deactivate_me[0], $deactivate_me[1] ) ) {
							// If we deactivated the old plugin, remembere that with ::state() and redirect back to this page to activate the module
							// We can't activate the module on this page load since the newly deactivated old plugin is still loaded on this page load.
							$deactivated[] = "$module:$idx";
						}
					}
					if ( $deactivated ) {
						$state->state( 'deactivated_plugins', join( ',', $deactivated ) );
						wp_safe_redirect( add_query_arg( 'jetpack_restate', 1 ) );
						exit;
					}
				}
			}

			// Protect won't work with mis-configured IPs.
			if ( 'protect' === $module ) {
				if ( ! IP_Utils::get_ip() ) {
					$state->state( 'message', 'protect_misconfigured_ip' );
					return false;
				}
			}

			if ( class_exists( 'Jetpack_Plan' ) && ! \Jetpack_Plan::supports( $module ) ) {
				return false;
			}

			// Check the file for fatal errors, a la wp-admin/plugins.php::activate.
			$errors = new Errors();
			$state->state( 'module', $module );
			$state->state( 'error', 'module_activation_failed' ); // we'll override this later if the plugin can be included without fatal error.
			$errors->catch_errors( true );

			ob_start();
			$module_path = $this->get_path( $module );
			if ( file_exists( $module_path ) ) {
				require $this->get_path( $module ); // phpcs:ignore WordPressVIPMinimum.Files.IncludingFile.NotAbsolutePath
			}

			$active[] = $module;
			$this->update_active( $active );

			$state->state( 'error', false ); // the override.
			ob_end_clean();
			$errors->catch_errors( false );
		} else { // Not a Jetpack plugin.
			$active[] = $module;
			$this->update_active( $active );
		}

		if ( $redirect ) {
			wp_safe_redirect( ( new Paths() )->admin_url( 'page=jetpack' ) );
		}
		if ( $exit ) {
			exit;
		}
		return true;
	}

	/**
	 * Deactivate module.
	 *
	 * @param string $module Module slug.
	 *
	 * @return bool
	 */
	public function deactivate( $module ) {
		/**
		 * Fires when a module is deactivated.
		 *
		 * @since 1.9.0
		 *
		 * @param string $module Module slug.
		 */
		do_action( 'jetpack_pre_deactivate_module', $module );

		$active = $this->get_active();
		$new    = array_filter( array_diff( $active, (array) $module ) );

		return $this->update_active( $new );
	}

	/**
	 * Generate a module's path from its slug.
	 *
	 * @param string $slug Module slug.
	 */
	public function get_path( $slug ) {
		if ( ! Constants::is_defined( 'JETPACK__PLUGIN_DIR' ) ) {
			return '';
		}
		/**
		 * Filters the path of a modules.
		 *
		 * @since 7.4.0
		 *
		 * @param array $return The absolute path to a module's root php file
		 * @param string $slug The module slug
		 */
		return apply_filters( 'jetpack_get_module_path', JETPACK__PLUGIN_DIR . "modules/$slug.php", $slug );
	}

	/**
	 * Saves all the currently active modules to options.
	 * Also fires Action hooks for each newly activated and deactivated module.
	 *
	 * @param array $modules Array of active modules to be saved in options.
	 *
	 * @return $success bool true for success, false for failure.
	 */
	public function update_active( $modules ) {
		$current_modules      = \Jetpack_Options::get_option( 'active_modules', array() );
		$active_modules       = $this->get_active();
		$new_active_modules   = array_diff( $modules, $current_modules );
		$new_inactive_modules = array_diff( $active_modules, $modules );
		$new_current_modules  = array_diff( array_merge( $current_modules, $new_active_modules ), $new_inactive_modules );
		$reindexed_modules    = array_values( $new_current_modules );
		$success              = \Jetpack_Options::update_option( 'active_modules', array_unique( $reindexed_modules ) );
		// Let's take `pre_update_option_jetpack_active_modules` filter into account
		// and actually decide for which modules we need to fire hooks by comparing
		// the 'active_modules' option before and after the update.
		$current_modules_post_update = \Jetpack_Options::get_option( 'active_modules', array() );

		$new_inactive_modules = array_diff( $current_modules, $current_modules_post_update );
		$new_inactive_modules = array_unique( $new_inactive_modules );
		$new_inactive_modules = array_values( $new_inactive_modules );

		$new_active_modules = array_diff( $current_modules_post_update, $current_modules );
		$new_active_modules = array_unique( $new_active_modules );
		$new_active_modules = array_values( $new_active_modules );

		foreach ( $new_active_modules as $module ) {
			/**
			 * Fires when a specific module is activated.
			 *
			 * @since 1.9.0
			 *
			 * @param string $module Module slug.
			 * @param boolean $success whether the module was activated. @since 4.2
			 */
			do_action( 'jetpack_activate_module', $module, $success );
			/**
			 * Fires when a module is activated.
			 * The dynamic part of the filter, $module, is the module slug.
			 *
			 * @since 1.9.0
			 *
			 * @param string $module Module slug.
			 */
			do_action( "jetpack_activate_module_$module", $module );
		}

		foreach ( $new_inactive_modules as $module ) {
			/**
			 * Fired after a module has been deactivated.
			 *
			 * @since 4.2.0
			 *
			 * @param string $module Module slug.
			 * @param boolean $success whether the module was deactivated.
			 */
			do_action( 'jetpack_deactivate_module', $module, $success );
			/**
			 * Fires when a module is deactivated.
			 * The dynamic part of the filter, $module, is the module slug.
			 *
			 * @since 1.9.0
			 *
			 * @param string $module Module slug.
			 */
			do_action( "jetpack_deactivate_module_$module", $module );
		}

		return $success;
	}
}
