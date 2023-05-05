<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Sync\Functions;

/**
 * Base class for working with plugins.
 */
abstract class Jetpack_JSON_API_Plugins_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * Plugins.
	 *
	 * @var array
	 */
	protected $plugins = array();

	/**
	 * If the plugin is network wide.
	 *
	 * @var boolean
	 */
	protected $network_wide = false;

	/**
	 * If we're working in bulk.
	 *
	 * @var boolean
	 */
	protected $bulk = true;

	/**
	 * The log.
	 *
	 * @var array
	 */
	protected $log;

	/**
	 * Response format.
	 *
	 * @var array
	 */
	public static $_response_format = array( // phpcs:ignore PSR2.Classes.PropertyDeclaration.Underscore
		'id'                     => '(safehtml)  The plugin\'s ID',
		'slug'                   => '(safehtml)  The plugin\'s .org slug',
		'active'                 => '(boolean) The plugin status.',
		'update'                 => '(object)  The plugin update info.',
		'name'                   => '(safehtml)  The name of the plugin.',
		'plugin_url'             => '(url)  Link to the plugin\'s web site.',
		'version'                => '(safehtml)  The plugin version number.',
		'description'            => '(safehtml)  Description of what the plugin does and/or notes from the author',
		'author'                 => '(safehtml)  The author\'s name',
		'author_url'             => '(url)  The authors web site address',
		'network'                => '(boolean) Whether the plugin can only be activated network wide.',
		'autoupdate'             => '(boolean) Whether the plugin is automatically updated',
		'autoupdate_translation' => '(boolean) Whether the plugin is automatically updating translations',
		'next_autoupdate'        => '(string) Y-m-d H:i:s for next scheduled update event',
		'log'                    => '(array:safehtml) An array of update log strings.',
		'uninstallable'          => '(boolean) Whether the plugin is unistallable.',
		'action_links'           => '(array) An array of action links that the plugin uses.',
	);

	/**
	 * Response format v1_2
	 *
	 * @var array
	 */
	public static $_response_format_v1_2 = array( // phpcs:ignore PSR2.Classes.PropertyDeclaration.Underscore
		'slug'                   => '(safehtml) The plugin\'s .org slug',
		'active'                 => '(boolean) The plugin status.',
		'update'                 => '(object) The plugin update info.',
		'name'                   => '(safehtml) The plugin\'s ID',
		'display_name'           => '(safehtml) The name of the plugin.',
		'version'                => '(safehtml) The plugin version number.',
		'description'            => '(safehtml) Description of what the plugin does and/or notes from the author',
		'author'                 => '(safehtml) The author\'s name',
		'author_url'             => '(url) The authors web site address',
		'plugin_url'             => '(url) Link to the plugin\'s web site.',
		'network'                => '(boolean) Whether the plugin can only be activated network wide.',
		'autoupdate'             => '(boolean) Whether the plugin is automatically updated',
		'autoupdate_translation' => '(boolean) Whether the plugin is automatically updating translations',
		'uninstallable'          => '(boolean) Whether the plugin is unistallable.',
		'action_links'           => '(array) An array of action links that the plugin uses.',
		'log'                    => '(array:safehtml) An array of update log strings.',
	);

	/**
	 * The result.
	 *
	 * @return array
	 */
	protected function result() {

		$plugins = $this->get_plugins();

		if ( ! $this->bulk && ! empty( $plugins ) ) {
			return array_pop( $plugins );
		}

		return array( 'plugins' => $plugins );
	}

	/**
	 * Validate the input.
	 *
	 * @param string $plugin - the plugin we're validating.
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_input( $plugin ) {

		$error = parent::validate_input( $plugin );
		if ( is_wp_error( $error ) ) {
			return $error;
		}

		$error = $this->validate_network_wide();
		if ( is_wp_error( $error ) ) {
			return $error;
		}

		$args = $this->input();
		// find out what plugin, or plugins we are dealing with
		// validate the requested plugins
		if ( ! isset( $plugin ) || empty( $plugin ) ) {
			if ( ! $args['plugins'] || empty( $args['plugins'] ) ) {
				return new WP_Error( 'missing_plugin', __( 'You are required to specify a plugin.', 'jetpack' ), 400 );
			}
			if ( is_array( $args['plugins'] ) ) {
				$this->plugins = $args['plugins'];
			} else {
				$this->plugins[] = $args['plugins'];
			}
		} else {
			$this->bulk      = false;
			$this->plugins[] = urldecode( $plugin );
		}

		$error = $this->validate_plugins();
		if ( is_wp_error( $error ) ) {
			return $error;
		}

		return true;
	}

	/**
	 * Walks through submitted plugins to make sure they are valid
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_plugins() {
		if ( empty( $this->plugins ) || ! is_array( $this->plugins ) ) {
			return new WP_Error( 'missing_plugins', __( 'No plugins found.', 'jetpack' ) );
		}
		foreach ( $this->plugins as $index => $plugin ) {
			if ( ! preg_match( '/\.php$/', $plugin ) ) {
				$plugin                  = $plugin . '.php';
				$this->plugins[ $index ] = $plugin;
			}
			$valid = $this->validate_plugin( urldecode( $plugin ) );
			if ( is_wp_error( $valid ) ) {
				return $valid;
			}
		}

		return true;
	}

	/**
	 * Format the plugin.
	 *
	 * @param string $plugin_file - the plugin file.
	 * @param array  $plugin_data - the plugin data.
	 *
	 * @return array
	 */
	protected function format_plugin( $plugin_file, $plugin_data ) {
		if ( version_compare( $this->min_version, '1.2', '>=' ) ) {
			return $this->format_plugin_v1_2( $plugin_file, $plugin_data );
		}
		$plugin                    = array();
		$plugin['id']              = preg_replace( '/(.+)\.php$/', '$1', $plugin_file );
		$plugin['slug']            = Jetpack_Autoupdate::get_plugin_slug( $plugin_file );
		$plugin['active']          = Jetpack::is_plugin_active( $plugin_file );
		$plugin['name']            = $plugin_data['Name'];
		$plugin['plugin_url']      = $plugin_data['PluginURI'];
		$plugin['version']         = $plugin_data['Version'];
		$plugin['description']     = $plugin_data['Description'];
		$plugin['author']          = $plugin_data['Author'];
		$plugin['author_url']      = $plugin_data['AuthorURI'];
		$plugin['network']         = $plugin_data['Network'];
		$plugin['update']          = $this->get_plugin_updates( $plugin_file );
		$plugin['next_autoupdate'] = gmdate( 'Y-m-d H:i:s', wp_next_scheduled( 'wp_maybe_auto_update' ) );
		$action_link               = $this->get_plugin_action_links( $plugin_file );
		if ( ! empty( $action_link ) ) {
			$plugin['action_links'] = $action_link;
		}

		$plugin['plugin'] = $plugin_file;
		if ( ! class_exists( 'WP_Automatic_Updater' ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		}
		$autoupdate           = ( new WP_Automatic_Updater() )->should_update( 'plugin', (object) $plugin, WP_PLUGIN_DIR );
		$plugin['autoupdate'] = $autoupdate;

		$autoupdate_translation           = in_array( $plugin_file, Jetpack_Options::get_option( 'autoupdate_plugins_translations', array() ), true );
		$plugin['autoupdate_translation'] = $autoupdate || $autoupdate_translation || Jetpack_Options::get_option( 'autoupdate_translations', false );

		$plugin['uninstallable'] = is_uninstallable_plugin( $plugin_file );

		if ( is_multisite() ) {
			$plugin['network_active'] = is_plugin_active_for_network( $plugin_file );
		}

		if ( ! empty( $this->log[ $plugin_file ] ) ) {
			$plugin['log'] = $this->log[ $plugin_file ];
		}
		return $plugin;
	}

	/**
	 * Format the plugin for v1_2.
	 *
	 * @param string $plugin_file - the plugin file.
	 * @param array  $plugin_data - the plugin data.
	 *
	 * @return array
	 */
	protected function format_plugin_v1_2( $plugin_file, $plugin_data ) {
		$plugin                 = array();
		$plugin['slug']         = Jetpack_Autoupdate::get_plugin_slug( $plugin_file );
		$plugin['active']       = Jetpack::is_plugin_active( $plugin_file );
		$plugin['name']         = preg_replace( '/(.+)\.php$/', '$1', $plugin_file );
		$plugin['display_name'] = $plugin_data['Name'];
		$plugin['plugin_url']   = $plugin_data['PluginURI'];
		$plugin['version']      = $plugin_data['Version'];
		$plugin['description']  = $plugin_data['Description'];
		$plugin['author']       = $plugin_data['Author'];
		$plugin['author_url']   = $plugin_data['AuthorURI'];
		$plugin['network']      = $plugin_data['Network'];
		$plugin['update']       = $this->get_plugin_updates( $plugin_file );
		$action_link            = $this->get_plugin_action_links( $plugin_file );
		if ( ! empty( $action_link ) ) {
			$plugin['action_links'] = $action_link;
		}

		$plugin['plugin'] = $plugin_file;
		if ( ! class_exists( 'WP_Automatic_Updater' ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		}
		$autoupdate           = ( new WP_Automatic_Updater() )->should_update( 'plugin', (object) $plugin, WP_PLUGIN_DIR );
		$plugin['autoupdate'] = $autoupdate;

		$autoupdate_translation           = $this->plugin_has_translations_autoupdates_enabled( $plugin_file );
		$plugin['autoupdate_translation'] = $autoupdate || $autoupdate_translation || Jetpack_Options::get_option( 'autoupdate_translations', false );
		$plugin['uninstallable']          = is_uninstallable_plugin( $plugin_file );

		if ( is_multisite() ) {
			$plugin['network_active'] = is_plugin_active_for_network( $plugin_file );
		}

		if ( ! empty( $this->log[ $plugin_file ] ) ) {
			$plugin['log'] = $this->log[ $plugin_file ];
		}

		return $plugin;
	}

	/**
	 * Check if plugin has autoupdates for translations enabled.
	 *
	 * @param string $plugin_file - the plugin file.
	 *
	 * @return bool
	 */
	protected function plugin_has_translations_autoupdates_enabled( $plugin_file ) {
		return (bool) in_array( $plugin_file, Jetpack_Options::get_option( 'autoupdate_plugins_translations', array() ), true );
	}

	/**
	 * Get file mod capabilities.
	 */
	protected function get_file_mod_capabilities() {
		$reasons_can_not_autoupdate   = array();
		$reasons_can_not_modify_files = array();

		$has_file_system_write_access = Functions::file_system_write_access();
		if ( ! $has_file_system_write_access ) {
			$reasons_can_not_modify_files['has_no_file_system_write_access'] = __( 'The file permissions on this host prevent editing files.', 'jetpack' );
		}

		$disallow_file_mods = Constants::get_constant( 'DISALLOW_FILE_MODS' );
		if ( $disallow_file_mods ) {
			$reasons_can_not_modify_files['disallow_file_mods'] = __( 'File modifications are explicitly disabled by a site administrator.', 'jetpack' );
		}

		$automatic_updater_disabled = Constants::get_constant( 'AUTOMATIC_UPDATER_DISABLED' );
		if ( $automatic_updater_disabled ) {
			$reasons_can_not_autoupdate['automatic_updater_disabled'] = __( 'Any autoupdates are explicitly disabled by a site administrator.', 'jetpack' );
		}

		if ( is_multisite() ) {
			// is it the main network ? is really is multi network
			if ( Jetpack::is_multi_network() ) {
				$reasons_can_not_modify_files['is_multi_network'] = __( 'Multi network install are not supported.', 'jetpack' );
			}
			// Is the site the main site here.
			if ( ! is_main_site() ) {
				$reasons_can_not_modify_files['is_sub_site'] = __( 'The site is not the main network site', 'jetpack' );
			}
		}

		$file_mod_capabilities = array(
			'modify_files'     => (bool) empty( $reasons_can_not_modify_files ), // install, remove, update
			'autoupdate_files' => (bool) empty( $reasons_can_not_modify_files ) && empty( $reasons_can_not_autoupdate ), // enable autoupdates
		);

		if ( ! empty( $reasons_can_not_modify_files ) ) {
			$file_mod_capabilities['reasons_modify_files_unavailable'] = $reasons_can_not_modify_files;
		}

		if ( ! $file_mod_capabilities['autoupdate_files'] ) {
			$file_mod_capabilities['reasons_autoupdate_unavailable'] = array_merge( $reasons_can_not_autoupdate, $reasons_can_not_modify_files );
		}
		return $file_mod_capabilities;
	}

	/**
	 * Get plugins.
	 *
	 * @return array
	 */
	protected function get_plugins() {
		$plugins = array();
		/** This filter is documented in wp-admin/includes/class-wp-plugins-list-table.php */
		$installed_plugins = apply_filters( 'all_plugins', get_plugins() );
		foreach ( $this->plugins as $plugin ) {
			if ( ! isset( $installed_plugins[ $plugin ] ) ) {
				continue;
			}

			$formatted_plugin = $this->format_plugin( $plugin, $installed_plugins[ $plugin ] );

			// If this endpoint accepts site based authentication and a blog token is used, skip capabilities check.
			if ( $this->accepts_site_based_authentication() ) {
				$plugins[] = $formatted_plugin;
				continue;
			}

			/*
			 * Do not show network-active plugins
			 * to folks who do not have the permission to see them.
			 */
			if (
				/** This filter is documented in src/wp-admin/includes/class-wp-plugins-list-table.php */
				! apply_filters( 'show_network_active_plugins', current_user_can( 'manage_network_plugins' ) )
				&& ! empty( $formatted_plugin['network_active'] )
				&& true === $formatted_plugin['network_active']
			) {
				continue;
			}

			$plugins[] = $formatted_plugin;
		}
		$args = $this->query_args();

		if ( isset( $args['offset'] ) ) {
			$plugins = array_slice( $plugins, (int) $args['offset'] );
		}
		if ( isset( $args['limit'] ) ) {
			$plugins = array_slice( $plugins, 0, (int) $args['limit'] );
		}

		return $plugins;
	}

	/**
	 * Validate network wide.
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_network_wide() {
		$args = $this->input();

		if ( isset( $args['network_wide'] ) && $args['network_wide'] ) {
			$this->network_wide = true;
		}

		// If this endpoint accepts site based authentication and a blog token is used, skip capabilities check.
		if ( $this->accepts_site_based_authentication() ) {
			return true;
		}

		if ( $this->network_wide && ! current_user_can( 'manage_network_plugins' ) ) {
			return new WP_Error( 'unauthorized', __( 'This user is not authorized to manage plugins network wide.', 'jetpack' ), 403 );
		}

		return true;
	}

	/**
	 * Validate the plugin.
	 *
	 * @param string $plugin - the plugin we're validating.
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_plugin( $plugin ) {
		if ( ! isset( $plugin ) || empty( $plugin ) ) {
			return new WP_Error( 'missing_plugin', __( 'You are required to specify a plugin to activate.', 'jetpack' ), 400 );
		}

		$error = validate_plugin( $plugin );
		if ( is_wp_error( $error ) ) {
			return new WP_Error( 'unknown_plugin', $error->get_error_messages(), 404 );
		}

		return true;
	}

	/**
	 * Get plugin updates.
	 *
	 * @param string $plugin_file - the plugin file.
	 *
	 * @return object|null
	 */
	protected function get_plugin_updates( $plugin_file ) {
		$plugin_updates = get_plugin_updates();
		if ( isset( $plugin_updates[ $plugin_file ] ) ) {
			$update         = $plugin_updates[ $plugin_file ]->update;
			$cleaned_update = array();
			foreach ( (array) $update as $update_key => $update_value ) {
				switch ( $update_key ) {
					case 'id':
					case 'slug':
					case 'plugin':
					case 'new_version':
					case 'tested':
						$cleaned_update[ $update_key ] = wp_kses( $update_value, array() );
						break;
					case 'url':
					case 'package':
						$cleaned_update[ $update_key ] = esc_url( $update_value );
						break;
				}
			}
			return (object) $cleaned_update;
		}
		return null;
	}

	/**
	 * Get plugin action links.
	 *
	 * @param string $plugin_file - the plugin file.
	 *
	 * @return array
	 */
	protected function get_plugin_action_links( $plugin_file ) {
		return Functions::get_plugins_action_links( $plugin_file );
	}
}
