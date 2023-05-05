<?php
/**
 * Themes sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

/**
 * Class to handle sync for themes.
 */
class Themes extends Module {
	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'themes';
	}

	/**
	 * Initialize themes action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		add_action( 'switch_theme', array( $this, 'sync_theme_support' ), 10, 3 );
		add_action( 'jetpack_sync_current_theme_support', $callable, 10, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'check_upgrader' ), 10, 2 );
		add_action( 'jetpack_installed_theme', $callable, 10, 2 );
		add_action( 'jetpack_updated_themes', $callable, 10, 2 );
		add_filter( 'wp_redirect', array( $this, 'detect_theme_edit' ) );
		add_action( 'jetpack_edited_theme', $callable, 10, 2 );
		add_action( 'wp_ajax_edit-theme-plugin-file', array( $this, 'theme_edit_ajax' ), 0 );
		add_action( 'update_site_option_allowedthemes', array( $this, 'sync_network_allowed_themes_change' ), 10, 4 );
		add_action( 'jetpack_network_disabled_themes', $callable, 10, 2 );
		add_action( 'jetpack_network_enabled_themes', $callable, 10, 2 );

		// Theme deletions.
		add_action( 'deleted_theme', array( $this, 'detect_theme_deletion' ), 10, 2 );
		add_action( 'jetpack_deleted_theme', $callable, 10, 2 );

		// Sidebar updates.
		add_action( 'update_option_sidebars_widgets', array( $this, 'sync_sidebar_widgets_actions' ), 10, 2 );

		add_action( 'jetpack_widget_added', $callable, 10, 4 );
		add_action( 'jetpack_widget_removed', $callable, 10, 4 );
		add_action( 'jetpack_widget_moved_to_inactive', $callable, 10, 2 );
		add_action( 'jetpack_cleared_inactive_widgets', $callable );
		add_action( 'jetpack_widget_reordered', $callable, 10, 2 );
		add_filter( 'widget_update_callback', array( $this, 'sync_widget_edit' ), 10, 4 );
		add_action( 'jetpack_widget_edited', $callable );
	}

	/**
	 * Sync handler for a widget edit.
	 *
	 * @access public
	 *
	 * @todo Implement nonce verification
	 *
	 * @param array      $instance      The current widget instance's settings.
	 * @param array      $new_instance  Array of new widget settings.
	 * @param array      $old_instance  Array of old widget settings.
	 * @param \WP_Widget $widget_object The current widget instance.
	 * @return array The current widget instance's settings.
	 */
	public function sync_widget_edit( $instance, $new_instance, $old_instance, $widget_object ) {
		if ( empty( $old_instance ) ) {
			return $instance;
		}

		// Don't trigger sync action if this is an ajax request, because Customizer makes them during preview before saving changes.
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX && isset( $_POST['customized'] ) ) {
			return $instance;
		}

		$widget = array(
			'name'  => $widget_object->name,
			'id'    => $widget_object->id,
			'title' => isset( $new_instance['title'] ) ? $new_instance['title'] : '',
		);
		/**
		 * Trigger action to alert $callable sync listener that a widget was edited.
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.0.0
		 *
		 * @param string $widget_name , Name of edited widget
		 */
		do_action( 'jetpack_widget_edited', $widget );

		return $instance;
	}

	/**
	 * Sync handler for network allowed themes change.
	 *
	 * @access public
	 *
	 * @param string $option     Name of the network option.
	 * @param mixed  $value      Current value of the network option.
	 * @param mixed  $old_value  Old value of the network option.
	 * @param int    $network_id ID of the network.
	 */
	public function sync_network_allowed_themes_change( $option, $value, $old_value, $network_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$all_enabled_theme_slugs = array_keys( $value );

		if ( count( $old_value ) > count( $value ) ) {

			// Suppress jetpack_network_disabled_themes sync action when theme is deleted.
			$delete_theme_call = $this->get_delete_theme_call();
			if ( ! empty( $delete_theme_call ) ) {
				return;
			}

			$newly_disabled_theme_names = array_keys( array_diff_key( $old_value, $value ) );
			$newly_disabled_themes      = $this->get_theme_details_for_slugs( $newly_disabled_theme_names );
			/**
			 * Trigger action to alert $callable sync listener that network themes were disabled.
			 *
			 * @since 1.6.3
			 * @since-jetpack 5.0.0
			 *
			 * @param mixed $newly_disabled_themes, Array of info about network disabled themes
			 * @param mixed $all_enabled_theme_slugs, Array of slugs of all enabled themes
			 */
			do_action( 'jetpack_network_disabled_themes', $newly_disabled_themes, $all_enabled_theme_slugs );
			return;
		}

		$newly_enabled_theme_names = array_keys( array_diff_key( $value, $old_value ) );
		$newly_enabled_themes      = $this->get_theme_details_for_slugs( $newly_enabled_theme_names );
		/**
		 * Trigger action to alert $callable sync listener that network themes were enabled
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.0.0
		 *
		 * @param mixed $newly_enabled_themes , Array of info about network enabled themes
		 * @param mixed $all_enabled_theme_slugs, Array of slugs of all enabled themes
		 */
		do_action( 'jetpack_network_enabled_themes', $newly_enabled_themes, $all_enabled_theme_slugs );
	}

	/**
	 * Retrieve details for one or more themes by their slugs.
	 *
	 * @access private
	 *
	 * @param array $theme_slugs Theme slugs.
	 * @return array Details for the themes.
	 */
	private function get_theme_details_for_slugs( $theme_slugs ) {
		$theme_data = array();
		foreach ( $theme_slugs as $slug ) {
			$theme               = wp_get_theme( $slug );
			$theme_data[ $slug ] = array(
				'name'    => $theme->get( 'Name' ),
				'version' => $theme->get( 'Version' ),
				'uri'     => $theme->get( 'ThemeURI' ),
				'slug'    => $slug,
			);
		}
		return $theme_data;
	}

	/**
	 * Detect a theme edit during a redirect.
	 *
	 * @access public
	 *
	 * @param string $redirect_url Redirect URL.
	 * @return string Redirect URL.
	 */
	public function detect_theme_edit( $redirect_url ) {
		$url              = wp_parse_url( admin_url( $redirect_url ) );
		$theme_editor_url = wp_parse_url( admin_url( 'theme-editor.php' ) );

		if ( $theme_editor_url['path'] !== $url['path'] ) {
			return $redirect_url;
		}

		$query_params = array();
		wp_parse_str( $url['query'], $query_params );
		if (
			! isset( $_POST['newcontent'] ) ||
			! isset( $query_params['file'] ) ||
			! isset( $query_params['theme'] ) ||
			! isset( $query_params['updated'] )
		) {
			return $redirect_url;
		}
		$theme      = wp_get_theme( $query_params['theme'] );
		$theme_data = array(
			'name'    => $theme->get( 'Name' ),
			'version' => $theme->get( 'Version' ),
			'uri'     => $theme->get( 'ThemeURI' ),
		);

		/**
		 * Trigger action to alert $callable sync listener that a theme was edited.
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.0.0
		 *
		 * @param string $query_params['theme'], Slug of edited theme
		 * @param string $theme_data, Information about edited them
		 */
		do_action( 'jetpack_edited_theme', $query_params['theme'], $theme_data );

		return $redirect_url;
	}

	/**
	 * Handler for AJAX theme editing.
	 *
	 * @todo Refactor to use WP_Filesystem instead of fopen()/fclose().
	 */
	public function theme_edit_ajax() {
		$args = wp_unslash( $_POST );

		if ( empty( $args['theme'] ) ) {
			return;
		}

		if ( empty( $args['file'] ) ) {
			return;
		}
		$file = $args['file'];
		if ( 0 !== validate_file( $file ) ) {
			return;
		}

		if ( ! isset( $args['newcontent'] ) ) {
			return;
		}

		if ( ! isset( $args['nonce'] ) ) {
			return;
		}

		$stylesheet = $args['theme'];
		if ( 0 !== validate_file( $stylesheet ) ) {
			return;
		}

		if ( ! current_user_can( 'edit_themes' ) ) {
			return;
		}

		$theme = wp_get_theme( $stylesheet );
		if ( ! $theme->exists() ) {
			return;
		}

		if ( ! wp_verify_nonce( $args['nonce'], 'edit-theme_' . $stylesheet . '_' . $file ) ) {
			return;
		}

		if ( $theme->errors() && 'theme_no_stylesheet' === $theme->errors()->get_error_code() ) {
			return;
		}

		$editable_extensions = wp_get_theme_file_editable_extensions( $theme );

		$allowed_files = array();
		foreach ( $editable_extensions as $type ) {
			switch ( $type ) {
				case 'php':
					$allowed_files = array_merge( $allowed_files, $theme->get_files( 'php', -1 ) );
					break;
				case 'css':
					$style_files                = $theme->get_files( 'css', -1 );
					$allowed_files['style.css'] = $style_files['style.css'];
					$allowed_files              = array_merge( $allowed_files, $style_files );
					break;
				default:
					$allowed_files = array_merge( $allowed_files, $theme->get_files( $type, -1 ) );
					break;
			}
		}

		$real_file = $theme->get_stylesheet_directory() . '/' . $file;
		if ( 0 !== validate_file( $real_file, $allowed_files ) ) {
			return;
		}

		// Ensure file is real.
		if ( ! is_file( $real_file ) ) {
			return;
		}

		// Ensure file extension is allowed.
		$extension = null;
		if ( preg_match( '/\.([^.]+)$/', $real_file, $matches ) ) {
			$extension = strtolower( $matches[1] );
			if ( ! in_array( $extension, $editable_extensions, true ) ) {
				return;
			}
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writeable
		if ( ! is_writeable( $real_file ) ) {
			return;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		$file_pointer = fopen( $real_file, 'w+' );
		if ( false === $file_pointer ) {
			return;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		fclose( $file_pointer );

		$theme_data = array(
			'name'    => $theme->get( 'Name' ),
			'version' => $theme->get( 'Version' ),
			'uri'     => $theme->get( 'ThemeURI' ),
		);

		/**
		 * This action is documented already in this file.
		 */
		do_action( 'jetpack_edited_theme', $stylesheet, $theme_data );
	}

	/**
	 * Detect a theme deletion.
	 *
	 * @access public
	 *
	 * @param string $stylesheet Stylesheet of the theme to delete.
	 * @param bool   $deleted    Whether the theme deletion was successful.
	 */
	public function detect_theme_deletion( $stylesheet, $deleted ) {
		$theme      = wp_get_theme( $stylesheet );
		$theme_data = array(
			'name'    => $theme->get( 'Name' ),
			'version' => $theme->get( 'Version' ),
			'uri'     => $theme->get( 'ThemeURI' ),
			'slug'    => $stylesheet,
		);

		if ( $deleted ) {
			/**
			 * Signals to the sync listener that a theme was deleted and a sync action
			 * reflecting the deletion and theme slug should be sent
			 *
			 * @since 1.6.3
			 * @since-jetpack 5.0.0
			 *
			 * @param string $stylesheet Theme slug
			 * @param array  $theme_data Theme info Since 5.3
			 */
			do_action( 'jetpack_deleted_theme', $stylesheet, $theme_data );
		}
	}

	/**
	 * Handle an upgrader completion action.
	 *
	 * @access public
	 *
	 * @param \WP_Upgrader $upgrader The upgrader instance.
	 * @param array        $details  Array of bulk item update data.
	 */
	public function check_upgrader( $upgrader, $details ) {
		if ( ! isset( $details['type'] ) ||
			'theme' !== $details['type'] ||
			is_wp_error( $upgrader->skin->result ) ||
			! method_exists( $upgrader, 'theme_info' )
		) {
			return;
		}

		if ( 'install' === $details['action'] ) {
			$theme = $upgrader->theme_info();
			if ( ! $theme instanceof \WP_Theme ) {
				return;
			}
			$theme_info = array(
				'name'    => $theme->get( 'Name' ),
				'version' => $theme->get( 'Version' ),
				'uri'     => $theme->get( 'ThemeURI' ),
			);

			/**
			 * Signals to the sync listener that a theme was installed and a sync action
			 * reflecting the installation and the theme info should be sent
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.9.0
			 *
			 * @param string $theme->theme_root Text domain of the theme
			 * @param mixed $theme_info Array of abbreviated theme info
			 */
			do_action( 'jetpack_installed_theme', $theme->stylesheet, $theme_info );
		}

		if ( 'update' === $details['action'] ) {
			$themes = array();

			if ( empty( $details['themes'] ) && isset( $details['theme'] ) ) {
				$details['themes'] = array( $details['theme'] );
			}

			foreach ( $details['themes'] as $theme_slug ) {
				$theme = wp_get_theme( $theme_slug );

				if ( ! $theme instanceof \WP_Theme ) {
					continue;
				}

				$themes[ $theme_slug ] = array(
					'name'       => $theme->get( 'Name' ),
					'version'    => $theme->get( 'Version' ),
					'uri'        => $theme->get( 'ThemeURI' ),
					'stylesheet' => $theme->stylesheet,
				);
			}

			if ( empty( $themes ) ) {
				return;
			}

			/**
			 * Signals to the sync listener that one or more themes was updated and a sync action
			 * reflecting the update and the theme info should be sent
			 *
			 * @since 1.6.3
			 * @since-jetpack 6.2.0
			 *
			 * @param mixed $themes Array of abbreviated theme info
			 */
			do_action( 'jetpack_updated_themes', $themes );
		}
	}

	/**
	 * Initialize themes action listeners for full sync.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_full_sync_listeners( $callable ) {
		add_action( 'jetpack_full_sync_theme_data', $callable );
	}

	/**
	 * Handle a theme switch.
	 *
	 * @access public
	 *
	 * @param string    $new_name  Name of the new theme.
	 * @param \WP_Theme $new_theme The new theme.
	 * @param \WP_Theme $old_theme The previous theme.
	 */
	public function sync_theme_support( $new_name, $new_theme = null, $old_theme = null ) {
		$previous_theme = $this->get_theme_info( $old_theme );

		/**
		 * Fires when the client needs to sync theme support info
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param array the theme support array
		 * @param array the previous theme since Jetpack 6.5.0
		 */
		do_action( 'jetpack_sync_current_theme_support', $this->get_theme_info(), $previous_theme );
	}

	/**
	 * Enqueue the themes actions for full sync.
	 *
	 * @access public
	 *
	 * @param array   $config               Full sync configuration for this sync module.
	 * @param int     $max_items_to_enqueue Maximum number of items to enqueue.
	 * @param boolean $state                True if full sync has finished enqueueing this module, false otherwise.
	 * @return array  Number of actions enqueued, and next module state.
	 */
	public function enqueue_full_sync_actions( $config, $max_items_to_enqueue, $state ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		/**
		 * Tells the client to sync all theme data to the server
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param boolean Whether to expand theme data (should always be true)
		 */
		do_action( 'jetpack_full_sync_theme_data', true );

		// The number of actions enqueued, and next module state (true == done).
		return array( 1, true );
	}

	/**
	 * Send the themes actions for full sync.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @param int   $send_until The timestamp until the current request can send.
	 * @param array $state This module Full Sync status.
	 *
	 * @return array This module Full Sync status.
	 */
	public function send_full_sync_actions( $config, $send_until, $state ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		// we call this instead of do_action when sending immediately.
		$this->send_action( 'jetpack_full_sync_theme_data', array( true ) );

		// The number of actions enqueued, and next module state (true == done).
		return array( 'finished' => true );
	}

	/**
	 * Retrieve an estimated number of actions that will be enqueued.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return array Number of items yet to be enqueued.
	 */
	public function estimate_full_sync_actions( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return 1;
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
		add_filter( 'jetpack_sync_before_send_jetpack_full_sync_theme_data', array( $this, 'expand_theme_data' ) );
	}

	/**
	 * Retrieve the actions that will be sent for this module during a full sync.
	 *
	 * @access public
	 *
	 * @return array Full sync actions of this module.
	 */
	public function get_full_sync_actions() {
		return array( 'jetpack_full_sync_theme_data' );
	}

	/**
	 * Expand the theme within a hook before it is serialized and sent to the server.
	 *
	 * @access public
	 *
	 * @return array Theme data.
	 */
	public function expand_theme_data() {
		return array( $this->get_theme_info() );
	}

	/**
	 * Retrieve the name of the widget by the widget ID.
	 *
	 * @access public
	 * @global $wp_registered_widgets
	 *
	 * @param string $widget_id Widget ID.
	 * @return string Name of the widget, or null if not found.
	 */
	public function get_widget_name( $widget_id ) {
		global $wp_registered_widgets;
		return ( isset( $wp_registered_widgets[ $widget_id ] ) ? $wp_registered_widgets[ $widget_id ]['name'] : null );
	}

	/**
	 * Retrieve the name of the sidebar by the sidebar ID.
	 *
	 * @access public
	 * @global $wp_registered_sidebars
	 *
	 * @param string $sidebar_id Sidebar ID.
	 * @return string Name of the sidebar, or null if not found.
	 */
	public function get_sidebar_name( $sidebar_id ) {
		global $wp_registered_sidebars;
		return ( isset( $wp_registered_sidebars[ $sidebar_id ] ) ? $wp_registered_sidebars[ $sidebar_id ]['name'] : null );
	}

	/**
	 * Sync addition of widgets to a sidebar.
	 *
	 * @access public
	 *
	 * @param array  $new_widgets New widgets.
	 * @param array  $old_widgets Old widgets.
	 * @param string $sidebar     Sidebar ID.
	 * @return array All widgets that have been moved to the sidebar.
	 */
	public function sync_add_widgets_to_sidebar( $new_widgets, $old_widgets, $sidebar ) {
		$added_widgets = array_diff( $new_widgets, $old_widgets );
		if ( empty( $added_widgets ) ) {
			return array();
		}
		$moved_to_sidebar = array();
		$sidebar_name     = $this->get_sidebar_name( $sidebar );

		// Don't sync jetpack_widget_added if theme was switched.
		if ( $this->is_theme_switch() ) {
			return array();
		}

		foreach ( $added_widgets as $added_widget ) {
			$moved_to_sidebar[] = $added_widget;
			$added_widget_name  = $this->get_widget_name( $added_widget );
			/**
			 * Helps Sync log that a widget got added
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.9.0
			 *
			 * @param string $sidebar, Sidebar id got changed
			 * @param string $added_widget, Widget id got added
			 * @param string $sidebar_name, Sidebar id got changed Since 5.0.0
			 * @param string $added_widget_name, Widget id got added Since 5.0.0
			 */
			do_action( 'jetpack_widget_added', $sidebar, $added_widget, $sidebar_name, $added_widget_name );
		}
		return $moved_to_sidebar;
	}

	/**
	 * Sync removal of widgets from a sidebar.
	 *
	 * @access public
	 *
	 * @param array  $new_widgets      New widgets.
	 * @param array  $old_widgets      Old widgets.
	 * @param string $sidebar          Sidebar ID.
	 * @param array  $inactive_widgets Current inactive widgets.
	 * @return array All widgets that have been moved to inactive.
	 */
	public function sync_remove_widgets_from_sidebar( $new_widgets, $old_widgets, $sidebar, $inactive_widgets ) {
		$removed_widgets = array_diff( $old_widgets, $new_widgets );

		if ( empty( $removed_widgets ) ) {
			return array();
		}

		$moved_to_inactive = array();
		$sidebar_name      = $this->get_sidebar_name( $sidebar );

		foreach ( $removed_widgets as $removed_widget ) {
			// Lets check if we didn't move the widget to in_active_widgets.
			if ( isset( $inactive_widgets ) && ! in_array( $removed_widget, $inactive_widgets, true ) ) {
				$removed_widget_name = $this->get_widget_name( $removed_widget );
				/**
				 * Helps Sync log that a widgte got removed
				 *
				 * @since 1.6.3
				 * @since-jetpack 4.9.0
				 *
				 * @param string $sidebar, Sidebar id got changed
				 * @param string $removed_widget, Widget id got removed
				 * @param string $sidebar_name, Name of the sidebar that changed  Since 5.0.0
				 * @param string $removed_widget_name, Name of the widget that got removed Since 5.0.0
				 */
				do_action( 'jetpack_widget_removed', $sidebar, $removed_widget, $sidebar_name, $removed_widget_name );
			} else {
				$moved_to_inactive[] = $removed_widget;
			}
		}
		return $moved_to_inactive;
	}

	/**
	 * Sync a reorder of widgets within a sidebar.
	 *
	 * @access public
	 *
	 * @todo Refactor serialize() to a json_encode().
	 *
	 * @param array  $new_widgets New widgets.
	 * @param array  $old_widgets Old widgets.
	 * @param string $sidebar     Sidebar ID.
	 */
	public function sync_widgets_reordered( $new_widgets, $old_widgets, $sidebar ) {
		$added_widgets = array_diff( $new_widgets, $old_widgets );
		if ( ! empty( $added_widgets ) ) {
			return;
		}
		$removed_widgets = array_diff( $old_widgets, $new_widgets );
		if ( ! empty( $removed_widgets ) ) {
			return;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
		if ( serialize( $old_widgets ) !== serialize( $new_widgets ) ) {
			$sidebar_name = $this->get_sidebar_name( $sidebar );
			/**
			 * Helps Sync log that a sidebar id got reordered
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.9.0
			 *
			 * @param string $sidebar, Sidebar id got changed
			 * @param string $sidebar_name, Name of the sidebar that changed  Since 5.0.0
			 */
			do_action( 'jetpack_widget_reordered', $sidebar, $sidebar_name );
		}
	}

	/**
	 * Handle the update of the sidebars and widgets mapping option.
	 *
	 * @access public
	 *
	 * @param mixed $old_value The old option value.
	 * @param mixed $new_value The new option value.
	 */
	public function sync_sidebar_widgets_actions( $old_value, $new_value ) {
		// Don't really know how to deal with different array_values yet.
		if (
			( isset( $old_value['array_version'] ) && 3 !== $old_value['array_version'] ) ||
			( isset( $new_value['array_version'] ) && 3 !== $new_value['array_version'] )
		) {
			return;
		}

		$moved_to_inactive_ids = array();
		$moved_to_sidebar      = array();

		foreach ( $new_value as $sidebar => $new_widgets ) {
			if ( in_array( $sidebar, array( 'array_version', 'wp_inactive_widgets' ), true ) ) {
				continue;
			}
			$old_widgets = isset( $old_value[ $sidebar ] )
				? $old_value[ $sidebar ]
				: array();

			if ( ! is_array( $new_widgets ) ) {
				$new_widgets = array();
			}

			$moved_to_inactive_recently = $this->sync_remove_widgets_from_sidebar( $new_widgets, $old_widgets, $sidebar, $new_value['wp_inactive_widgets'] );
			$moved_to_inactive_ids      = array_merge( $moved_to_inactive_ids, $moved_to_inactive_recently );

			$moved_to_sidebar_recently = $this->sync_add_widgets_to_sidebar( $new_widgets, $old_widgets, $sidebar );
			$moved_to_sidebar          = array_merge( $moved_to_sidebar, $moved_to_sidebar_recently );

			$this->sync_widgets_reordered( $new_widgets, $old_widgets, $sidebar );

		}

		// Don't sync either jetpack_widget_moved_to_inactive or jetpack_cleared_inactive_widgets if theme was switched.
		if ( $this->is_theme_switch() ) {
			return;
		}

		// Treat inactive sidebar a bit differently.
		if ( ! empty( $moved_to_inactive_ids ) ) {
			$moved_to_inactive_name = array_map( array( $this, 'get_widget_name' ), $moved_to_inactive_ids );
			/**
			 * Helps Sync log that a widgets IDs got moved to in active
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.9.0
			 *
			 * @param array $moved_to_inactive_ids, Array of widgets id that moved to inactive id got changed
			 * @param array $moved_to_inactive_names, Array of widgets names that moved to inactive id got changed Since 5.0.0
			 */
			do_action( 'jetpack_widget_moved_to_inactive', $moved_to_inactive_ids, $moved_to_inactive_name );
		} elseif ( empty( $moved_to_sidebar ) && empty( $new_value['wp_inactive_widgets'] ) && ! empty( $old_value['wp_inactive_widgets'] ) ) {
			/**
			 * Helps Sync log that a got cleared from inactive.
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.9.0
			 */
			do_action( 'jetpack_cleared_inactive_widgets' );
		}
	}

	/**
	 * Retrieve the theme data for the current or a specific theme.
	 *
	 * @access private
	 *
	 * @param \WP_Theme $theme Theme object. Optional, will default to the current theme.
	 *
	 * @return array Theme data.
	 */
	private function get_theme_info( $theme = null ) {
		$theme_support = array();

		// We are trying to get the current theme info.
		if ( null === $theme ) {
			$theme = wp_get_theme();
		}

		$theme_support['name']    = $theme->get( 'Name' );
		$theme_support['version'] = $theme->get( 'Version' );
		$theme_support['slug']    = $theme->get_stylesheet();
		$theme_support['uri']     = $theme->get( 'ThemeURI' );

		return $theme_support;
	}

	/**
	 * Whether we've deleted a theme in the current request.
	 *
	 * @access private
	 *
	 * @return boolean True if this is a theme deletion request, false otherwise.
	 */
	private function get_delete_theme_call() {
		// Intentional usage of `debug_backtrace()` for production needs.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
		$backtrace         = debug_backtrace();
		$delete_theme_call = null;
		foreach ( $backtrace as $call ) {
			if ( isset( $call['function'] ) && 'delete_theme' === $call['function'] ) {
				$delete_theme_call = $call;
				break;
			}
		}
		return $delete_theme_call;
	}

	/**
	 * Whether we've switched to another theme in the current request.
	 *
	 * @access private
	 *
	 * @return boolean True if this is a theme switch request, false otherwise.
	 */
	private function is_theme_switch() {
		return did_action( 'after_switch_theme' );
	}

	/**
	 * Return Total number of objects.
	 *
	 * @param array $config Full Sync config.
	 *
	 * @return int total
	 */
	public function total( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return 1;
	}

	/**
	 * Retrieve a set of constants by their IDs.
	 *
	 * @access public
	 *
	 * @param string $object_type Object type.
	 * @param array  $ids         Object IDs.
	 * @return array Array of objects.
	 */
	public function get_objects_by_id( $object_type, $ids ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( 'theme-info' !== $object_type ) {
			return array();
		}

		return array( $this->get_theme_info() );
	}

}
