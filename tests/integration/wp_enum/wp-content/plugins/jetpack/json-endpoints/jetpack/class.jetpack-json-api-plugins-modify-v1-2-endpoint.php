<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
new Jetpack_JSON_API_Plugins_Modify_v1_2_Endpoint(
	array(
		'description'             => 'Activate/Deactivate a Plugin on your Jetpack Site, or set automatic updates',
		'min_version'             => '1.2',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/plugins/%s',
		'stat'                    => 'plugins:1:modify',
		'path_labels'             => array(
			'$site'   => '(int|string) The site ID, The site domain',
			'$plugin' => '(string) The plugin ID',
		),
		'request_format'          => array(
			'action'       => '(string) Possible values are \'update\'',
			'autoupdate'   => '(bool) Whether or not to automatically update the plugin',
			'active'       => '(bool) Activate or deactivate the plugin',
			'network_wide' => '(bool) Do action network wide (default value: false)',
		),
		'query_parameters'        => array(
			'autoupdate' => '(bool=false) If the update is happening as a result of autoupdate event',
		),
		'response_format'         => Jetpack_JSON_API_Plugins_Endpoint::$_response_format_v1_2,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'action' => 'update',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.2/sites/example.wordpress.org/plugins/hello-dolly%20hello',
	)
);

new Jetpack_JSON_API_Plugins_Modify_v1_2_Endpoint(
	array(
		'description'             => 'Activate/Deactivate a list of plugins on your Jetpack Site, or set automatic updates',
		'min_version'             => '1.2',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/plugins',
		'stat'                    => 'plugins:modify',
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'action'       => '(string) Possible values are \'update\'',
			'autoupdate'   => '(bool) Whether or not to automatically update the plugin',
			'active'       => '(bool) Activate or deactivate the plugin',
			'network_wide' => '(bool) Do action network wide (default value: false)',
			'plugins'      => '(array) A list of plugin ids to modify',
		),
		'query_parameters'        => array(
			'autoupdate' => '(bool=false) If the update is happening as a result of autoupdate event',
		),
		'response_format'         => array(
			'plugins'     => '(array:plugin_v1_2) An array of plugin objects.',
			'updated'     => '(array) A list of plugin ids that were updated. Only present if action is update.',
			'not_updated' => '(array) A list of plugin ids that were not updated. Only present if action is update.',
			'log'         => '(array) Update log. Only present if action is update.',
		),
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'active'  => true,
				'plugins' => array(
					'jetpack/jetpack',
					'akismet/akismet',
				),
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.2/sites/example.wordpress.org/plugins',
	)
);

new Jetpack_JSON_API_Plugins_Modify_v1_2_Endpoint(
	array(
		'description'             => 'Update a Plugin on your Jetpack Site',
		'min_version'             => '1.2',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/plugins/%s/update/',
		'stat'                    => 'plugins:1:update',
		'path_labels'             => array(
			'$site'   => '(int|string) The site ID, The site domain',
			'$plugin' => '(string) The plugin ID',
		),
		'query_parameters'        => array(
			'autoupdate' => '(bool=false) If the update is happening as a result of autoupdate event',
		),
		'response_format'         => Jetpack_JSON_API_Plugins_Endpoint::$_response_format_v1_2,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.2/sites/example.wordpress.org/plugins/hello-dolly%20hello/update',
	)
);

/**
 * Plugins modify 1_2 Endpoint.
 */
class Jetpack_JSON_API_Plugins_Modify_v1_2_Endpoint extends Jetpack_JSON_API_Plugins_Modify_Endpoint { // phpcs:ignore PEAR.NamingConventions.ValidClassName.Invalid, Generic.Classes.OpeningBraceSameLine.ContentAfterBrace

	/**
	 * Activate plugins.
	 *
	 * @return null|WP_Error null on success, WP_Error otherwise.
	 */
	protected function activate() {
		$permission_error = false;
		$has_errors       = false;
		foreach ( $this->plugins as $plugin ) {

			// If this endpoint accepts site based authentication and a blog token is used, skip capabilities check.
			if ( ! $this->accepts_site_based_authentication() ) {
				if ( ! $this->current_user_can( 'activate_plugin', $plugin ) ) {
					$this->log[ $plugin ]['error'] = __( 'Sorry, you are not allowed to activate this plugin.', 'jetpack' );

					$has_errors       = true;
					$permission_error = true;
					continue;
				}
			}

			if ( ( ! $this->network_wide && Jetpack::is_plugin_active( $plugin ) ) || is_plugin_active_for_network( $plugin ) ) {
				continue;
			}

			if ( ! $this->network_wide && is_network_only_plugin( $plugin ) && is_multisite() ) {
				$this->log[ $plugin ]['error'] = __( 'Plugin can only be Network Activated', 'jetpack' );

				$has_errors = true;
				continue;
			}

			$result = activate_plugin( $plugin, '', $this->network_wide );

			if ( is_wp_error( $result ) ) {
				$this->log[ $plugin ]['error'] = $result->get_error_messages();

				$has_errors = true;
				continue;
			}

			$success = Jetpack::is_plugin_active( $plugin );
			if ( $success && $this->network_wide ) {
				$success &= is_plugin_active_for_network( $plugin );
			}

			if ( ! $success ) {
				$this->log[ $plugin ]['error'] = $result->get_error_messages;

				$has_errors = true;
				continue;
			}
			$this->log[ $plugin ][] = __( 'Plugin activated.', 'jetpack' );
		}

		if ( ! $this->bulk && $has_errors ) {
			$plugin = $this->plugins[0];
			if ( $permission_error ) {
				return new WP_Error( 'unauthorized_error', $this->log[ $plugin ]['error'], 403 );
			}

			return new WP_Error( 'activation_error', $this->log[ $plugin ]['error'] );
		}
	}

	/**
	 * Deactivate plugins.
	 *
	 * @return null|WP_Error null on success, WP_Error otherwise.
	 */
	protected function deactivate() {
		$permission_error = false;
		foreach ( $this->plugins as $plugin ) {
			// If this endpoint accepts site based authentication and a blog token is used, skip capabilities check.
			if ( ! $this->accepts_site_based_authentication() ) {
				if ( ! $this->current_user_can( 'deactivate_plugin', $plugin ) ) {
					$error = __( 'Sorry, you are not allowed to deactivate this plugin.', 'jetpack' );

					$this->log[ $plugin ]['error'] = $error;
					$permission_error              = true;
					continue;
				}
			}

			if ( ! Jetpack::is_plugin_active( $plugin ) ) {
				continue;
			}

			deactivate_plugins( $plugin, false, $this->network_wide );

			$success = ! Jetpack::is_plugin_active( $plugin );
			if ( $success && $this->network_wide ) {
				$success &= ! is_plugin_active_for_network( $plugin );
			}

			if ( ! $success ) {
				$error = __( 'There was an error deactivating your plugin', 'jetpack' );

				$this->log[ $plugin ]['error'] = $error;
				continue;
			}
			$this->log[ $plugin ][] = __( 'Plugin deactivated.', 'jetpack' );
		}
		if ( ! $this->bulk && isset( $error ) ) {
			if ( $permission_error ) {
				return new WP_Error( 'unauthorized_error', $error, 403 );
			}

			return new WP_Error( 'deactivation_error', $error );
		}
	}
}
