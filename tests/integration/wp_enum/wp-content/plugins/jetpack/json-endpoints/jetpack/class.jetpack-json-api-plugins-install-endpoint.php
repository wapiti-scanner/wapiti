<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Plugins_Installer;

require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
// POST /sites/%s/plugins/%s/install
new Jetpack_JSON_API_Plugins_Install_Endpoint(
	array(
		'description'             => 'Install a plugin to your jetpack blog',
		'group'                   => '__do_not_document',
		'stat'                    => 'plugins:1:install',
		'min_version'             => '1',
		'max_version'             => '1.1',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/plugins/%s/install',
		'path_labels'             => array(
			'$site'   => '(int|string) The site ID, The site domain',
			'$plugin' => '(int|string) The plugin slug to install',
		),
		'response_format'         => Jetpack_JSON_API_Plugins_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/plugins/akismet/install',
	)
);

new Jetpack_JSON_API_Plugins_Install_Endpoint(
	array(
		'description'             => 'Install a plugin to your jetpack blog',
		'group'                   => '__do_not_document',
		'stat'                    => 'plugins:1:install',
		'min_version'             => '1.2',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/plugins/%s/install',
		'path_labels'             => array(
			'$site'   => '(int|string) The site ID, The site domain',
			'$plugin' => '(int|string) The plugin slug to install',
		),
		'response_format'         => Jetpack_JSON_API_Plugins_Endpoint::$_response_format_v1_2,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.2/sites/example.wordpress.org/plugins/akismet/install',
	)
);

/**
 * Plugins install enedpoint class.
 *
 * POST /sites/%s/plugins/%s/install
 */
class Jetpack_JSON_API_Plugins_Install_Endpoint extends Jetpack_JSON_API_Plugins_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'install_plugins';

	/**
	 * The action.
	 *
	 * @var string
	 */
	protected $action = 'install';

	/**
	 * Installation.
	 *
	 * @return bool|WP_Error
	 */
	protected function install() {
		$result = '';
		foreach ( $this->plugins as $index => $slug ) {
			$result = Plugins_Installer::install_plugin( $slug );
			if ( is_wp_error( $result ) ) {
				$this->log[ $slug ][] = $result->get_error_message();
				if ( ! $this->bulk ) {
					return $result;
				}
			}
		}

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		// No errors, install worked. Now replace the slug with the actual plugin id
		$this->plugins[ $index ] = Plugins_Installer::get_plugin_id_by_slug( $slug );

		return true;
	}

	/**
	 * Validate the plugins.
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_plugins() {
		if ( empty( $this->plugins ) || ! is_array( $this->plugins ) ) {
			return new WP_Error( 'missing_plugins', __( 'No plugins found.', 'jetpack' ) );
		}

		foreach ( $this->plugins as $slug ) {
			// make sure it is not already installed
			if ( Plugins_Installer::get_plugin_id_by_slug( $slug ) ) {
				return new WP_Error( 'plugin_already_installed', __( 'The plugin is already installed', 'jetpack' ) );
			}
		}

		return true;
	}
}
