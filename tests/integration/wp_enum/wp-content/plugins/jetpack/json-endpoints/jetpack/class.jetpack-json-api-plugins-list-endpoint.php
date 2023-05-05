<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new Jetpack_JSON_API_Plugins_List_Endpoint(
	array(
		'description'             => 'Get installed Plugins on your blog',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/plugins',
		'stat'                    => 'plugins',
		'min_version'             => '1',
		'max_version'             => '1.1',
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'allow_jetpack_site_auth' => true,
		'response_format'         => array(
			'plugins' => '(plugin) An array of plugin objects.',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/plugins',
	)
);

/**
 * Plugins list endpoint class.
 *
 * GET /sites/%s/plugins
 *
 * No v1.2 versions since they are .com only
 */
class Jetpack_JSON_API_Plugins_List_Endpoint extends Jetpack_JSON_API_Plugins_Endpoint {
	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'activate_plugins';

	/**
	 * Validate the input.
	 *
	 * @param string $plugin - the plugin.
	 *
	 * @return bool
	 */
	public function validate_input( $plugin ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		wp_update_plugins();
		$this->plugins = array_keys( get_plugins() );
		return true;
	}
}


