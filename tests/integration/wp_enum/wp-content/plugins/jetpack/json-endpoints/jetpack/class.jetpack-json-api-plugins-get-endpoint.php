<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * JSON API plugins get endpoint.
 */
new Jetpack_JSON_API_Plugins_Get_Endpoint(
	array(
		'description'             => 'Get the Plugin data.',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/plugins/%s/',
		'min_version'             => '1',
		'max_version'             => '1.1',
		'stat'                    => 'plugins:1',
		'path_labels'             => array(
			'$site'   => '(int|string) The site ID, The site domain',
			'$plugin' => '(string) The plugin ID',
		),
		'allow_jetpack_site_auth' => true,
		'response_format'         => Jetpack_JSON_API_Plugins_Endpoint::$_response_format,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/plugins/hello-dolly%20hello',
	)
);

/**
 * Plugins get endpoint class.
 *
 * GET  /sites/%s/plugins/%s
 *
 * No v1.2 version since it is .com only
 */
class Jetpack_JSON_API_Plugins_Get_Endpoint extends Jetpack_JSON_API_Plugins_Endpoint {
	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'activate_plugins';
}
