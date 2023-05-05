<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * The Modules get endpoint.
 *
 * /sites/%s/jetpack/modules/%s
 */
class Jetpack_JSON_API_Modules_Get_Endpoint extends Jetpack_JSON_API_Modules_Endpoint {
	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'jetpack_manage_modules';
}
