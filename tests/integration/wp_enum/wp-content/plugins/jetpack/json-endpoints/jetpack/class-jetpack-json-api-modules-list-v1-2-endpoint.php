<?php
/**
 * List modules v1.2 endpoint.
 *
 *  @package automattic/jetpack
 */

use Automattic\Jetpack\Status;
/**
 * List modules v1.2 endpoint.
 */
class Jetpack_JSON_API_Modules_List_V1_2_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * This endpoint allows authentication both via a blog and a user token.
	 * If a user token is used, that user should have `jetpack_manage_modules` capability.
	 *
	 * @var array|string
	 */
	protected $needed_capabilities = 'jetpack_manage_modules';

	/**
	 * Fetch modules list.
	 *
	 * @return array An array of module objects.
	 */
	protected function result() {
		require_once JETPACK__PLUGIN_DIR . 'class.jetpack-admin.php';

		$is_offline_mode = ( new Status() )->is_offline_mode();

		$modules = Jetpack_Admin::init()->get_modules();

		foreach ( $modules as $slug => $properties ) {
			if ( $is_offline_mode ) {
				$requires_connection      = isset( $modules[ $slug ]['requires_connection'] ) && $modules[ $slug ]['requires_connection'];
				$requires_user_connection = isset( $modules[ $slug ]['requires_user_connection'] ) && $modules[ $slug ]['requires_user_connection'];
				if (
					$requires_connection || $requires_user_connection
				) {
					$modules[ $slug ]['activated'] = false;
				}
			}
		}

		$modules = Jetpack::get_translated_modules( $modules );

		return array( 'modules' => $modules );
	}
}
