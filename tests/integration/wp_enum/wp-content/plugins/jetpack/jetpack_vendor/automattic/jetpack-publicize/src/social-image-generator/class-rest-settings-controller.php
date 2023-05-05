<?php
/**
 * Class used to register REST API settings endpoints used by Social Image Generator.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize\Social_Image_Generator;

use WP_Error;
use WP_REST_Controller;
use WP_REST_Server;

/**
 * Defines our endpoints.
 */
class REST_Settings_Controller extends WP_REST_Controller {
	/**
	 * Register REST API endpoints.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			'jetpack/v4',
			'/social-image-generator/settings',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_settings' ),
					'permission_callback' => array( $this, 'settings_permissions_callback' ),
				),
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'update_settings' ),
					'permission_callback' => array( $this, 'settings_permissions_callback' ),
					'args'                => $this->get_endpoint_args_for_item_schema( WP_REST_Server::CREATABLE ),
				),
				'schema' => array( $this, 'get_public_item_schema' ),
			)
		);
	}

	/**
	 * GET `/jetpack/v4/social-image-generator/settings`
	 *
	 * @return WP_REST_Response
	 */
	public function get_settings() {
		$settings   = new Settings();
		$response   = array();
		$schema     = $this->get_item_schema();
		$properties = array_keys( $schema['properties'] );

		if ( in_array( 'enabled', $properties, true ) ) {
			$response['enabled'] = $settings->is_enabled();
		}

		if ( in_array( 'defaults', $properties, true ) ) {
			$response['defaults'] = $settings->get_defaults();
		}

		return rest_ensure_response( $response );
	}

	/**
	 * POST `/jetpack/v4/social-image-generator/settings`
	 *
	 * @param WP_REST_Request $request The API request.
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public function update_settings( $request ) {
		$settings = new Settings();

		if ( isset( $request['enabled'] ) ) {
			$settings->set_enabled( $request['enabled'] );
		}

		if ( $request['defaults'] && $request['defaults']['template'] ) {
			$settings->set_default_template( $request['defaults']['template'] );
		}

		return rest_ensure_response( $this->get_settings() );
	}

	/**
	 * Check the permissions for accessing and updating the settings endpoint.
	 *
	 * @return bool|WP_Error True if user can manage options.
	 */
	public function settings_permissions_callback() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error(
				'rest_forbidden_context',
				__( 'Sorry, you are not allowed to access this endpoint.', 'jetpack-publicize-pkg' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		return true;
	}

	/**
	 * Retrieves the Social Image Generator's settings schema, conforming to JSON Schema.
	 *
	 * @return array Schema data.
	 */
	public function get_item_schema() {
		$schema = array(
			'$schema'    => 'http://json-schema.org/draft-04/schema#',
			'title'      => 'social-image-generator-settings',
			'type'       => 'object',
			'properties' => array(
				'enabled'  => array(
					'description' => __( 'Whether or not Social Image Generator is enabled.', 'jetpack-publicize-pkg' ),
					'type'        => 'boolean',
					'context'     => array( 'view', 'edit' ),
				),
				'defaults' => array(
					'description' => __( 'The default settings for a new generated image.', 'jetpack-publicize-pkg' ),
					'type'        => 'object',
					'context'     => array( 'view', 'edit' ),
					'properties'  => array(
						'template' => array(
							'type' => 'string',
							'enum' => Templates::TEMPLATES,
						),
					),
				),
			),
		);

		return rest_default_additional_properties_to_false( $schema );
	}
}
