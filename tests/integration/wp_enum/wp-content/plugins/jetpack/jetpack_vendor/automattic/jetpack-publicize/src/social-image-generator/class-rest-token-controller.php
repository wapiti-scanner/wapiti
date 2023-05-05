<?php
/**
 * Defines the endpoints used for handling tokens for the Social Image Generator.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize\Social_Image_Generator;

use WP_Error;
use WP_REST_Controller;
use WP_REST_Server;

/**
 * Class used to register token related REST API endpoints used by Social Image Generator.
 */
class REST_Token_Controller extends WP_REST_Controller {

	/**
	 * Register REST API endpoints.
	 *
	 * @return void
	 */
	public function register_routes() {
		register_rest_route(
			'jetpack/v4',
			'/social-image-generator/generate-preview-token',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'generate_preview_token' ),
				'permission_callback' => array( $this, 'require_admin_privilege_callback' ),
				'args'                => $this->get_endpoint_args_for_item_schema( WP_REST_Server::CREATABLE ),
				'schema'              => array( $this, 'get_public_item_schema' ),
			)
		);
	}

	/**
	 * Passes the request parameters to the WPCOM endpoint to generate a preview image token.
	 *
	 * @param WP_Request $request The request object, which includes the parameters.
	 * @return array|WP_Error The token or an error.
	 */
	public function generate_preview_token( $request ) {
		$text      = $request->get_param( 'text' );
		$image_url = $request->get_param( 'image_url' );
		$template  = $request->get_param( 'template' );

		return fetch_token( $text, $image_url, $template );
	}

	/**
	 * Check the current user has admin privleges for accessing the endpoints.
	 *
	 * @return bool|WP_Error True if user can manage options.
	 */
	public function require_admin_privilege_callback() {
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
	 * Retrieves the JSON schema for the token generation.
	 *
	 * @return array Schema data.
	 */
	public function get_item_schema() {
		$schema = array(
			'$schema'    => 'http://json-schema.org/draft-04/schema#',
			'title'      => 'social-image-generator-token',
			'type'       => 'object',
			'properties' => array(
				'text'      => array(
					'description' => __( 'The text to be used to generate the image.', 'jetpack-publicize-pkg' ),
					'type'        => 'string',
					'required'    => true,
					'context'     => array( 'edit' ),
				),
				'image_url' => array(
					'description' => __( 'The URL of the background image to use when generating the social image.', 'jetpack-publicize-pkg' ),
					'type'        => 'string',
					'format'      => 'uri',
					'required'    => false,
					'context'     => array( 'edit' ),
				),
				'template'  => array(
					'description' => __( 'The template slug', 'jetpack-publicize-pkg' ),
					'type'        => 'string',
					'enum'        => Templates::TEMPLATES,
					'required'    => false,
				),
			),
		);

		return rest_default_additional_properties_to_false( $schema );
	}
}
