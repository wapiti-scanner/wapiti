<?php
/**
 * Global style REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

require_once ABSPATH . 'wp-includes/class-wp-theme-json-resolver.php';
require_once ABSPATH . 'wp-includes/theme.php';

/**
 * Class Global_Style
 */
class Global_Style extends \WP_REST_Posts_Controller {

	/**
	 * Base class
	 */
	use Import;

	/**
	 * The Import ID add a new item to the schema.
	 */
	use Import_ID;

	/**
	 * Whether the controller supports batching.
	 *
	 * @var array
	 */
	protected $allow_batch = array( 'v1' => true );

	/**
	 * Constructor.
	 */
	public function __construct() {
		parent::__construct( 'wp_global_styles' );

		$this->rest_base = 'global-styles';
	}

	/**
	 * Adds the schema from additional fields to a schema array.
	 *
	 * The type of object is inferred from the passed schema.
	 *
	 * @param array $schema Schema array.
	 * @return array Modified Schema array.
	 */
	public function add_additional_fields_schema( $schema ) {
		$schema['properties']['theme'] = array(
			'description' => __( 'The name of the theme.', 'jetpack-import' ),
			'type'        => 'string',
			'required'    => true,
		);

		// The unique identifier is only required for PUT requests.
		return $this->add_unique_identifier_to_schema( $schema, isset( $_SERVER['REQUEST_METHOD'] ) && $_SERVER['REQUEST_METHOD'] === 'PUT' );
	}

	/**
	 * Update the globals style post.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
	 */
	public function create_item( $request ) {
		if ( ! class_exists( 'WP_Theme_JSON_Resolver' ) ) {
			require_once ABSPATH . 'wp-includes/class-wp-theme-json-resolver.php';
		}

		$theme = \wp_get_theme( $request['theme'] );

		// Check if the theme exists.
		if ( ! $theme->exists() ) {
			return new \WP_Error(
				'theme_not_found',
				__( 'Theme not found.', 'jetpack-import' ),
				array(
					'status' => 400,
					'theme'  => $request['theme'],
				)
			);
		}

		/**
		 * Get the global styles post, or create it.
		 *
		 * A global style post is a post with wp-global-styles-{stylesheet} as post slug.
		 */
		$post = \WP_Theme_JSON_Resolver::get_user_data_from_wp_global_styles( $theme, true );

		if ( \is_wp_error( $post ) ) {
			return $post;
		}

		$args = array(
			'ID'           => $post['ID'],
			'post_content' => $request['content'],
		);

		// Update the post with the passed data.
		$post_id = wp_update_post( $args, true, false );

		if ( is_wp_error( $post_id ) ) {
			$post_id->add_data( array( 'status' => 400 ) );

			return $post_id;
		}

		// Get the post.
		$post = get_post( $post_id );

		$response = $this->prepare_item_for_response( $post, $request );
		$response = rest_ensure_response( $response );

		return $this->add_import_id_metadata( $request, $response );
	}
}
