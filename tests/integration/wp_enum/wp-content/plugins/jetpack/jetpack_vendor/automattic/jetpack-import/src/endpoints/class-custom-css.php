<?php
/**
 * Custom CSS REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

require_once ABSPATH . 'wp-includes/theme.php';

/**
 * Class Custom_CSS
 */
class Custom_CSS extends \WP_REST_Posts_Controller {

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
		parent::__construct( 'custom_css' );

		$this->rest_base = 'custom-css';
	}

	/**
	 * Update the custom CSS post.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
	 */
	public function create_item( $request ) {
		$args = array(
			'stylesheet' => $request['title'],
		);

		$post = wp_update_custom_css_post( $request['content'], $args );

		if ( is_wp_error( $post ) ) {
			return $post;
		}

		$response = $this->prepare_item_for_response( $post, $request );
		$response = rest_ensure_response( $response );

		return $this->add_import_id_metadata( $request, $response );
	}
}
