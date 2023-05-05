<?php
/**
 * Menus REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

/**
 * Class Menu
 */
class Menu extends \WP_REST_Menus_Controller {

	/**
	 * Base class
	 */
	use Import;

	/**
	 * The Import ID add a new item to the schema.
	 */
	use Import_ID;

	/**
	 * Whether the controller supports batching. Default true.
	 *
	 * @var array
	 */
	protected $allow_batch = array( 'v1' => true );

	/**
	 * Constructor.
	 */
	public function __construct() {
		parent::__construct( 'nav_menu' );

		// @see add_term_meta
		$this->import_id_meta_type = 'term';
	}

	/**
	 * Creates a single menu.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
	 */
	public function create_item( $request ) {
		$response = parent::create_item( $request );

		// Ensure that the HTTP status is a valid one.
		$response = $this->ensure_http_status( $response, 'menu_exists', 409 );

		return $this->add_import_id_metadata( $request, $response );
	}
}
