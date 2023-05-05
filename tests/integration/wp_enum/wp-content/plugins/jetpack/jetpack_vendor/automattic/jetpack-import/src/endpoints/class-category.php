<?php
/**
 * Categories REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

/**
 * Class Category
 */
class Category extends \WP_REST_Terms_Controller {

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
		parent::__construct( 'category' );

		// @see add_term_meta
		$this->import_id_meta_type = 'term';
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
		// Parent term is saved like a slug in WXR so we have to rewrite the schema.
		$schema['properties']['parent']['description'] = __( 'The parent category slug.', 'jetpack-import' );
		$schema['properties']['parent']['type']        = 'string';

		// Add the import unique ID to the schema.
		return $this->add_unique_identifier_to_schema( $schema );
	}

	/**
	 * Creates a single category.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
	 */
	public function create_item( $request ) {
		if ( ! empty( $request['parent'] ) ) {
			$parent = get_term_by( 'slug', $request['parent'], 'category' );

			// Overwrite the parent ID with the parent term ID found using the slug.
			$request['parent'] = $parent ? $parent->term_id : 0;
		}

		$response = parent::create_item( $request );

		// Ensure that the HTTP status is a valid one.
		$response = $this->ensure_http_status( $response, 'term_exists', 409 );

		return $this->add_import_id_metadata( $request, $response );
	}
}
