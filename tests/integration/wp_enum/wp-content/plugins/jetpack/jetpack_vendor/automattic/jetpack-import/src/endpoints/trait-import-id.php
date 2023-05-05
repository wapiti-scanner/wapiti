<?php
/**
 * Jetpack Import unique import ID.
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

/**
 * Import ID trait. Add a unique import ID to the items schema.
 */
trait Import_ID {

	/**
	 * Meta and REST property name used for storing the WXR import ID.
	 *
	 * @var string
	 */
	protected $import_id_field_name = 'unified_importer_id';

	/**
	 * Import ID meta name.
	 *
	 * @var string
	 */
	protected $import_id_meta_type;

	/**
	 * Adds the schema from additional fields to a schema array.
	 *
	 * The type of object is inferred from the passed schema.
	 *
	 * @param array $schema Schema array.
	 * @return array Modified Schema array.
	 */
	public function add_additional_fields_schema( $schema ) {
		// Add the import unique ID to the schema.
		return $this->add_unique_identifier_to_schema( $schema );
	}

	/**
	 * Create a resource.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
	 */
	public function create_item( $request ) {
		$response = parent::create_item( $request );

		return $this->add_import_id_metadata( $request, $response );
	}

	/**
	 * Adds the unique identifier to the schema array.
	 *
	 * @param array $schema Schema array.
	 * @param bool  $required Whether the field is required.
	 * @return array Modified Schema array.
	 */
	protected function add_unique_identifier_to_schema( $schema, $required = true ) {
		// Add the import unique ID to the schema.
		$schema['properties'][ $this->import_id_field_name ] = array(
			'description' => __( 'Jetpack Import unique identifier for the term.', 'jetpack-import' ),
			'type'        => 'integer',
			'context'     => array( 'view', 'embed', 'edit' ),
			'required'    => $required,
		);

		return $schema;
	}

	/**
	 * Add the import unique ID to the resource metadata.
	 *
	 * @param WP_REST_Request  $request Full details about the request.
	 * @param WP_REST_Response $response Response object.
	 * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
	 */
	protected function add_import_id_metadata( $request, $response ) {
		// Skip on error.
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$data   = $response->get_data();
		$status = $response->get_status();

		// Skip if the resource has not been added or modified.
		if ( ! ( $status === 200 || $status === 201 ) ) {
			return $response;
		}

		// Add the import unique ID to the resource metadata.
		\add_metadata( $this->import_id_meta_type, $data['id'], $this->import_id_field_name, $request[ $this->import_id_field_name ], true );

		return $response;
	}

	/**
	 * Get the import DB query. This is used to get the items with a specific
	 * meta key that have been imported.
	 *
	 * @param int $parent_import_id The parent import ID.
	 * @return array The query.
	 */
	protected function get_import_db_query( $parent_import_id ) {
		// Get the only one item with the parent import ID.
		return array(
			'number'     => 1,
			'fields'     => 'ids',
			'meta_query' => array(
				array(
					'key'   => $this->import_id_field_name,
					'value' => $parent_import_id,
				),
			),
		);
	}
}
