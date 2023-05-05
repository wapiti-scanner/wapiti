<?php // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
/**
 * End REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

/**
 * Class End
 *
 * This class is used to start the import process.
 */
class End extends \WP_REST_Controller {

	/**
	 * Base class
	 */
	use Import;

	/**
	 * The Import ID add a new item to the schema.
	 */
	use Import_ID;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->rest_base = 'end';
	}

	/**
	 * Get the register route options.
	 *
	 * @see register_rest_route()
	 *
	 * @return array The options.
	 */
	protected function get_route_options() {
		return array(
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'cleanup_database' ),
				'permission_callback' => array( $this, 'import_permissions_callback' ),
				'args'                => array(),
			),
			'schema' => array( $this, 'get_public_item_schema' ),
		);
	}

	/**
	 * Retrieves the start values schema, conforming to JSON Schema.
	 *
	 * @return array Item schema data.
	 */
	public function get_item_schema() {
		if ( $this->schema ) {
			return $this->add_additional_fields_schema( $this->schema );
		}

		$schema = array(
			'$schema'    => 'http://json-schema.org/draft-04/schema#',
			'title'      => 'import-end',
			'type'       => 'object',
			'properties' => array(
				'commentmeta_count' => array(
					'description' => __( 'Comment meta deleted count.', 'jetpack-import' ),
					'type'        => 'integer',
					'context'     => array( 'view' ),
					'readonly'    => true,
				),
				'postmeta_count'    => array(
					'description' => __( 'Post meta deleted count.', 'jetpack-import' ),
					'type'        => 'integer',
					'context'     => array( 'view' ),
					'readonly'    => true,
				),
				'termmeta_count'    => array(
					'description' => __( 'Term meta deleted count.', 'jetpack-import' ),
					'type'        => 'integer',
					'context'     => array( 'view' ),
					'readonly'    => true,
				),
			),
		);

		$this->schema = $schema;

		return $this->add_additional_fields_schema( $this->schema );
	}

	/**
	 * Delete all meta values from database.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or error object on failure.
	 *
	 * phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
	 */
	public function cleanup_database( $request ) {
		global $wpdb;

		$where = array( 'meta_key' => $this->import_id_field_name );

		return array(
			'commentmeta_count' => $wpdb->delete( $wpdb->commentmeta, $where ),
			'postmeta_count'    => $wpdb->delete( $wpdb->postmeta, $where ),
			'termmeta_count'    => $wpdb->delete( $wpdb->termmeta, $where ),
		);
	}
}
