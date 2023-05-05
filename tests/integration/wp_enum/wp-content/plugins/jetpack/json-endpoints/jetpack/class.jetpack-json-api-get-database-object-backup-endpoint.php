<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Get Database object backup endpoint class.
 *
 * /sites/%s/database-object/backup      -> $blog_id
 */
class Jetpack_JSON_API_Get_Database_Object_Backup_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var array
	 */
	protected $needed_capabilities = array(); // This endpoint is only accessible using a site token

	/**
	 * Object type.
	 *
	 * @var string
	 */
	protected $object_type;

	/**
	 * Object ID.
	 *
	 * @var int
	 */
	protected $object_id;

	/**
	 * Full list of database objects that can be retrieved via this endpoint.
	 *
	 * @var array
	 */
	protected $object_types = array(
		'woocommerce_attribute'                       => array(
			'table'    => 'woocommerce_attribute_taxonomies',
			'id_field' => 'attribute_id',
		),

		'woocommerce_downloadable_product_permission' => array(
			'table'    => 'woocommerce_downloadable_product_permissions',
			'id_field' => 'permission_id',
		),

		'woocommerce_order_item'                      => array(
			'table'     => 'woocommerce_order_items',
			'id_field'  => 'order_item_id',
			'meta_type' => 'order_item',
		),

		'woocommerce_payment_token'                   => array(
			'table'     => 'woocommerce_payment_tokens',
			'id_field'  => 'token_id',
			'meta_type' => 'payment_token',
		),

		'woocommerce_tax_rate'                        => array(
			'table'          => 'woocommerce_tax_rates',
			'id_field'       => 'tax_rate_id',
			'child_table'    => 'woocommerce_tax_rate_locations',
			'child_id_field' => 'tax_rate_id',
		),

		'woocommerce_webhook'                         => array(
			'table'    => 'wc_webhooks',
			'id_field' => 'webhook_id',
		),
	);

	/**
	 * Validate input.
	 *
	 * @param object $object - unused.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_input( $object ) {  // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$query_args = $this->query_args();

		if ( empty( $query_args['object_type'] ) || empty( $query_args['object_id'] ) ) {
			return new WP_Error( 'invalid_args', __( 'You must specify both an object type and id to fetch', 'jetpack' ), 400 );
		}

		if ( empty( $this->object_types[ $query_args['object_type'] ] ) ) {
			return new WP_Error( 'invalid_args', __( 'Specified object_type not recognized', 'jetpack' ), 400 );
		}

		$this->object_type = $this->object_types[ $query_args['object_type'] ];
		$this->object_id   = $query_args['object_id'];

		return true;
	}

	/**
	 * The result.
	 *
	 * @return array|WP_Error
	 */
	protected function result() {
		global $wpdb;

		// Disable Sync as this is a read-only operation and triggered by sync activity.
		\Automattic\Jetpack\Sync\Actions::mark_sync_read_only();

		$table    = $wpdb->prefix . $this->object_type['table'];
		$id_field = $this->object_type['id_field'];

		// Fetch the requested object
		$query  = $wpdb->prepare( 'select * from `' . $table . '` where `' . $id_field . '` = %d', $this->object_id ); //phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$object = $wpdb->get_row( $query ); //phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		if ( empty( $object ) ) {
			return new WP_Error( 'object_not_found', __( 'Object not found', 'jetpack' ), 404 );
		}

		$result = array( 'object' => $object );

		// Fetch associated metadata (if this object type has any)
		if ( ! empty( $this->object_type['meta_type'] ) ) {
			$result['meta'] = get_metadata( $this->object_type['meta_type'], $this->object_id );
		}

		// If there is a child linked table (eg: woocommerce_tax_rate_locations), fetch linked records
		if ( ! empty( $this->object_type['child_table'] ) ) {
			$child_table    = $wpdb->prefix . $this->object_type['child_table'];
			$child_id_field = $this->object_type['child_id_field'];

			$query              = $wpdb->prepare( 'select * from `' . $child_table . '` where `' . $child_id_field . '` = %d', $this->object_id ); //phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$result['children'] = $wpdb->get_results( $query ); //phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		}

		return $result;
	}

}
