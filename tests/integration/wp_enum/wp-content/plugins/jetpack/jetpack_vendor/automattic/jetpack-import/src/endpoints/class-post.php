<?php
/**
 * Posts REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

use Automattic\Jetpack\Sync\Settings;

if ( ! function_exists( 'post_exists' ) ) {
	require_once ABSPATH . 'wp-admin/includes/post.php';
}

/**
 * Class Post
 */
class Post extends \WP_REST_Posts_Controller {

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
	 *
	 * @param string $post_type Post type.
	 */
	public function __construct( $post_type = 'post' ) {
		parent::__construct( $post_type );

		// @see add_post_meta
		$this->import_id_meta_type = $post_type;
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
		// WXR saves terms as slugs, so we need to overwrite the schema.
		$schema['properties']['categories']['items']['type'] = 'string';
		$schema['properties']['tags']['items']['type']       = 'string';

		// Add the import unique ID to the schema.
		return $this->add_unique_identifier_to_schema( $schema );
	}

	/**
	 * Creates a single post.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
	 */
	public function create_item( $request ) {
		// Skip if the post already exists.
		$post_id = \post_exists(
			$request['title'],
			'',
			$request['date'],
			$this->post_type,
			$request['status']
		);

		if ( $post_id ) {
			return new \WP_Error(
				'post_exists',
				__( 'Cannot create existing post.', 'jetpack-import' ),
				array(
					'status'  => 409,
					'post_id' => $post_id,
				)
			);
		}

		// WXR saves terms as slugs, so we need to convert them to IDs before send the data to the legacy endpoint.
		foreach ( array( 'categories', 'tags' ) as $taxonomy ) {
			$request[ $taxonomy ] = $this->extract_terms_ids( $request, $taxonomy );
		}

		$response = parent::create_item( $request );

		// Process post metadata.
		if ( ! is_wp_error( $response ) && isset( $response->data ) && isset( $response->data['id'] ) ) {
			$this->process_post_meta( $response->data['id'], $request );
		}

		return $this->add_import_id_metadata( $request, $response );
	}

	/**
	 * Extract terms IDs from slugs.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @param string          $taxonomy Taxonomy name.
	 * @return array List of terms IDs.
	 */
	protected function extract_terms_ids( $request, $taxonomy ) {
		$ret = is_array( $request[ $taxonomy ] ) ? $request[ $taxonomy ] : array();

		if ( ! count( $ret ) ) {
			return $ret;
		}

		$taxonomy_name = $taxonomy === 'tags' ? 'post_tag' : 'category';

		// Extract the terms by ID.
		$ids = $this->get_term_ids_from_slugs( $ret, $taxonomy_name );

		// Create missing terms and add their IDs to the $ids array.
		$ids = $this->create_missing_terms( $ret, $ids, $taxonomy_name );

		if ( is_array( $ids ) ) {
			return $ids;
		} else {
			// Flush away any invalid terms.
			return array();
		}
	}

	/**
	 * Processes the metadata of a WordPress post when creating it.
	 *
	 * @param int   $post_id The post ID.
	 * @param mixed $request An object containing the metadata being added to the post.
	 * @return void
	 */
	public function process_post_meta( $post_id, $request ) {
		$metas = $request->get_param( 'meta' );

		if ( empty( $metas ) ) {
			return;
		}

		$meta_keys_array = $this->filter_post_meta_keys( $metas );
		// Adding it to the whitelist
		Settings::update_settings( array( 'post_meta_whitelist' => $meta_keys_array ) );

		if ( is_array( $metas ) ) {
			foreach ( $metas as $meta_key => $meta_value ) {

				$meta_value = maybe_unserialize( $meta_value );
				if ( $meta_key === '_edit_last' ) {
					update_post_meta( $post_id, $meta_key, $meta_value );
				} else {
					// Add the meta data to the post
					add_post_meta( $post_id, $meta_key, $meta_value );
				}

				do_action( 'import_post_meta', $post_id, $meta_key, $meta_value );
			}
		}
	}

	/**
	 * Filters an array of post meta keys.
	 *
	 * @param array $metas An array of metas to filter.
	 * @return array The filtered array of meta keys.
	 */
	private function filter_post_meta_keys( $metas ) {
		// Define an array of keys to exclude from the filtered array
		$excluded_keys = array();
		// Convert array of keys to a plain array of key strings
		$meta_keys = array_unique( array_values( array_keys( $metas ) ) );
		// // Filter the array by removing the excluded keys and any keys that include '_oembed'
		$filtered_keys = array_filter(
			$meta_keys,
			function ( $key ) use ( $excluded_keys ) {
				// We also don't want to include any oembed post meta because it gets created after a post created
				return ! in_array( $key, $excluded_keys, true ) && strpos( $key, '_oembed' ) === false;
			}
		);
		// Return the filtered array
		return $filtered_keys;
	}

	/**
	 * Get term IDs from slugs.
	 *
	 * @param array  $term_slugs      Array of term slugs.
	 * @param string $taxonomy_name   Taxonomy name.
	 *
	 * @return array                  Array of term IDs.
	 */
	protected function get_term_ids_from_slugs( $term_slugs, $taxonomy_name ) {
		return get_terms(
			array(
				'fields'     => 'ids',
				'hide_empty' => false,
				'slug'       => $term_slugs,
				'taxonomy'   => $taxonomy_name,
			)
		);
	}

	/**
	 * Create any missing terms in the given taxonomy.
	 *
	 * @param array  $term_slugs   The slugs of the terms to check for.
	 * @param array  $existing_ids The IDs of any terms that already exist.
	 * @param string $taxonomy_name The name of the taxonomy.
	 *
	 * @return array The IDs of any terms that are now in the taxonomy.
	 */
	protected function create_missing_terms( $term_slugs, $existing_ids, $taxonomy_name ) {
		$ids = $existing_ids;

		foreach ( $term_slugs as $term_slug ) {
			if ( ! term_exists( $term_slug, $taxonomy_name ) ) {
				$term_name = $this->slug_to_readable_name( $term_slug );
				$new_term  = wp_insert_term( $term_name, $taxonomy_name, array( 'slug' => $term_slug ) );
				if ( ! is_wp_error( $new_term ) && isset( $new_term['term_id'] ) ) {
					$ids[] = $new_term['term_id'];
				}
			}
		}

		return $ids;
	}

	/**
	 * Convert a slug to a readable name.
	 *
	 * @param string $slug Slug to convert.
	 * @return string Converted name.
	 */
	protected function slug_to_readable_name( $slug ) {
		$name = str_replace( array( '-', '_' ), ' ', $slug );
		$name = ucwords( $name );
		return $name;
	}
}
