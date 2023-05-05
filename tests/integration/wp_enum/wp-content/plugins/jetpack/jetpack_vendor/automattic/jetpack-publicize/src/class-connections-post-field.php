<?php
/**
 * Registers the API field for Publicize connections.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize;

/**
 * The class to register the field and augment requests
 * to Publicize supported post types.
 */
class Connections_Post_Field {

	const FIELD_NAME = 'jetpack_publicize_connections';

	/**
	 * Array of post IDs that have been updated.
	 *
	 * @var array
	 */
	private $meta_saved = array();

	/**
	 * Used to memoize the updates for a given post.
	 *
	 * @var array
	 */
	public $memoized_updates = array();

	/**
	 * Registers the jetpack_publicize_connections field. Called
	 * automatically on `rest_api_init()`.
	 */
	public function register_fields() {
		$post_types = get_post_types_by_support( 'publicize' );
		foreach ( $post_types as $post_type ) {
			// Adds meta support for those post types that don't already have it.
			// Only runs during REST API requests, so it doesn't impact UI.
			if ( ! post_type_supports( $post_type, 'custom-fields' ) ) {
				add_post_type_support( $post_type, 'custom-fields' );
			}

			// We use these hooks and not the update_callback because we must updateth meta
			// before we set the post as published, otherwise the wrong connections could be used.
			add_filter( 'rest_pre_insert_' . $post_type, array( $this, 'rest_pre_insert' ), 10, 2 );
			add_action( 'rest_insert_' . $post_type, array( $this, 'rest_insert' ), 10, 3 );

			register_rest_field(
				$post_type,
				self::FIELD_NAME,
				array(
					'get_callback' => array( $this, 'get' ),
					'schema'       => $this->get_schema(),
				)
			);
		}
	}

	/**
	 * Defines data structure and what elements are visible in which contexts
	 */
	public function get_schema() {
		return array(
			'$schema' => 'http://json-schema.org/draft-04/schema#',
			'title'   => 'jetpack-publicize-post-connections',
			'type'    => 'array',
			'context' => array( 'view', 'edit' ),
			'items'   => $this->post_connection_schema(),
			'default' => array(),
		);
	}

	/**
	 * Schema for the endpoint.
	 */
	private function post_connection_schema() {
		return array(
			'$schema'    => 'http://json-schema.org/draft-04/schema#',
			'title'      => 'jetpack-publicize-post-connection',
			'type'       => 'object',
			'properties' => array(
				'id'              => array(
					'description' => __( 'Unique identifier for the Jetpack Social connection', 'jetpack-publicize-pkg' ),
					'type'        => 'string',
					'context'     => array( 'view', 'edit' ),
					'readonly'    => true,
				),
				'service_name'    => array(
					'description' => __( 'Alphanumeric identifier for the Jetpack Social service', 'jetpack-publicize-pkg' ),
					'type'        => 'string',
					'context'     => array( 'view', 'edit' ),
					'readonly'    => true,
				),
				'display_name'    => array(
					'description' => __( 'Username of the connected account', 'jetpack-publicize-pkg' ),
					'type'        => 'string',
					'context'     => array( 'view', 'edit' ),
					'readonly'    => true,
				),
				'profile_picture' => array(
					'description' => __( 'Profile picture of the connected account', 'jetpack-publicize-pkg' ),
					'type'        => 'string',
					'context'     => array( 'edit' ),
					'readonly'    => true,
				),
				'enabled'         => array(
					'description' => __( 'Whether to share to this connection', 'jetpack-publicize-pkg' ),
					'type'        => 'boolean',
					'context'     => array( 'edit' ),
				),
				'done'            => array(
					'description' => __( 'Whether Jetpack Social has already finished sharing for this post', 'jetpack-publicize-pkg' ),
					'type'        => 'boolean',
					'context'     => array( 'edit' ),
					'readonly'    => true,
				),
				'toggleable'      => array(
					'description' => __( 'Whether `enable` can be changed for this post/connection', 'jetpack-publicize-pkg' ),
					'type'        => 'boolean',
					'context'     => array( 'edit' ),
					'readonly'    => true,
				),
			),
		);
	}

	/**
	 * Permission check, based on module availability and user capabilities.
	 *
	 * @param int $post_id Post ID.
	 *
	 * @return true|WP_Error
	 */
	public function permission_check( $post_id ) {
		global $publicize;

		if ( ! $publicize ) {
			return new \WP_Error(
				'publicize_not_available',
				__( 'Sorry, Jetpack Social is not available on your site right now.', 'jetpack-publicize-pkg' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		if ( $publicize->current_user_can_access_publicize_data( $post_id ) ) {
			return true;
		}

		return new \WP_Error(
			'invalid_user_permission_publicize',
			__( 'Sorry, you are not allowed to access Jetpack Social data for this post.', 'jetpack-publicize-pkg' ),
			array( 'status' => rest_authorization_required_code() )
		);
	}

	/**
	 * The field's wrapped getter. Does permission checks and output preparation.
	 *
	 * This cannot be extended: implement `->get()` instead.
	 *
	 * @param mixed           $post_array Probably an array. Whatever the endpoint returns.
	 * @param string          $field_name  Should always match `->field_name`.
	 * @param WP_REST_Request $request     WP API request.
	 * @param string          $object_type Should always match `->object_type`.
	 *
	 * @return mixed
	 */
	public function get( $post_array, $field_name, $request, $object_type ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		global $publicize;

		$full_schema      = $this->get_schema();
		$permission_check = $this->permission_check( empty( $post_array['id'] ) ? 0 : $post_array['id'] );
		if ( is_wp_error( $permission_check ) ) {
			return $full_schema['default'];
		}

		$schema      = $full_schema['items'];
		$properties  = array_keys( $schema['properties'] );
		$connections = $publicize->get_filtered_connection_data( $post_array['id'] );

		$output_connections = array();
		foreach ( $connections as $connection ) {
			$output_connection = array();
			foreach ( $properties as $property ) {
				if ( isset( $connection[ $property ] ) ) {
					$output_connection[ $property ] = $connection[ $property ];
				}
			}

			$output_connection['id'] = (string) $connection['unique_id'];

			$output_connections[] = $output_connection;
		}

		// TODO: Work out if this is necessary. We shouldn't be creating an invalid value here.
		$is_valid = rest_validate_value_from_schema( $output_connections, $full_schema, self::FIELD_NAME );
		if ( is_wp_error( $is_valid ) ) {
			return $is_valid;
		}

		$context = ! empty( $request['context'] ) ? $request['context'] : 'view';
		return $this->filter_response_by_context( $output_connections, $full_schema, $context );
	}

	/**
	 * Prior to updating the post, first calculate which Services to
	 * Publicize to and which to skip.
	 *
	 * @param object          $post    Post data to insert/update.
	 * @param WP_REST_Request $request API request.
	 *
	 * @return Filtered $post
	 */
	public function rest_pre_insert( $post, $request ) {
		$request_connections = ! empty( $request['jetpack_publicize_connections'] ) ? $request['jetpack_publicize_connections'] : array();

		$permission_check = $this->permission_check( empty( $post->ID ) ? 0 : $post->ID );
		if ( is_wp_error( $permission_check ) ) {
			return empty( $request_connections ) ? $post : $permission_check;
		}
		// memoize.
		$this->get_meta_to_update( $request_connections, isset( $post->ID ) ? $post->ID : 0 );

		if ( isset( $post->ID ) ) {
			// Set the meta before we mark the post as published so that publicize works as expected.
			// If this is not the case post end up on social media when they are marked as skipped.
			$this->update( $request_connections, $post );
		}

		return $post;
	}

	/**
	 * After creating a new post, update our cached data to reflect
	 * the new post ID.
	 *
	 * @param WP_Post         $post    Post data to update.
	 * @param WP_REST_Request $request API request.
	 * @param bool            $is_new  Is this a new post.
	 */
	public function rest_insert( $post, $request, $is_new ) {
		if ( ! $is_new ) {
			// An existing post was edited - no need to update
			// our cache - we started out knowing the correct
			// post ID.
			return;
		}

		if ( ! isset( $this->memoized_updates[0] ) ) {
			return;
		}

		$this->memoized_updates[ $post->ID ] = $this->memoized_updates[0];
		unset( $this->memoized_updates[0] );
	}

	/**
	 * Get list of meta data to update per post ID.
	 *
	 * @param array $requested_connections Publicize connections to update.
	 *              Items are either `{ id: (string) }` or `{ service_name: (string) }`.
	 * @param int   $post_id    Post ID.
	 */
	protected function get_meta_to_update( $requested_connections, $post_id = 0 ) {
		global $publicize;

		if ( ! $publicize || ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) ) {
			return array();
		}

		if ( isset( $this->memoized_updates[ $post_id ] ) ) {
			return $this->memoized_updates[ $post_id ];
		}

		$available_connections = $publicize->get_filtered_connection_data( $post_id );

		$changed_connections = array();

		// Build lookup mappings.
		$available_connections_by_unique_id    = array();
		$available_connections_by_service_name = array();
		foreach ( $available_connections as $available_connection ) {
			$available_connections_by_unique_id[ $available_connection['unique_id'] ] = $available_connection;

			if ( ! isset( $available_connections_by_service_name[ $available_connection['service_name'] ] ) ) {
				$available_connections_by_service_name[ $available_connection['service_name'] ] = array();
			}
			$available_connections_by_service_name[ $available_connection['service_name'] ][] = $available_connection;
		}

		// Handle { service_name: $service_name, enabled: (bool) }.
		// If the service is not available, it will be skipped.
		foreach ( $requested_connections as $requested_connection ) {
			if ( ! isset( $requested_connection['service_name'] ) ) {
				continue;
			}

			if ( ! isset( $available_connections_by_service_name[ $requested_connection['service_name'] ] ) ) {
				continue;
			}

			foreach ( $available_connections_by_service_name[ $requested_connection['service_name'] ] as $available_connection ) {
				$changed_connections[ $available_connection['unique_id'] ] = $requested_connection['enabled'];
			}
		}

		// Handle { id: $id, enabled: (bool) }
		// These override the service_name settings.
		foreach ( $requested_connections as $requested_connection ) {
			if ( ! isset( $requested_connection['id'] ) ) {
				continue;
			}

			if ( ! isset( $available_connections_by_unique_id[ $requested_connection['id'] ] ) ) {
				continue;
			}

			$changed_connections[ $requested_connection['id'] ] = $requested_connection['enabled'];
		}

		// Set all changed connections to their new value.
		foreach ( $changed_connections as $unique_id => $enabled ) {
			$connection = $available_connections_by_unique_id[ $unique_id ];

			if ( $connection['done'] || ! $connection['toggleable'] ) {
				continue;
			}

			$available_connections_by_unique_id[ $unique_id ]['enabled'] = $enabled;
		}

		$meta_to_update = array();
		// For all connections, ensure correct post_meta.
		foreach ( $available_connections_by_unique_id as $unique_id => $available_connection ) {
			if ( $available_connection['enabled'] ) {
				$meta_to_update[ $publicize->POST_SKIP . $unique_id ] = null; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			} else {
				$meta_to_update[ $publicize->POST_SKIP . $unique_id ] = 1; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			}
		}

		$this->memoized_updates[ $post_id ] = $meta_to_update;

		return $meta_to_update;
	}

	/**
	 * Update the connections slated to be shared to.
	 *
	 * @param array   $requested_connections Publicize connections to update.
	 *              Items are either `{ id: (string) }` or `{ service_name: (string) }`.
	 * @param WP_Post $post    Post data.
	 */
	public function update( $requested_connections, $post ) {
		if ( isset( $this->meta_saved[ $post->ID ] ) ) { // Make sure we only save it once - per request.
			return;
		}
		foreach ( $this->get_meta_to_update( $requested_connections, $post->ID ) as $meta_key => $meta_value ) {
			if ( $meta_value === null ) {
				delete_post_meta( $post->ID, $meta_key );
			} else {
				update_post_meta( $post->ID, $meta_key, $meta_value );
			}
		}
		$this->meta_saved[ $post->ID ] = true;
	}

	/**
	 * Removes properties that should not appear in the current
	 * request's context
	 *
	 * $context is a Core REST API Framework request attribute that is
	 * always one of:
	 * * view (what you see on the blog)
	 * * edit (what you see in an editor)
	 * * embed (what you see in, e.g., an oembed)
	 *
	 * Fields (and sub-fields, and sub-sub-...) can be flagged for a
	 * set of specific contexts via the field's schema.
	 *
	 * The Core API will filter out top-level fields with the wrong
	 * context, but will not recurse deeply enough into arrays/objects
	 * to remove all levels of sub-fields with the wrong context.
	 *
	 * This function handles that recursion.
	 *
	 * @param mixed  $value   Value passed to API request.
	 * @param array  $schema  Schema to validate against.
	 * @param string $context REST API Request context.
	 *
	 * @return mixed Filtered $value
	 */
	public function filter_response_by_context( $value, $schema, $context ) {
		if ( ! $this->is_valid_for_context( $schema, $context ) ) {
			// We use this intentionally odd looking WP_Error object
			// internally only in this recursive function (see below
			// in the `object` case). It will never be output by the REST API.
			// If we return this for the top level object, Core
			// correctly remove the top level object from the response
			// for us.
			return new \WP_Error( '__wrong-context__' );
		}

		switch ( $schema['type'] ) {
			case 'array':
				if ( ! isset( $schema['items'] ) ) {
					return $value;
				}

				// Shortcircuit if we know none of the items are valid for this context.
				// This would only happen in a strangely written schema.
				if ( ! $this->is_valid_for_context( $schema['items'], $context ) ) {
					return array();
				}

				// Recurse to prune sub-properties of each item.
				foreach ( $value as $key => $item ) {
					$value[ $key ] = $this->filter_response_by_context( $item, $schema['items'], $context );
				}

				return $value;
			case 'object':
				if ( ! isset( $schema['properties'] ) ) {
					return $value;
				}

				foreach ( $value as $field_name => $field_value ) {
					if ( isset( $schema['properties'][ $field_name ] ) ) {
						$field_value = $this->filter_response_by_context( $field_value, $schema['properties'][ $field_name ], $context );
						if ( is_wp_error( $field_value ) && '__wrong-context__' === $field_value->get_error_code() ) {
							unset( $value[ $field_name ] );
						} else {
							// Respect recursion that pruned sub-properties of each property.
							$value[ $field_name ] = $field_value;
						}
					}
				}

				return (object) $value;
		}

		return $value;
	}

	/**
	 * Ensure that our request matches its expected context.
	 *
	 * @param array  $schema  Schema to validate against.
	 * @param string $context REST API Request context.
	 * @return bool
	 */
	private function is_valid_for_context( $schema, $context ) {
		return empty( $schema['context'] ) || in_array( $context, $schema['context'], true );
	}

}
