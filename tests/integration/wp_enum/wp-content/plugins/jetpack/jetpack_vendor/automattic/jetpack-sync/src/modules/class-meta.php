<?php
/**
 * Meta sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

/**
 * Class to handle sync for meta.
 */
class Meta extends Module {
	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'meta';
	}

	/**
	 * This implementation of get_objects_by_id() is a bit hacky since we're not passing in an array of meta IDs,
	 * but instead an array of post or comment IDs for which to retrieve meta for. On top of that,
	 * we also pass in an associative array where we expect there to be 'meta_key' and 'ids' keys present.
	 *
	 * This seemed to be required since if we have missing meta on WP.com and need to fetch it, we don't know what
	 * the meta key is, but we do know that we have missing meta for a given post or comment.
	 *
	 * @todo Refactor the $wpdb->prepare call to use placeholders.
	 *
	 * @param string $object_type The type of object for which we retrieve meta. Either 'post' or 'comment'.
	 * @param array  $config      Must include 'meta_key' and 'ids' keys.
	 *
	 * @return array
	 */
	public function get_objects_by_id( $object_type, $config ) {
		$table = _get_meta_table( $object_type );

		if ( ! $table ) {
			return array();
		}

		if ( ! is_array( $config ) ) {
			return array();
		}

		$meta_objects = array();
		foreach ( $config as $item ) {
			$meta = null;
			if ( isset( $item['id'] ) && isset( $item['meta_key'] ) ) {
				$meta = $this->get_object_by_id( $object_type, (int) $item['id'], (string) $item['meta_key'] );
			}
			$meta_objects[ $item['id'] . '-' . $item['meta_key'] ] = $meta;
		}

		return $meta_objects;
	}

	/**
	 * Get a single Meta Result.
	 *
	 * @param string $object_type  post, comment, term, user.
	 * @param null   $id           Object ID.
	 * @param null   $meta_key     Meta Key.
	 *
	 * @return mixed|null
	 */
	public function get_object_by_id( $object_type, $id = null, $meta_key = null ) {
		global $wpdb;

		if ( ! is_int( $id ) || ! is_string( $meta_key ) ) {
			return null;
		}

		$table            = _get_meta_table( $object_type );
		$object_id_column = $object_type . '_id';

		// Sanitize so that the array only has integer values.
		$meta = $wpdb->get_results(
			$wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE {$object_id_column} = %d AND meta_key = %s",
				$id,
				$meta_key
			),
			ARRAY_A
		);

		$meta_objects = null;

		if ( ! is_wp_error( $meta ) && ! empty( $meta ) ) {
			foreach ( $meta as $meta_entry ) {
				if ( 'post' === $object_type && strlen( $meta_entry['meta_value'] ) >= Posts::MAX_POST_META_LENGTH ) {
					$meta_entry['meta_value'] = '';
				}
				$meta_objects[] = array(
					'meta_type'  => $object_type,
					'meta_id'    => $meta_entry['meta_id'],
					'meta_key'   => $meta_key,
					'meta_value' => $meta_entry['meta_value'],
					'object_id'  => $meta_entry[ $object_id_column ],
				);
			}
		}

		return $meta_objects;
	}
}
