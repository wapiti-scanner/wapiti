<?php
/**
 * A base abstraction of a sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Sync\Functions;
use Automattic\Jetpack\Sync\Listener;
use Automattic\Jetpack\Sync\Replicastore;
use Automattic\Jetpack\Sync\Sender;
use Automattic\Jetpack\Sync\Settings;

/**
 * Basic methods implemented by Jetpack Sync extensions.
 *
 * @abstract
 */
abstract class Module {
	/**
	 * Number of items per chunk when grouping objects for performance reasons.
	 *
	 * @access public
	 *
	 * @var int
	 */
	const ARRAY_CHUNK_SIZE = 10;

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	abstract public function name();

	/**
	 * The id field in the database.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function id_field() {
		return 'ID';
	}

	/**
	 * The table in the database.
	 *
	 * @access public
	 *
	 * @return string|bool
	 */
	public function table_name() {
		return false;
	}

	// phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable

	/**
	 * Retrieve a sync object by its ID.
	 *
	 * @access public
	 *
	 * @param string $object_type Type of the sync object.
	 * @param int    $id          ID of the sync object.
	 * @return mixed Object, or false if the object is invalid.
	 */
	public function get_object_by_id( $object_type, $id ) {
		return false;
	}

	/**
	 * Initialize callables action listeners.
	 * Override these to set up listeners and set/reset data/defaults.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
	}

	/**
	 * Initialize module action listeners for full sync.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_full_sync_listeners( $callable ) {
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
	}

	/**
	 * Set module defaults.
	 *
	 * @access public
	 */
	public function set_defaults() {
	}

	/**
	 * Perform module cleanup.
	 * Usually triggered when uninstalling the plugin.
	 *
	 * @access public
	 */
	public function reset_data() {
	}

	/**
	 * Enqueue the module actions for full sync.
	 *
	 * @access public
	 *
	 * @param array   $config               Full sync configuration for this sync module.
	 * @param int     $max_items_to_enqueue Maximum number of items to enqueue.
	 * @param boolean $state                True if full sync has finished enqueueing this module, false otherwise.
	 * @return array  Number of actions enqueued, and next module state.
	 */
	public function enqueue_full_sync_actions( $config, $max_items_to_enqueue, $state ) {
		// In subclasses, return the number of actions enqueued, and next module state (true == done).
		return array( null, true );
	}

	/**
	 * Retrieve an estimated number of actions that will be enqueued.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return array Number of items yet to be enqueued.
	 */
	public function estimate_full_sync_actions( $config ) {
		// In subclasses, return the number of items yet to be enqueued.
		return null;
	}

	// phpcs:enable VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable

	/**
	 * Retrieve the actions that will be sent for this module during a full sync.
	 *
	 * @access public
	 *
	 * @return array Full sync actions of this module.
	 */
	public function get_full_sync_actions() {
		return array();
	}

	/**
	 * Get the number of actions that we care about.
	 *
	 * @access protected
	 *
	 * @param array $action_names     Action names we're interested in.
	 * @param array $actions_to_count Unfiltered list of actions we want to count.
	 * @return array Number of actions that we're interested in.
	 */
	protected function count_actions( $action_names, $actions_to_count ) {
		return count( array_intersect( $action_names, $actions_to_count ) );
	}

	/**
	 * Calculate the checksum of one or more values.
	 *
	 * @access protected
	 *
	 * @param mixed $values Values to calculate checksum for.
	 * @param bool  $sort If $values should have ksort called on it.
	 * @return int The checksum.
	 */
	protected function get_check_sum( $values, $sort = true ) {
		// Associative array order changes the generated checksum value.
		if ( $sort && is_array( $values ) ) {
			$this->recursive_ksort( $values );
		}
		return crc32( wp_json_encode( Functions::json_wrap( $values ) ) );
	}

	/**
	 * Recursively call ksort on an Array
	 *
	 * @param array $values Array.
	 */
	private function recursive_ksort( &$values ) {
		ksort( $values );
		foreach ( $values as &$value ) {
			if ( is_array( $value ) ) {
				$this->recursive_ksort( $value );
			}
		}
	}

	/**
	 * Whether a particular checksum in a set of checksums is valid.
	 *
	 * @access protected
	 *
	 * @param array  $sums_to_check Array of checksums.
	 * @param string $name          Name of the checksum.
	 * @param int    $new_sum       Checksum to compare against.
	 * @return boolean Whether the checksum is valid.
	 */
	protected function still_valid_checksum( $sums_to_check, $name, $new_sum ) {
		if ( isset( $sums_to_check[ $name ] ) && $sums_to_check[ $name ] === $new_sum ) {
			return true;
		}

		return false;
	}

	/**
	 * Enqueue all items of a sync type as an action.
	 *
	 * @access protected
	 *
	 * @param string  $action_name          Name of the action.
	 * @param string  $table_name           Name of the database table.
	 * @param string  $id_field             Name of the ID field in the database.
	 * @param string  $where_sql            The SQL WHERE clause to filter to the desired items.
	 * @param int     $max_items_to_enqueue Maximum number of items to enqueue in the same time.
	 * @param boolean $state                Whether enqueueing has finished.
	 * @return array Array, containing the number of chunks and TRUE, indicating enqueueing has finished.
	 */
	protected function enqueue_all_ids_as_action( $action_name, $table_name, $id_field, $where_sql, $max_items_to_enqueue, $state ) {
		global $wpdb;

		if ( ! $where_sql ) {
			$where_sql = '1 = 1';
		}

		$items_per_page        = 1000;
		$page                  = 1;
		$chunk_count           = 0;
		$previous_interval_end = $state ? $state : '~0';
		$listener              = Listener::get_instance();

		// Count down from max_id to min_id so we get newest posts/comments/etc first.
		// phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		while ( $ids = $wpdb->get_col( "SELECT {$id_field} FROM {$table_name} WHERE {$where_sql} AND {$id_field} < {$previous_interval_end} ORDER BY {$id_field} DESC LIMIT {$items_per_page}" ) ) {
			// Request posts in groups of N for efficiency.
			$chunked_ids = array_chunk( $ids, self::ARRAY_CHUNK_SIZE );

			// If we hit our row limit, process and return.
			if ( $chunk_count + count( $chunked_ids ) >= $max_items_to_enqueue ) {
				$remaining_items_count                      = $max_items_to_enqueue - $chunk_count;
				$remaining_items                            = array_slice( $chunked_ids, 0, $remaining_items_count );
				$remaining_items_with_previous_interval_end = $this->get_chunks_with_preceding_end( $remaining_items, $previous_interval_end );
				$listener->bulk_enqueue_full_sync_actions( $action_name, $remaining_items_with_previous_interval_end );

				$last_chunk = end( $remaining_items );
				return array( $remaining_items_count + $chunk_count, end( $last_chunk ) );
			}
			$chunked_ids_with_previous_end = $this->get_chunks_with_preceding_end( $chunked_ids, $previous_interval_end );

			$listener->bulk_enqueue_full_sync_actions( $action_name, $chunked_ids_with_previous_end );

			$chunk_count += count( $chunked_ids );
			++$page;
			// The $ids are ordered in descending order.
			$previous_interval_end = end( $ids );
		}

		if ( $wpdb->last_error ) {
			// return the values that were passed in so all these chunks get retried.
			return array( $max_items_to_enqueue, $state );
		}

		return array( $chunk_count, true );
	}

	/**
	 * Given the Module Full Sync Configuration and Status return the next chunk of items to send.
	 *
	 * @param array $config This module Full Sync configuration.
	 * @param array $status This module Full Sync status.
	 * @param int   $chunk_size Chunk size.
	 *
	 * @return array|object|null
	 */
	public function get_next_chunk( $config, $status, $chunk_size ) {
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		global $wpdb;
		return $wpdb->get_col(
			<<<SQL
SELECT {$this->id_field()}
FROM {$wpdb->{$this->table_name()}}
WHERE {$this->get_where_sql( $config )}
AND {$this->id_field()} < {$status['last_sent']}
ORDER BY {$this->id_field()}
DESC LIMIT {$chunk_size}
SQL
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/**
	 * Return the initial last sent object.
	 *
	 * @return string|array initial status.
	 */
	public function get_initial_last_sent() {
		return '~0';
	}

	/**
	 * Immediately send all items of a sync type as an action.
	 *
	 * @access protected
	 *
	 * @param string $config Full sync configuration for this module.
	 * @param array  $status the current module full sync status.
	 * @param float  $send_until timestamp until we want this request to send full sync events.
	 *
	 * @return array Status, the module full sync status updated.
	 */
	public function send_full_sync_actions( $config, $status, $send_until ) {
		global $wpdb;

		if ( empty( $status['last_sent'] ) ) {
			$status['last_sent'] = $this->get_initial_last_sent();
		}

		$limits = Settings::get_setting( 'full_sync_limits' )[ $this->name() ];

		$chunks_sent = 0;
		// phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
		while ( $objects = $this->get_next_chunk( $config, $status, $limits['chunk_size'] ) ) {
			if ( $chunks_sent++ === $limits['max_chunks'] || microtime( true ) >= $send_until ) {
				return $status;
			}

			$result = $this->send_action( 'jetpack_full_sync_' . $this->name(), array( $objects, $status['last_sent'] ) );

			if ( is_wp_error( $result ) || $wpdb->last_error ) {
				$status['error'] = true;
				return $status;
			}
			// The $ids are ordered in descending order.
			$status['last_sent'] = end( $objects );
			$status['sent']     += count( $objects );
		}

		if ( ! $wpdb->last_error ) {
			$status['finished'] = true;
		}

		return $status;
	}

	/**
	 * Immediately sends a single item without firing or enqueuing it
	 *
	 * @param string $action_name The action.
	 * @param array  $data The data associated with the action.
	 */
	public function send_action( $action_name, $data = null ) {
		$sender = Sender::get_instance();
		return $sender->send_action( $action_name, $data );
	}

	/**
	 * Retrieve chunk IDs with previous interval end.
	 *
	 * @access protected
	 *
	 * @param array $chunks                All remaining items.
	 * @param int   $previous_interval_end The last item from the previous interval.
	 * @return array Chunk IDs with the previous interval end.
	 */
	protected function get_chunks_with_preceding_end( $chunks, $previous_interval_end ) {
		$chunks_with_ends = array();
		foreach ( $chunks as $chunk ) {
			$chunks_with_ends[] = array(
				'ids'          => $chunk,
				'previous_end' => $previous_interval_end,
			);
			// Chunks are ordered in descending order.
			$previous_interval_end = end( $chunk );
		}
		return $chunks_with_ends;
	}

	/**
	 * Get metadata of a particular object type within the designated meta key whitelist.
	 *
	 * @access protected
	 *
	 * @todo Refactor to use $wpdb->prepare() on the SQL query.
	 *
	 * @param array  $ids                Object IDs.
	 * @param string $meta_type          Meta type.
	 * @param array  $meta_key_whitelist Meta key whitelist.
	 * @return array Unserialized meta values.
	 */
	protected function get_metadata( $ids, $meta_type, $meta_key_whitelist ) {
		global $wpdb;
		$table = _get_meta_table( $meta_type );
		$id    = $meta_type . '_id';
		if ( ! $table ) {
			return array();
		}

		$private_meta_whitelist_sql = "'" . implode( "','", array_map( 'esc_sql', $meta_key_whitelist ) ) . "'";

		return array_map(
			array( $this, 'unserialize_meta' ),
			$wpdb->get_results(
				// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared
				"SELECT $id, meta_key, meta_value, meta_id FROM $table WHERE $id IN ( " . implode( ',', wp_parse_id_list( $ids ) ) . ' )' .
				" AND meta_key IN ( $private_meta_whitelist_sql ) ",
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared
				OBJECT
			)
		);
	}

	/**
	 * Initialize listeners for the particular meta type.
	 *
	 * @access public
	 *
	 * @param string   $meta_type Meta type.
	 * @param callable $callable  Action handler callable.
	 */
	public function init_listeners_for_meta_type( $meta_type, $callable ) {
		add_action( "added_{$meta_type}_meta", $callable, 10, 4 );
		add_action( "updated_{$meta_type}_meta", $callable, 10, 4 );
		add_action( "deleted_{$meta_type}_meta", $callable, 10, 4 );
	}

	/**
	 * Initialize meta whitelist handler for the particular meta type.
	 *
	 * @access public
	 *
	 * @param string   $meta_type         Meta type.
	 * @param callable $whitelist_handler Action handler callable.
	 */
	public function init_meta_whitelist_handler( $meta_type, $whitelist_handler ) {
		add_filter( "jetpack_sync_before_enqueue_added_{$meta_type}_meta", $whitelist_handler );
		add_filter( "jetpack_sync_before_enqueue_updated_{$meta_type}_meta", $whitelist_handler );
		add_filter( "jetpack_sync_before_enqueue_deleted_{$meta_type}_meta", $whitelist_handler );
	}

	/**
	 * Retrieve the term relationships for the specified object IDs.
	 *
	 * @access protected
	 *
	 * @todo This feels too specific to be in the abstract sync Module class. Move it?
	 *
	 * @param array $ids Object IDs.
	 * @return array Term relationships - object ID and term taxonomy ID pairs.
	 */
	protected function get_term_relationships( $ids ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		return $wpdb->get_results( "SELECT object_id, term_taxonomy_id FROM $wpdb->term_relationships WHERE object_id IN ( " . implode( ',', wp_parse_id_list( $ids ) ) . ' )', OBJECT );
	}

	/**
	 * Unserialize the value of a meta object, if necessary.
	 *
	 * @access public
	 *
	 * @param object $meta Meta object.
	 * @return object Meta object with possibly unserialized value.
	 */
	public function unserialize_meta( $meta ) {
		$meta->meta_value = maybe_unserialize( $meta->meta_value );
		return $meta;
	}

	/**
	 * Retrieve a set of objects by their IDs.
	 *
	 * @access public
	 *
	 * @param string $object_type Object type.
	 * @param array  $ids         Object IDs.
	 * @return array Array of objects.
	 */
	public function get_objects_by_id( $object_type, $ids ) {
		if ( empty( $ids ) || empty( $object_type ) ) {
			return array();
		}

		$objects = array();
		foreach ( (array) $ids as $id ) {
			$object = $this->get_object_by_id( $object_type, $id );

			// Only add object if we have the object.
			if ( $object ) {
				$objects[ $id ] = $object;
			}
		}

		return $objects;
	}

	/**
	 * Gets a list of minimum and maximum object ids for each batch based on the given batch size.
	 *
	 * @access public
	 *
	 * @param int         $batch_size The batch size for objects.
	 * @param string|bool $where_sql  The sql where clause minus 'WHERE', or false if no where clause is needed.
	 *
	 * @return array|bool An array of min and max ids for each batch. FALSE if no table can be found.
	 */
	public function get_min_max_object_ids_for_batches( $batch_size, $where_sql = false ) {
		global $wpdb;

		if ( ! $this->table_name() ) {
			return false;
		}

		$results      = array();
		$table        = $wpdb->{$this->table_name()};
		$current_max  = 0;
		$current_min  = 1;
		$id_field     = $this->id_field();
		$replicastore = new Replicastore();

		$total = $replicastore->get_min_max_object_id(
			$id_field,
			$table,
			$where_sql,
			false
		);

		while ( $total->max > $current_max ) {
			$where  = $where_sql ?
				$where_sql . " AND $id_field > $current_max" :
				"$id_field > $current_max";
			$result = $replicastore->get_min_max_object_id(
				$id_field,
				$table,
				$where,
				$batch_size
			);
			if ( empty( $result->min ) && empty( $result->max ) ) {
				// Our query produced no min and max. We can assume the min from the previous query,
				// and the total max we found in the initial query.
				$current_max = (int) $total->max;
				$result      = (object) array(
					'min' => $current_min,
					'max' => $current_max,
				);
			} else {
				$current_min = (int) $result->min;
				$current_max = (int) $result->max;
			}
			$results[] = $result;
		}

		return $results;
	}

	/**
	 * Return Total number of objects.
	 *
	 * @param array $config Full Sync config.
	 *
	 * @return int total
	 */
	public function total( $config ) {
		global $wpdb;
		$table = $wpdb->{$this->table_name()};
		$where = $this->get_where_sql( $config );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_var( "SELECT COUNT(*) FROM $table WHERE $where" );
	}

	/**
	 * Retrieve the WHERE SQL clause based on the module config.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return string WHERE SQL clause, or `null` if no comments are specified in the module config.
	 */
	public function get_where_sql( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return '1=1';
	}

}
