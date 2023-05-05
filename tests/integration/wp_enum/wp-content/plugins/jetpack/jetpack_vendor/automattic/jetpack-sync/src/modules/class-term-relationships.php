<?php
/**
 * Term relationships sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Sync\Listener;
use Automattic\Jetpack\Sync\Settings;

/**
 * Class to handle sync for term relationships.
 */
class Term_Relationships extends Module {

	/**
	 * Max terms to return in one single query
	 *
	 * @access public
	 *
	 * @const int
	 */
	const QUERY_LIMIT = 1000;

	/**
	 * Max value for a signed INT in MySQL - https://dev.mysql.com/doc/refman/8.0/en/integer-types.html
	 *
	 * @access public
	 *
	 * @const int
	 */
	const MAX_INT = 2147483647;

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'term_relationships';
	}

	/**
	 * The id field in the database.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function id_field() {
		return 'object_id';
	}

	/**
	 * The table in the database.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function table_name() {
		return 'term_relationships';
	}

	/**
	 * Initialize term relationships action listeners for full sync.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_full_sync_listeners( $callable ) {
		add_action( 'jetpack_full_sync_term_relationships', $callable, 10, 2 );
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
		// Full sync.
		add_filter( 'jetpack_sync_before_send_jetpack_full_sync_term_relationships', array( $this, 'expand_term_relationships' ) );
	}

	/**
	 * Enqueue the term relationships actions for full sync.
	 *
	 * @access public
	 *
	 * @param array  $config Full sync configuration for this sync module.
	 * @param int    $max_items_to_enqueue Maximum number of items to enqueue.
	 * @param object $last_object_enqueued Last object enqueued.
	 *
	 * @return array Number of actions enqueued, and next module state.
	 * @todo This method has similarities with Automattic\Jetpack\Sync\Modules\Module::enqueue_all_ids_as_action. Refactor to keep DRY.
	 * @see Automattic\Jetpack\Sync\Modules\Module::enqueue_all_ids_as_action
	 */
	public function enqueue_full_sync_actions( $config, $max_items_to_enqueue, $last_object_enqueued ) {
		global $wpdb;
		$term_relationships_full_sync_item_size = Settings::get_setting( 'term_relationships_full_sync_item_size' );
		$limit                                  = min( $max_items_to_enqueue * $term_relationships_full_sync_item_size, self::QUERY_LIMIT );
		$items_enqueued_count                   = 0;
		$last_object_enqueued                   = $last_object_enqueued ? $last_object_enqueued : array(
			'object_id'        => self::MAX_INT,
			'term_taxonomy_id' => self::MAX_INT,
		);

		while ( $limit > 0 ) {
			/*
			 * SELECT object_id, term_taxonomy_id
			 *  FROM $wpdb->term_relationships
			 *  WHERE ( object_id = 11 AND term_taxonomy_id < 14 ) OR ( object_id < 11 )
			 *  ORDER BY object_id DESC, term_taxonomy_id DESC LIMIT 1000
			 */
			$objects = $wpdb->get_results( $wpdb->prepare( "SELECT object_id, term_taxonomy_id FROM $wpdb->term_relationships WHERE ( object_id = %d AND term_taxonomy_id < %d ) OR ( object_id < %d ) ORDER BY object_id DESC, term_taxonomy_id DESC LIMIT %d", $last_object_enqueued['object_id'], $last_object_enqueued['term_taxonomy_id'], $last_object_enqueued['object_id'], $limit ), ARRAY_A );
			// Request term relationships in groups of N for efficiency.
			$objects_count = count( $objects );
			if ( ! count( $objects ) ) {
				return array( $items_enqueued_count, true );
			}
			$items                 = array_chunk( $objects, $term_relationships_full_sync_item_size );
			$last_object_enqueued  = $this->bulk_enqueue_full_sync_term_relationships( $items, $last_object_enqueued );
			$items_enqueued_count += count( $items );
			$limit                 = min( $limit - $objects_count, self::QUERY_LIMIT );
		}

		// We need to do this extra check in case $max_items_to_enqueue * $term_relationships_full_sync_item_size == relationships objects left.
		$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $wpdb->term_relationships WHERE ( object_id = %d AND term_taxonomy_id < %d ) OR ( object_id < %d ) ORDER BY object_id DESC, term_taxonomy_id DESC LIMIT %d", $last_object_enqueued['object_id'], $last_object_enqueued['term_taxonomy_id'], $last_object_enqueued['object_id'], 1 ) );
		if ( 0 === (int) $count ) {
			return array( $items_enqueued_count, true );
		}

		return array( $items_enqueued_count, $last_object_enqueued );
	}

	/**
	 * Return the initial last sent object.
	 *
	 * @return string|array initial status.
	 */
	public function get_initial_last_sent() {
		return array(
			'object_id'        => self::MAX_INT,
			'term_taxonomy_id' => self::MAX_INT,
		);
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
		global $wpdb;

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT object_id, term_taxonomy_id 
				FROM $wpdb->term_relationships 
				WHERE ( object_id = %d AND term_taxonomy_id < %d ) OR ( object_id < %d ) 
				ORDER BY object_id DESC, term_taxonomy_id 
				DESC LIMIT %d",
				$status['last_sent']['object_id'],
				$status['last_sent']['term_taxonomy_id'],
				$status['last_sent']['object_id'],
				$chunk_size
			),
			ARRAY_A
		);
	}

	/**
	 *
	 * Enqueue all $items within `jetpack_full_sync_term_relationships` actions.
	 *
	 * @param array $items Groups of objects to sync.
	 * @param array $previous_interval_end Last item enqueued.
	 *
	 * @return array Last enqueued object.
	 */
	public function bulk_enqueue_full_sync_term_relationships( $items, $previous_interval_end ) {
		$listener                         = Listener::get_instance();
		$items_with_previous_interval_end = $this->get_chunks_with_preceding_end( $items, $previous_interval_end );
		$listener->bulk_enqueue_full_sync_actions( 'jetpack_full_sync_term_relationships', $items_with_previous_interval_end );
		$last_item = end( $items );
		return end( $last_item );
	}

	/**
	 * Retrieve an estimated number of actions that will be enqueued.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return int Number of items yet to be enqueued.
	 */
	public function estimate_full_sync_actions( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		global $wpdb;

		$query = "SELECT COUNT(*) FROM $wpdb->term_relationships";

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
		$count = $wpdb->get_var( $query );

		return (int) ceil( $count / Settings::get_setting( 'term_relationships_full_sync_item_size' ) );
	}

	/**
	 * Retrieve the actions that will be sent for this module during a full sync.
	 *
	 * @access public
	 *
	 * @return array Full sync actions of this module.
	 */
	public function get_full_sync_actions() {
		return array( 'jetpack_full_sync_term_relationships' );
	}

	/**
	 * Expand the term relationships within a hook before they are serialized and sent to the server.
	 *
	 * @access public
	 *
	 * @param array $args The hook parameters.
	 * @return array $args The expanded hook parameters.
	 */
	public function expand_term_relationships( $args ) {
		list( $term_relationships, $previous_end ) = $args;

		return array(
			'term_relationships' => $term_relationships,
			'previous_end'       => $previous_end,
		);
	}
}
