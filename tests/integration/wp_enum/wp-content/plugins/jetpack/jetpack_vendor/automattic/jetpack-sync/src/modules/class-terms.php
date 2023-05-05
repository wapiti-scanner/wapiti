<?php
/**
 * Terms sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Sync\Defaults;
use Automattic\Jetpack\Sync\Settings;

/**
 * Class to handle sync for terms.
 */
class Terms extends Module {

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'terms';
	}

	/**
	 * The id field in the database.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function id_field() {
		return 'term_taxonomy_id';
	}

	/**
	 * The table in the database.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function table_name() {
		return 'term_taxonomy';
	}

	/**
	 * Allows WordPress.com servers to retrieve term-related objects via the sync API.
	 *
	 * @param string $object_type The type of object.
	 * @param int    $id          The id of the object.
	 *
	 * @return bool|object A WP_Term object, or a row from term_taxonomy table depending on object type.
	 */
	public function get_object_by_id( $object_type, $id ) {
		global $wpdb;
		$object = false;
		if ( 'term' === $object_type ) {
			$object = get_term( (int) $id );

			if ( is_wp_error( $object ) && $object->get_error_code() === 'invalid_taxonomy' ) {
				// Fetch raw term.
				$columns = implode( ', ', array_unique( array_merge( Defaults::$default_term_checksum_columns, array( 'term_group' ) ) ) );
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$object = $wpdb->get_row( $wpdb->prepare( "SELECT $columns FROM $wpdb->terms WHERE term_id = %d", $id ) );
			}
		}

		if ( 'term_taxonomy' === $object_type ) {
			$columns = implode( ', ', array_unique( array_merge( Defaults::$default_term_taxonomy_checksum_columns, array( 'description' ) ) ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$object = $wpdb->get_row( $wpdb->prepare( "SELECT $columns FROM $wpdb->term_taxonomy WHERE term_taxonomy_id = %d", $id ) );
		}

		if ( 'term_relationships' === $object_type ) {
			$columns = implode( ', ', Defaults::$default_term_relationships_checksum_columns );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$objects = $wpdb->get_results( $wpdb->prepare( "SELECT $columns FROM $wpdb->term_relationships WHERE object_id = %d", $id ) );
			$object  = (object) array(
				'object_id'     => $id,
				'relationships' => array_map( array( $this, 'expand_terms_for_relationship' ), $objects ),
			);
		}

		return $object ? $object : false;
	}

	/**
	 * Initialize terms action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		add_action( 'created_term', array( $this, 'save_term_handler' ), 10, 3 );
		add_action( 'edited_term', array( $this, 'save_term_handler' ), 10, 3 );
		add_action( 'jetpack_sync_save_term', $callable );
		add_action( 'jetpack_sync_add_term', $callable );
		add_action( 'delete_term', $callable, 10, 4 );
		add_action( 'set_object_terms', $callable, 10, 6 );
		add_action( 'deleted_term_relationships', $callable, 10, 2 );
		add_filter( 'jetpack_sync_before_enqueue_set_object_terms', array( $this, 'filter_set_object_terms_no_update' ) );
		add_filter( 'jetpack_sync_before_enqueue_jetpack_sync_save_term', array( $this, 'filter_blacklisted_taxonomies' ) );
		add_filter( 'jetpack_sync_before_enqueue_jetpack_sync_add_term', array( $this, 'filter_blacklisted_taxonomies' ) );
	}

	/**
	 * Initialize terms action listeners for full sync.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_full_sync_listeners( $callable ) {
		add_action( 'jetpack_full_sync_terms', $callable, 10, 2 );
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
		// Full sync.
		add_filter( 'jetpack_sync_before_send_jetpack_full_sync_terms', array( $this, 'expand_term_taxonomy_id' ) );
	}

	/**
	 * Enqueue the terms actions for full sync.
	 *
	 * @access public
	 *
	 * @param array   $config               Full sync configuration for this sync module.
	 * @param int     $max_items_to_enqueue Maximum number of items to enqueue.
	 * @param boolean $state                True if full sync has finished enqueueing this module, false otherwise.
	 * @return array Number of actions enqueued, and next module state.
	 */
	public function enqueue_full_sync_actions( $config, $max_items_to_enqueue, $state ) {
		global $wpdb;
		return $this->enqueue_all_ids_as_action( 'jetpack_full_sync_terms', $wpdb->term_taxonomy, 'term_taxonomy_id', $this->get_where_sql( $config ), $max_items_to_enqueue, $state );
	}

	/**
	 * Retrieve the WHERE SQL clause based on the module config.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return string WHERE SQL clause, or `null` if no comments are specified in the module config.
	 */
	public function get_where_sql( $config ) {
		$where_sql = Settings::get_blacklisted_taxonomies_sql();

		if ( is_array( $config ) ) {
			$where_sql .= ' AND term_taxonomy_id IN (' . implode( ',', array_map( 'intval', $config ) ) . ')';
		}

		return $where_sql;
	}

	/**
	 * Retrieve an estimated number of actions that will be enqueued.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return int Number of items yet to be enqueued.
	 */
	public function estimate_full_sync_actions( $config ) {
		global $wpdb;

		$query = "SELECT count(*) FROM $wpdb->term_taxonomy";

		$where_sql = $this->get_where_sql( $config );
		if ( $where_sql ) {
			$query .= ' WHERE ' . $where_sql;
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
		$count = $wpdb->get_var( $query );

		return (int) ceil( $count / self::ARRAY_CHUNK_SIZE );
	}

	/**
	 * Retrieve the actions that will be sent for this module during a full sync.
	 *
	 * @access public
	 *
	 * @return array Full sync actions of this module.
	 */
	public function get_full_sync_actions() {
		return array( 'jetpack_full_sync_terms' );
	}

	/**
	 * Handler for creating and updating terms.
	 *
	 * @access public
	 *
	 * @param int    $term_id  Term ID.
	 * @param int    $tt_id    Term taxonomy ID.
	 * @param string $taxonomy Taxonomy slug.
	 */
	public function save_term_handler( $term_id, $tt_id, $taxonomy ) {
		if ( class_exists( '\\WP_Term' ) ) {
			$term_object = \WP_Term::get_instance( $term_id, $taxonomy );
		} else {
			$term_object = get_term_by( 'id', $term_id, $taxonomy );
		}

		$current_filter = current_filter();

		if ( 'created_term' === $current_filter ) {
			/**
			 * Fires when the client needs to add a new term
			 *
			 * @since 1.6.3
			 * @since-jetpack 5.0.0
			 *
			 * @param object the Term object
			 */
			do_action( 'jetpack_sync_add_term', $term_object );
			return;
		}

		/**
		 * Fires when the client needs to update a term
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param object the Term object
		 */
		do_action( 'jetpack_sync_save_term', $term_object );
	}

	/**
	 * Filter blacklisted taxonomies.
	 *
	 * @access public
	 *
	 * @param array $args Hook args.
	 * @return array|boolean False if not whitelisted, the original hook args otherwise.
	 */
	public function filter_blacklisted_taxonomies( $args ) {
		$term = $args[0];

		if ( in_array( $term->taxonomy, Settings::get_setting( 'taxonomies_blacklist' ), true ) ) {
			return false;
		}

		return $args;
	}

	/**
	 * Filter out set_object_terms actions where the terms have not changed.
	 *
	 * @param array $args Hook args.
	 * @return array|boolean False if no change in terms, the original hook args otherwise.
	 */
	public function filter_set_object_terms_no_update( $args ) {
		// There is potential for other plugins to modify args, therefore lets validate # of and types.
		// $args[2] is $tt_ids, $args[5] is $old_tt_ids see wp-includes/taxonomy.php L2740.
		if ( 6 === count( $args ) && is_array( $args[2] ) && is_array( $args[5] ) ) {
			if ( empty( array_diff( $args[2], $args[5] ) ) && empty( array_diff( $args[5], $args[2] ) ) ) {
				return false;
			}
		}
		return $args;
	}

	/**
	 * Expand the term taxonomy IDs to terms within a hook before they are serialized and sent to the server.
	 *
	 * @access public
	 *
	 * @param array $args The hook parameters.
	 * @return array $args The expanded hook parameters.
	 */
	public function expand_term_taxonomy_id( $args ) {
		list( $term_taxonomy_ids,  $previous_end ) = $args;

		return array(
			'terms'        => get_terms(
				array(
					'hide_empty'       => false,
					'term_taxonomy_id' => $term_taxonomy_ids,
					'orderby'          => 'term_taxonomy_id',
					'order'            => 'DESC',
				)
			),
			'previous_end' => $previous_end,
		);
	}

	/**
	 * Gets a term object based on a given row from the term_relationships database table.
	 *
	 * @access public
	 *
	 * @param object $relationship A row object from the term_relationships table.
	 * @return object|bool A term object, or false if term taxonomy doesn't exist.
	 */
	public function expand_terms_for_relationship( $relationship ) {
		return get_term_by( 'term_taxonomy_id', $relationship->term_taxonomy_id );
	}

}
