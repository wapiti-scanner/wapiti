<?php
/**
 * Sync replicastore.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use Automattic\Jetpack\Sync\Replicastore\Table_Checksum;
use Automattic\Jetpack\Sync\Replicastore\Table_Checksum_Usermeta;
use Automattic\Jetpack\Sync\Replicastore\Table_Checksum_Users;
use Exception;
use WP_Error;

/**
 * An implementation of Replicastore Interface which returns data stored in a WordPress.org DB.
 * This is useful to compare values in the local WP DB to values in the synced replica store
 */
class Replicastore implements Replicastore_Interface {
	/**
	 * Empty and reset the replicastore.
	 *
	 * @access public
	 */
	public function reset() {
		global $wpdb;

		$wpdb->query( "DELETE FROM $wpdb->posts" );

		// Delete comments from cache.
		$comment_ids = $wpdb->get_col( "SELECT comment_ID FROM $wpdb->comments" );
		if ( ! empty( $comment_ids ) ) {
			clean_comment_cache( $comment_ids );
		}
		$wpdb->query( "DELETE FROM $wpdb->comments" );

		// Also need to delete terms from cache.
		$term_ids = $wpdb->get_col( "SELECT term_id FROM $wpdb->terms" );
		foreach ( $term_ids as $term_id ) {
			wp_cache_delete( $term_id, 'terms' );
		}

		$wpdb->query( "DELETE FROM $wpdb->terms" );

		$wpdb->query( "DELETE FROM $wpdb->term_taxonomy" );
		$wpdb->query( "DELETE FROM $wpdb->term_relationships" );

		// Callables and constants.
		$wpdb->query( "DELETE FROM $wpdb->options WHERE option_name LIKE 'jetpack_%'" );
		$wpdb->query( "DELETE FROM $wpdb->postmeta WHERE meta_key NOT LIKE '\_%'" );
	}

	/**
	 * Ran when full sync has just started.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 */
	public function full_sync_start( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$this->reset();
	}

	/**
	 * Ran when full sync has just finished.
	 *
	 * @access public
	 *
	 * @param string $checksum Deprecated since 7.3.0.
	 */
	public function full_sync_end( $checksum ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		// Noop right now.
	}

	/**
	 * Retrieve the number of terms.
	 *
	 * @access public
	 *
	 * @return int Number of terms.
	 */
	public function term_count() {
		global $wpdb;
		return $wpdb->get_var( "SELECT COUNT(*) FROM $wpdb->terms" );
	}

	/**
	 * Retrieve the number of rows in the `term_taxonomy` table.
	 *
	 * @access public
	 *
	 * @return int Number of terms.
	 */
	public function term_taxonomy_count() {
		global $wpdb;
		return $wpdb->get_var( "SELECT COUNT(*) FROM $wpdb->term_taxonomy" );
	}

	/**
	 * Retrieve the number of term relationships.
	 *
	 * @access public
	 *
	 * @return int Number of rows in the term relationships table.
	 */
	public function term_relationship_count() {
		global $wpdb;
		return $wpdb->get_var( "SELECT COUNT(*) FROM $wpdb->term_relationships" );
	}

	/**
	 * Retrieve the number of posts with a particular post status within a certain range.
	 *
	 * @access public
	 *
	 * @todo Prepare the SQL query before executing it.
	 *
	 * @param string $status Post status.
	 * @param int    $min_id Minimum post ID.
	 * @param int    $max_id Maximum post ID.
	 * @return int Number of posts.
	 */
	public function post_count( $status = null, $min_id = null, $max_id = null ) {
		global $wpdb;

		$where = '';

		if ( $status ) {
			$where = "post_status = '" . esc_sql( $status ) . "'";
		} else {
			$where = '1=1';
		}

		if ( ! empty( $min_id ) ) {
			$where .= ' AND ID >= ' . (int) $min_id;
		}

		if ( ! empty( $max_id ) ) {
			$where .= ' AND ID <= ' . (int) $max_id;
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_var( "SELECT COUNT(*) FROM $wpdb->posts WHERE $where" );
	}

	/**
	 * Retrieve the posts with a particular post status.
	 *
	 * @access public
	 *
	 * @todo Implement range and actually use max_id/min_id arguments.
	 *
	 * @param string $status Post status.
	 * @param int    $min_id Minimum post ID.
	 * @param int    $max_id Maximum post ID.
	 * @return array Array of posts.
	 */
	public function get_posts( $status = null, $min_id = null, $max_id = null ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$args = array(
			'orderby'        => 'ID',
			'posts_per_page' => -1,
		);

		if ( $status ) {
			$args['post_status'] = $status;
		} else {
			$args['post_status'] = 'any';
		}

		return get_posts( $args );
	}

	/**
	 * Retrieve a post object by the post ID.
	 *
	 * @access public
	 *
	 * @param int $id Post ID.
	 * @return \WP_Post Post object.
	 */
	public function get_post( $id ) {
		return get_post( $id );
	}

	/**
	 * Update or insert a post.
	 *
	 * @access public
	 *
	 * @param \WP_Post $post   Post object.
	 * @param bool     $silent Whether to perform a silent action. Not used in this implementation.
	 */
	public function upsert_post( $post, $silent = false ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		global $wpdb;

		// Reject the post if it's not a \WP_Post.
		if ( ! $post instanceof \WP_Post ) {
			return;
		}

		$post = $post->to_array();

		// Reject posts without an ID.
		if ( ! isset( $post['ID'] ) ) {
			return;
		}

		$now     = current_time( 'mysql' );
		$now_gmt = get_gmt_from_date( $now );

		$defaults = array(
			'ID'                    => 0,
			'post_author'           => '0',
			'post_content'          => '',
			'post_content_filtered' => '',
			'post_title'            => '',
			'post_name'             => '',
			'post_excerpt'          => '',
			'post_status'           => 'draft',
			'post_type'             => 'post',
			'comment_status'        => 'closed',
			'comment_count'         => '0',
			'ping_status'           => '',
			'post_password'         => '',
			'to_ping'               => '',
			'pinged'                => '',
			'post_parent'           => 0,
			'menu_order'            => 0,
			'guid'                  => '',
			'post_date'             => $now,
			'post_date_gmt'         => $now_gmt,
			'post_modified'         => $now,
			'post_modified_gmt'     => $now_gmt,
		);

		$post = array_intersect_key( $post, $defaults );

		$post = sanitize_post( $post, 'db' );

		unset( $post['filter'] );

		$exists = $wpdb->get_var( $wpdb->prepare( "SELECT EXISTS( SELECT 1 FROM $wpdb->posts WHERE ID = %d )", $post['ID'] ) );

		if ( $exists ) {
			$wpdb->update( $wpdb->posts, $post, array( 'ID' => $post['ID'] ) );
		} else {
			$wpdb->insert( $wpdb->posts, $post );
		}

		clean_post_cache( $post['ID'] );
	}

	/**
	 * Delete a post by the post ID.
	 *
	 * @access public
	 *
	 * @param int $post_id Post ID.
	 */
	public function delete_post( $post_id ) {
		wp_delete_post( $post_id, true );
	}

	/**
	 * Retrieve the checksum for posts within a range.
	 *
	 * @access public
	 *
	 * @param int $min_id Minimum post ID.
	 * @param int $max_id Maximum post ID.
	 * @return int The checksum.
	 */
	public function posts_checksum( $min_id = null, $max_id = null ) {
		return $this->summarize_checksum_histogram( $this->checksum_histogram( 'posts', null, $min_id, $max_id ) );
	}

	/**
	 * Retrieve the checksum for post meta within a range.
	 *
	 * @access public
	 *
	 * @param int $min_id Minimum post meta ID.
	 * @param int $max_id Maximum post meta ID.
	 * @return int The checksum.
	 */
	public function post_meta_checksum( $min_id = null, $max_id = null ) {
		return $this->summarize_checksum_histogram( $this->checksum_histogram( 'postmeta', null, $min_id, $max_id ) );
	}

	/**
	 * Retrieve the number of comments with a particular comment status within a certain range.
	 *
	 * @access public
	 *
	 * @todo Prepare the SQL query before executing it.
	 *
	 * @param string $status Comment status.
	 * @param int    $min_id Minimum comment ID.
	 * @param int    $max_id Maximum comment ID.
	 * @return int Number of comments.
	 */
	public function comment_count( $status = null, $min_id = null, $max_id = null ) {
		global $wpdb;

		$comment_approved = $this->comment_status_to_approval_value( $status );

		if ( false !== $comment_approved ) {
			$where = "comment_approved = '" . esc_sql( $comment_approved ) . "'";
		} else {
			$where = '1=1';
		}

		if ( ! empty( $min_id ) ) {
			$where .= ' AND comment_ID >= ' . (int) $min_id;
		}

		if ( ! empty( $max_id ) ) {
			$where .= ' AND comment_ID <= ' . (int) $max_id;
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_var( "SELECT COUNT(*) FROM $wpdb->comments WHERE $where" );
	}

	/**
	 * Translate a comment status to a value of the comment_approved field.
	 *
	 * @access protected
	 *
	 * @param string $status Comment status.
	 * @return string|bool New comment_approved value, false if the status doesn't affect it.
	 */
	protected function comment_status_to_approval_value( $status ) {
		switch ( (string) $status ) {
			case 'approve':
			case '1':
				return '1';
			case 'hold':
			case '0':
				return '0';
			case 'spam':
				return 'spam';
			case 'trash':
				return 'trash';
			case 'post-trashed':
				return 'post-trashed';
			case 'any':
			case 'all':
			default:
				return false;
		}
	}

	/**
	 * Retrieve the comments with a particular comment status.
	 *
	 * @access public
	 *
	 * @todo Implement range and actually use max_id/min_id arguments.
	 *
	 * @param string $status Comment status.
	 * @param int    $min_id Minimum comment ID.
	 * @param int    $max_id Maximum comment ID.
	 * @return array Array of comments.
	 */
	public function get_comments( $status = null, $min_id = null, $max_id = null ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$args = array(
			'orderby' => 'ID',
			'status'  => 'all',
		);

		if ( $status ) {
			$args['status'] = $status;
		}

		return get_comments( $args );
	}

	/**
	 * Retrieve a comment object by the comment ID.
	 *
	 * @access public
	 *
	 * @param int $id Comment ID.
	 * @return \WP_Comment Comment object.
	 */
	public function get_comment( $id ) {
		return \WP_Comment::get_instance( $id );
	}

	/**
	 * Update or insert a comment.
	 *
	 * @access public
	 *
	 * @param \WP_Comment $comment Comment object.
	 */
	public function upsert_comment( $comment ) {
		global $wpdb;

		$comment = $comment->to_array();

		// Filter by fields on comment table.
		$comment_fields_whitelist = array(
			'comment_ID',
			'comment_post_ID',
			'comment_author',
			'comment_author_email',
			'comment_author_url',
			'comment_author_IP',
			'comment_date',
			'comment_date_gmt',
			'comment_content',
			'comment_karma',
			'comment_approved',
			'comment_agent',
			'comment_type',
			'comment_parent',
			'user_id',
		);

		foreach ( $comment as $key => $value ) {
			if ( ! in_array( $key, $comment_fields_whitelist, true ) ) {
				unset( $comment[ $key ] );
			}
		}

		$exists = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT EXISTS( SELECT 1 FROM $wpdb->comments WHERE comment_ID = %d )",
				$comment['comment_ID']
			)
		);

		if ( $exists ) {
			$wpdb->update( $wpdb->comments, $comment, array( 'comment_ID' => $comment['comment_ID'] ) );
		} else {
			$wpdb->insert( $wpdb->comments, $comment );
		}
		// Remove comment from cache.
		clean_comment_cache( $comment['comment_ID'] );

		wp_update_comment_count( $comment['comment_post_ID'] );
	}

	/**
	 * Trash a comment by the comment ID.
	 *
	 * @access public
	 *
	 * @param int $comment_id Comment ID.
	 */
	public function trash_comment( $comment_id ) {
		wp_delete_comment( $comment_id );
	}

	/**
	 * Delete a comment by the comment ID.
	 *
	 * @access public
	 *
	 * @param int $comment_id Comment ID.
	 */
	public function delete_comment( $comment_id ) {
		wp_delete_comment( $comment_id, true );
	}

	/**
	 * Mark a comment by the comment ID as spam.
	 *
	 * @access public
	 *
	 * @param int $comment_id Comment ID.
	 */
	public function spam_comment( $comment_id ) {
		wp_spam_comment( $comment_id );
	}

	/**
	 * Trash the comments of a post.
	 *
	 * @access public
	 *
	 * @param int   $post_id  Post ID.
	 * @param array $statuses Post statuses. Not used in this implementation.
	 */
	public function trashed_post_comments( $post_id, $statuses ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		wp_trash_post_comments( $post_id );
	}

	/**
	 * Untrash the comments of a post.
	 *
	 * @access public
	 *
	 * @param int $post_id Post ID.
	 */
	public function untrashed_post_comments( $post_id ) {
		wp_untrash_post_comments( $post_id );
	}

	/**
	 * Retrieve the checksum for comments within a range.
	 *
	 * @access public
	 *
	 * @param int $min_id Minimum comment ID.
	 * @param int $max_id Maximum comment ID.
	 * @return int The checksum.
	 */
	public function comments_checksum( $min_id = null, $max_id = null ) {
		return $this->summarize_checksum_histogram( $this->checksum_histogram( 'comments', null, $min_id, $max_id ) );
	}

	/**
	 * Retrieve the checksum for comment meta within a range.
	 *
	 * @access public
	 *
	 * @param int $min_id Minimum comment meta ID.
	 * @param int $max_id Maximum comment meta ID.
	 * @return int The checksum.
	 */
	public function comment_meta_checksum( $min_id = null, $max_id = null ) {
		return $this->summarize_checksum_histogram( $this->checksum_histogram( 'commentmeta', null, $min_id, $max_id ) );
	}

	/**
	 * Update the value of an option.
	 *
	 * @access public
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Option value.
	 * @return bool False if value was not updated and true if value was updated.
	 */
	public function update_option( $option, $value ) {
		return update_option( $option, $value );
	}

	/**
	 * Retrieve an option value based on an option name.
	 *
	 * @access public
	 *
	 * @param string $option  Name of option to retrieve.
	 * @param mixed  $default Optional. Default value to return if the option does not exist.
	 * @return mixed Value set for the option.
	 */
	public function get_option( $option, $default = false ) {
		return get_option( $option, $default );
	}

	/**
	 * Remove an option by name.
	 *
	 * @access public
	 *
	 * @param string $option Name of option to remove.
	 * @return bool True, if option is successfully deleted. False on failure.
	 */
	public function delete_option( $option ) {
		return delete_option( $option );
	}

	/**
	 * Change the info of the current theme.
	 *
	 * @access public
	 *
	 * @param array $theme_info Theme info array.
	 */
	public function set_theme_info( $theme_info ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		// Noop.
	}

	/**
	 * Whether the current theme supports a certain feature.
	 *
	 * @access public
	 *
	 * @param string $feature Name of the feature.
	 */
	public function current_theme_supports( $feature ) {
		return current_theme_supports( $feature );
	}

	/**
	 * Retrieve metadata for the specified object.
	 *
	 * @access public
	 *
	 * @param string $type       Meta type.
	 * @param int    $object_id  ID of the object.
	 * @param string $meta_key   Meta key.
	 * @param bool   $single     If true, return only the first value of the specified meta_key.
	 *
	 * @return mixed Single metadata value, or array of values.
	 */
	public function get_metadata( $type, $object_id, $meta_key = '', $single = false ) {
		return get_metadata( $type, $object_id, $meta_key, $single );
	}

	/**
	 * Stores remote meta key/values alongside an ID mapping key.
	 *
	 * @access public
	 *
	 * @todo Refactor to not use interpolated values when preparing the SQL query.
	 *
	 * @param string $type       Meta type.
	 * @param int    $object_id  ID of the object.
	 * @param string $meta_key   Meta key.
	 * @param mixed  $meta_value Meta value.
	 * @param int    $meta_id    ID of the meta.
	 *
	 * @return bool False if meta table does not exist, true otherwise.
	 */
	public function upsert_metadata( $type, $object_id, $meta_key, $meta_value, $meta_id ) {
		$table = _get_meta_table( $type );
		if ( ! $table ) {
			return false;
		}

		global $wpdb;

		$exists = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT EXISTS( SELECT 1 FROM $table WHERE meta_id = %d )",
				$meta_id
			)
		);

		if ( $exists ) {
			$wpdb->update(
				$table,
				array(
					'meta_key'   => $meta_key,
					'meta_value' => maybe_serialize( $meta_value ),
				),
				array( 'meta_id' => $meta_id )
			);
		} else {
			$object_id_field = $type . '_id';
			$wpdb->insert(
				$table,
				array(
					'meta_id'        => $meta_id,
					$object_id_field => $object_id,
					'meta_key'       => $meta_key,
					'meta_value'     => maybe_serialize( $meta_value ),
				)
			);
		}

		wp_cache_delete( $object_id, $type . '_meta' );

		return true;
	}

	/**
	 * Delete metadata for the specified object.
	 *
	 * @access public
	 *
	 * @todo Refactor to not use interpolated values when preparing the SQL query.
	 *
	 * @param string $type      Meta type.
	 * @param int    $object_id ID of the object.
	 * @param array  $meta_ids  IDs of the meta objects to delete.
	 */
	public function delete_metadata( $type, $object_id, $meta_ids ) {
		global $wpdb;

		$table = _get_meta_table( $type );
		if ( ! $table ) {
			return false;
		}

		foreach ( $meta_ids as $meta_id ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE meta_id = %d", $meta_id ) );
		}

		// If we don't have an object ID what do we do - invalidate ALL meta?
		if ( $object_id ) {
			wp_cache_delete( $object_id, $type . '_meta' );
		}
	}

	/**
	 * Delete metadata with a certain key for the specified objects.
	 *
	 * @access public
	 *
	 * @todo Test this out to make sure it works as expected.
	 * @todo Refactor to not use interpolated values when preparing the SQL query.
	 *
	 * @param string $type       Meta type.
	 * @param array  $object_ids IDs of the objects.
	 * @param string $meta_key   Meta key.
	 */
	public function delete_batch_metadata( $type, $object_ids, $meta_key ) {
		global $wpdb;

		$table = _get_meta_table( $type );
		if ( ! $table ) {
			return false;
		}
		$column = sanitize_key( $type . '_id' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE $column IN (%s) && meta_key = %s", implode( ',', $object_ids ), $meta_key ) );

		// If we don't have an object ID what do we do - invalidate ALL meta?
		foreach ( $object_ids as $object_id ) {
			wp_cache_delete( $object_id, $type . '_meta' );
		}
	}

	/**
	 * Retrieve value of a constant based on the constant name.
	 *
	 * We explicitly return null instead of false if the constant doesn't exist.
	 *
	 * @access public
	 *
	 * @param string $constant Name of constant to retrieve.
	 * @return mixed Value set for the constant.
	 */
	public function get_constant( $constant ) {
		$value = get_option( 'jetpack_constant_' . $constant );

		if ( $value ) {
			return $value;
		}

		return null;
	}

	/**
	 * Set the value of a constant.
	 *
	 * @access public
	 *
	 * @param string $constant Name of constant to retrieve.
	 * @param mixed  $value    Value set for the constant.
	 */
	public function set_constant( $constant, $value ) {
		update_option( 'jetpack_constant_' . $constant, $value );
	}

	/**
	 * Retrieve the number of the available updates of a certain type.
	 * Type is one of: `plugins`, `themes`, `wordpress`, `translations`, `total`, `wp_update_version`.
	 *
	 * @access public
	 *
	 * @param string $type Type of updates to retrieve.
	 * @return int|null Number of updates available, `null` if type is invalid or missing.
	 */
	public function get_updates( $type ) {
		$all_updates = get_option( 'jetpack_updates', array() );

		if ( isset( $all_updates[ $type ] ) ) {
			return $all_updates[ $type ];
		} else {
			return null;
		}
	}

	/**
	 * Set the available updates of a certain type.
	 * Type is one of: `plugins`, `themes`, `wordpress`, `translations`, `total`, `wp_update_version`.
	 *
	 * @access public
	 *
	 * @param string $type    Type of updates to set.
	 * @param int    $updates Total number of updates.
	 */
	public function set_updates( $type, $updates ) {
		$all_updates          = get_option( 'jetpack_updates', array() );
		$all_updates[ $type ] = $updates;
		update_option( 'jetpack_updates', $all_updates );
	}

	/**
	 * Retrieve a callable value based on its name.
	 *
	 * @access public
	 *
	 * @param string $name Name of the callable to retrieve.
	 * @return mixed Value of the callable.
	 */
	public function get_callable( $name ) {
		$value = get_option( 'jetpack_' . $name );

		if ( $value ) {
			return $value;
		}

		return null;
	}

	/**
	 * Update the value of a callable.
	 *
	 * @access public
	 *
	 * @param string $name  Callable name.
	 * @param mixed  $value Callable value.
	 */
	public function set_callable( $name, $value ) {
		update_option( 'jetpack_' . $name, $value );
	}

	/**
	 * Retrieve a network option value based on a network option name.
	 *
	 * @access public
	 *
	 * @param string $option Name of network option to retrieve.
	 * @return mixed Value set for the network option.
	 */
	public function get_site_option( $option ) {
		return get_option( 'jetpack_network_' . $option );
	}

	/**
	 * Update the value of a network option.
	 *
	 * @access public
	 *
	 * @param string $option Network option name.
	 * @param mixed  $value  Network option value.
	 * @return bool False if value was not updated and true if value was updated.
	 */
	public function update_site_option( $option, $value ) {
		return update_option( 'jetpack_network_' . $option, $value );
	}

	/**
	 * Remove a network option by name.
	 *
	 * @access public
	 *
	 * @param string $option Name of option to remove.
	 * @return bool True, if option is successfully deleted. False on failure.
	 */
	public function delete_site_option( $option ) {
		return delete_option( 'jetpack_network_' . $option );
	}

	/**
	 * Retrieve the terms from a particular taxonomy.
	 *
	 * @access public
	 *
	 * @param string $taxonomy Taxonomy slug.
	 *
	 * @return array|WP_Error Array of terms or WP_Error object on failure.
	 */
	public function get_terms( $taxonomy ) {
		$t = $this->ensure_taxonomy( $taxonomy );
		if ( ! $t || is_wp_error( $t ) ) {
			return $t;
		}
		return get_terms( $taxonomy );
	}

	/**
	 * Retrieve a particular term.
	 *
	 * @access public
	 *
	 * @param string $taxonomy   Taxonomy slug.
	 * @param int    $term_id    ID of the term.
	 * @param string $term_key   ID Field `term_id` or `term_taxonomy_id`.
	 *
	 * @return \WP_Term|WP_Error Term object on success, \WP_Error object on failure.
	 */
	public function get_term( $taxonomy, $term_id, $term_key = 'term_id' ) {

		// Full Sync will pass false for the $taxonomy so a check for term_taxonomy_id is needed before ensure_taxonomy.
		if ( 'term_taxonomy_id' === $term_key ) {
			return get_term_by( 'term_taxonomy_id', $term_id );
		}

		$t = $this->ensure_taxonomy( $taxonomy );
		if ( ! $t || is_wp_error( $t ) ) {
			return $t;
		}

		return get_term( $term_id, $taxonomy );
	}

	/**
	 * Verify a taxonomy is legitimate and register it if necessary.
	 *
	 * @access private
	 *
	 * @param string $taxonomy Taxonomy slug.
	 *
	 * @return bool|void|WP_Error True if already exists; void if it was registered; \WP_Error on error.
	 */
	private function ensure_taxonomy( $taxonomy ) {
		if ( ! taxonomy_exists( $taxonomy ) ) {
			// Try re-registering synced taxonomies.
			$taxonomies = $this->get_callable( 'taxonomies' );
			if ( ! isset( $taxonomies[ $taxonomy ] ) ) {
				// Doesn't exist, or somehow hasn't been synced.
				return new WP_Error( 'invalid_taxonomy', "The taxonomy '$taxonomy' doesn't exist" );
			}
			$t = $taxonomies[ $taxonomy ];

			return register_taxonomy(
				$taxonomy,
				$t->object_type,
				(array) $t
			);
		}

		return true;
	}

	/**
	 * Retrieve all terms from a taxonomy that are related to an object with a particular ID.
	 *
	 * @access public
	 *
	 * @param int    $object_id Object ID.
	 * @param string $taxonomy  Taxonomy slug.
	 *
	 * @return array|bool|WP_Error Array of terms on success, `false` if no terms or post doesn't exist, \WP_Error on failure.
	 */
	public function get_the_terms( $object_id, $taxonomy ) {
		return get_the_terms( $object_id, $taxonomy );
	}

	/**
	 * Insert or update a term.
	 *
	 * @access public
	 *
	 * @param \WP_Term $term_object Term object.
	 *
	 * @return array|bool|WP_Error Array of term_id and term_taxonomy_id if updated, true if inserted, \WP_Error on failure.
	 */
	public function update_term( $term_object ) {
		$taxonomy = $term_object->taxonomy;
		global $wpdb;
		$exists = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT EXISTS( SELECT 1 FROM $wpdb->terms WHERE term_id = %d )",
				$term_object->term_id
			)
		);
		if ( ! $exists ) {
			$term_object   = sanitize_term( clone $term_object, $taxonomy, 'db' );
			$term          = array(
				'term_id'    => $term_object->term_id,
				'name'       => $term_object->name,
				'slug'       => $term_object->slug,
				'term_group' => $term_object->term_group,
			);
			$term_taxonomy = array(
				'term_taxonomy_id' => $term_object->term_taxonomy_id,
				'term_id'          => $term_object->term_id,
				'taxonomy'         => $term_object->taxonomy,
				'description'      => $term_object->description,
				'parent'           => (int) $term_object->parent,
				'count'            => (int) $term_object->count,
			);
			$wpdb->insert( $wpdb->terms, $term );
			$wpdb->insert( $wpdb->term_taxonomy, $term_taxonomy );

			return true;
		}

		return wp_update_term( $term_object->term_id, $taxonomy, (array) $term_object );
	}

	/**
	 * Delete a term by the term ID and its corresponding taxonomy.
	 *
	 * @access public
	 *
	 * @param int    $term_id  Term ID.
	 * @param string $taxonomy Taxonomy slug.
	 *
	 * @return bool|int|WP_Error True on success, false if term doesn't exist. Zero if trying with default category. \WP_Error on invalid taxonomy.
	 */
	public function delete_term( $term_id, $taxonomy ) {
		$this->ensure_taxonomy( $taxonomy );
		return wp_delete_term( $term_id, $taxonomy );
	}

	/**
	 * Add/update terms of a particular taxonomy of an object with the specified ID.
	 *
	 * @access public
	 *
	 * @param int              $object_id The object to relate to.
	 * @param string           $taxonomy  The context in which to relate the term to the object.
	 * @param string|int|array $terms     A single term slug, single term id, or array of either term slugs or ids.
	 * @param bool             $append    Optional. If false will delete difference of terms. Default false.
	 */
	public function update_object_terms( $object_id, $taxonomy, $terms, $append ) {
		$this->ensure_taxonomy( $taxonomy );
		wp_set_object_terms( $object_id, $terms, $taxonomy, $append );
	}

	/**
	 * Remove certain term relationships from the specified object.
	 *
	 * @access public
	 *
	 * @todo Refactor to not use interpolated values when preparing the SQL query.
	 *
	 * @param int   $object_id ID of the object.
	 * @param array $tt_ids    Term taxonomy IDs.
	 * @return bool True on success, false on failure.
	 */
	public function delete_object_terms( $object_id, $tt_ids ) {
		global $wpdb;

		if ( is_array( $tt_ids ) && ! empty( $tt_ids ) ) {
			// Escape.
			$tt_ids_sanitized = array_map( 'intval', $tt_ids );

			$taxonomies = array();
			foreach ( $tt_ids_sanitized as $tt_id ) {
				$term                            = get_term_by( 'term_taxonomy_id', $tt_id );
				$taxonomies[ $term->taxonomy ][] = $tt_id;
			}
			$in_tt_ids = implode( ', ', $tt_ids_sanitized );

			/**
			 * Fires immediately before an object-term relationship is deleted.
			 *
			 * @since 1.6.3
			 * @since-jetpack 2.9.0
			 *
			 * @param int   $object_id Object ID.
			 * @param array $tt_ids    An array of term taxonomy IDs.
			 */
			do_action( 'delete_term_relationships', $object_id, $tt_ids_sanitized );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$deleted = $wpdb->query( $wpdb->prepare( "DELETE FROM $wpdb->term_relationships WHERE object_id = %d AND term_taxonomy_id IN ($in_tt_ids)", $object_id ) );
			foreach ( $taxonomies as $taxonomy => $taxonomy_tt_ids ) {
				$this->ensure_taxonomy( $taxonomy );
				wp_cache_delete( $object_id, $taxonomy . '_relationships' );
				/**
				 * Fires immediately after an object-term relationship is deleted.
				 *
				 * @since 1.6.3
				 * @since-jetpack 2.9.0
				 *
				 * @param int   $object_id Object ID.
				 * @param array $tt_ids    An array of term taxonomy IDs.
				 */
				do_action( 'deleted_term_relationships', $object_id, $taxonomy_tt_ids );
				wp_update_term_count( $taxonomy_tt_ids, $taxonomy );
			}

			return (bool) $deleted;
		}

		return false;
	}

	/**
	 * Retrieve the number of users.
	 * Not supported in this replicastore.
	 *
	 * @access public
	 */
	public function user_count() {
		// Noop.
	}

	/**
	 * Retrieve a user object by the user ID.
	 *
	 * @access public
	 *
	 * @param int $user_id User ID.
	 * @return \WP_User User object.
	 */
	public function get_user( $user_id ) {
		return \WP_User::get_instance( $user_id );
	}

	/**
	 * Insert or update a user.
	 * Not supported in this replicastore.
	 *
	 * @access public
	 * @throws Exception If this method is invoked.
	 *
	 * @param \WP_User $user User object.
	 */
	public function upsert_user( $user ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$this->invalid_call();
	}

	/**
	 * Delete a user.
	 * Not supported in this replicastore.
	 *
	 * @access public
	 * @throws Exception If this method is invoked.
	 *
	 * @param int $user_id User ID.
	 */
	public function delete_user( $user_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$this->invalid_call();
	}

	/**
	 * Update/insert user locale.
	 * Not supported in this replicastore.
	 *
	 * @access public
	 * @throws Exception If this method is invoked.
	 *
	 * @param int    $user_id User ID.
	 * @param string $local   The user locale.
	 */
	public function upsert_user_locale( $user_id, $local ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$this->invalid_call();
	}

	/**
	 * Delete user locale.
	 * Not supported in this replicastore.
	 *
	 * @access public
	 * @throws Exception If this method is invoked.
	 *
	 * @param int $user_id User ID.
	 */
	public function delete_user_locale( $user_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$this->invalid_call();
	}

	/**
	 * Retrieve the user locale.
	 *
	 * @access public
	 *
	 * @param int $user_id User ID.
	 * @return string The user locale.
	 */
	public function get_user_locale( $user_id ) {
		return get_user_locale( $user_id );
	}

	/**
	 * Retrieve the allowed mime types for the user.
	 * Not supported in this replicastore.
	 *
	 * @access public
	 *
	 * @param int $user_id User ID.
	 */
	public function get_allowed_mime_types( $user_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		// Noop.
	}

	/**
	 * Retrieve all the checksums we are interested in.
	 * Currently that is posts, comments, post meta and comment meta.
	 *
	 * @access public
	 *
	 * @param boolean $perform_text_conversion If text fields should be latin1 converted.
	 *
	 * @return array Checksums.
	 */
	public function checksum_all( $perform_text_conversion = false ) {
		$post_checksum               = $this->checksum_histogram( 'posts', null, null, null, null, true, '', false, false, $perform_text_conversion );
		$comments_checksum           = $this->checksum_histogram( 'comments', null, null, null, null, true, '', false, false, $perform_text_conversion );
		$post_meta_checksum          = $this->checksum_histogram( 'postmeta', null, null, null, null, true, '', false, false, $perform_text_conversion );
		$comment_meta_checksum       = $this->checksum_histogram( 'commentmeta', null, null, null, null, true, '', false, false, $perform_text_conversion );
		$terms_checksum              = $this->checksum_histogram( 'terms', null, null, null, null, true, '', false, false, $perform_text_conversion );
		$term_relationships_checksum = $this->checksum_histogram( 'term_relationships', null, null, null, null, true, '', false, false, $perform_text_conversion );
		$term_taxonomy_checksum      = $this->checksum_histogram( 'term_taxonomy', null, null, null, null, true, '', false, false, $perform_text_conversion );

		$result = array(
			'posts'              => $this->summarize_checksum_histogram( $post_checksum ),
			'comments'           => $this->summarize_checksum_histogram( $comments_checksum ),
			'post_meta'          => $this->summarize_checksum_histogram( $post_meta_checksum ),
			'comment_meta'       => $this->summarize_checksum_histogram( $comment_meta_checksum ),
			'terms'              => $this->summarize_checksum_histogram( $terms_checksum ),
			'term_relationships' => $this->summarize_checksum_histogram( $term_relationships_checksum ),
			'term_taxonomy'      => $this->summarize_checksum_histogram( $term_taxonomy_checksum ),
		);

		/**
		 * WooCommerce tables
		 */

		/**
		 * On WordPress.com, we can't directly check if the site has support for WooCommerce.
		 * Having the option to override the functionality here helps with syncing WooCommerce tables.
		 *
		 * @since 10.1
		 *
		 * @param bool If we should we force-enable WooCommerce tables support.
		 */
		$force_woocommerce_support = apply_filters( 'jetpack_table_checksum_force_enable_woocommerce', false );

		if ( $force_woocommerce_support || class_exists( 'WooCommerce' ) ) {
			/**
			 * Guard in Try/Catch as it's possible for the WooCommerce class to exist, but
			 * the tables to not. If we don't do this, the response will be just the exception, without
			 * returning any valid data. This will prevent us from ever performing a checksum/fix
			 * for sites like this.
			 * It's better to just skip the tables in the response, instead of completely failing.
			 */

			try {
				$woocommerce_order_items_checksum  = $this->checksum_histogram( 'woocommerce_order_items' );
				$result['woocommerce_order_items'] = $this->summarize_checksum_histogram( $woocommerce_order_items_checksum );
			} catch ( Exception $ex ) {
				$result['woocommerce_order_items'] = null;
			}

			try {
				$woocommerce_order_itemmeta_checksum  = $this->checksum_histogram( 'woocommerce_order_itemmeta' );
				$result['woocommerce_order_itemmeta'] = $this->summarize_checksum_histogram( $woocommerce_order_itemmeta_checksum );
			} catch ( Exception $ex ) {
				$result['woocommerce_order_itemmeta'] = null;
			}
		}

		return $result;
	}

	/**
	 * Return the summarized checksum from buckets or the WP_Error.
	 *
	 * @param array $histogram checksum_histogram result.
	 *
	 * @return int|WP_Error checksum or Error.
	 */
	protected function summarize_checksum_histogram( $histogram ) {
		if ( is_wp_error( $histogram ) ) {
			return $histogram;
		} else {
			return array_sum( $histogram );
		}
	}

	/**
	 * Grabs the minimum and maximum object ids for the given parameters.
	 *
	 * @access public
	 *
	 * @param string $id_field     The id column in the table to query.
	 * @param string $object_table The table to query.
	 * @param string $where        A sql where clause without 'WHERE'.
	 * @param int    $bucket_size  The maximum amount of objects to include in the query.
	 *                             For `term_relationships` table, the bucket size will refer to the amount
	 *                             of distinct object ids. This will likely include more database rows than
	 *                             the bucket size implies.
	 *
	 * @return object An object with min_id and max_id properties.
	 */
	public function get_min_max_object_id( $id_field, $object_table, $where, $bucket_size ) {
		global $wpdb;

		// The term relationship table's unique key is a combination of 2 columns. `DISTINCT` helps us get a more acurate query.
		$distinct_sql = ( $wpdb->term_relationships === $object_table ) ? 'DISTINCT' : '';
		$where_sql    = $where ? "WHERE $where" : '';

		// Since MIN() and MAX() do not work with LIMIT, we'll need to adjust the dataset we query if a limit is present.
		// With a limit present, we'll look at a dataset consisting of object_ids that meet the constructs of the $where clause.
		// Without a limit, we can use the actual table as a dataset.
		$from = $bucket_size ?
			"( SELECT $distinct_sql $id_field FROM $object_table $where_sql ORDER BY $id_field ASC LIMIT $bucket_size ) as ids" :
			"$object_table $where_sql ORDER BY $id_field ASC";

		return $wpdb->get_row(
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT MIN($id_field) as min, MAX($id_field) as max FROM $from"
		);
	}

	/**
	 * Retrieve the checksum histogram for a specific object type.
	 *
	 * @access public
	 *
	 * @param string $table                   Object type.
	 * @param null   $buckets                 Number of buckets to split the objects to.
	 * @param null   $start_id                Minimum object ID.
	 * @param null   $end_id                  Maximum object ID.
	 * @param null   $columns                 Table columns to calculate the checksum from.
	 * @param bool   $strip_non_ascii         Whether to strip non-ASCII characters.
	 * @param string $salt                    Salt, used for $wpdb->prepare()'s args.
	 * @param bool   $only_range_edges        Only return the range edges and not the actual checksums.
	 * @param bool   $detailed_drilldown      If the call should return a detailed drilldown for the checksum or only the checksum.
	 * @param bool   $perform_text_conversion If text fields should be converted to latin1 during the checksum calculation.
	 *
	 * @return array|WP_Error The checksum histogram.
	 * @throws Exception Throws an exception if data validation fails inside `Table_Checksum` calls.
	 */
	public function checksum_histogram( $table, $buckets = null, $start_id = null, $end_id = null, $columns = null, $strip_non_ascii = true, $salt = '', $only_range_edges = false, $detailed_drilldown = false, $perform_text_conversion = false ) {
		global $wpdb;

		$wpdb->queries = array();
		try {
			$checksum_table = $this->get_table_checksum_instance( $table, $salt, $perform_text_conversion );
		} catch ( Exception $ex ) {
			return new WP_Error( 'checksum_disabled', $ex->getMessage() );
		}

		// Validate / Determine Buckets.
		if ( $buckets === null || $buckets < 1 ) {
			$buckets = $this->calculate_buckets( $table, $start_id, $end_id );
		}
		if ( is_wp_error( $buckets ) ) {
			return $buckets;
		}

		$range_edges = $checksum_table->get_range_edges( $start_id, $end_id );

		if ( $only_range_edges ) {
			return $range_edges;
		}

		$object_count = (int) $range_edges['item_count'];

		if ( 0 === $object_count ) {
			return array();
		}

		$bucket_size     = (int) ceil( $object_count / $buckets );
		$previous_max_id = max( 0, $range_edges['min_range'] );
		$histogram       = array();

		do {
			$ids_range = $checksum_table->get_range_edges( $previous_max_id, null, $bucket_size );

			if ( empty( $ids_range['min_range'] ) || empty( $ids_range['max_range'] ) ) {
				// Nothing to checksum here...
				break;
			}

			// Get the checksum value.
			$batch_checksum = $checksum_table->calculate_checksum( $ids_range['min_range'], $ids_range['max_range'], null, $detailed_drilldown );

			if ( is_wp_error( $batch_checksum ) ) {
				return $batch_checksum;
			}

			if ( $ids_range['min_range'] === $ids_range['max_range'] ) {
				$histogram[ $ids_range['min_range'] ] = $batch_checksum;
			} else {
				$histogram[ "{$ids_range[ 'min_range' ]}-{$ids_range[ 'max_range' ]}" ] = $batch_checksum;
			}

			$previous_max_id = $ids_range['max_range'] + 1;
			// If we've reached the max_range lets bail out.
			if ( $previous_max_id > $range_edges['max_range'] ) {
				break;
			}
		} while ( true );

		return $histogram;
	}

	/**
	 * Retrieve the type of the checksum.
	 *
	 * @access public
	 *
	 * @return string Type of the checksum.
	 */
	public function get_checksum_type() {
		return 'sum';
	}

	/**
	 * Used in methods that are not implemented and shouldn't be invoked.
	 *
	 * @access private
	 * @throws Exception If this method is invoked.
	 */
	private function invalid_call() {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
		$backtrace = debug_backtrace();
		$caller    = $backtrace[1]['function'];
		throw new Exception( "This function $caller is not supported on the WP Replicastore" );
	}

	/**
	 * Determine number of buckets to use in full table checksum.
	 *
	 * @param string $table Object Type.
	 * @param int    $start_id Min Object ID.
	 * @param int    $end_id Max Object ID.
	 * @return int|WP_Error Number of Buckets to use.
	 */
	private function calculate_buckets( $table, $start_id = null, $end_id = null ) {
		// Get # of objects.
		try {
			$checksum_table = $this->get_table_checksum_instance( $table );
		} catch ( Exception $ex ) {
			return new WP_Error( 'checksum_disabled', $ex->getMessage() );
		}
		$range_edges  = $checksum_table->get_range_edges( $start_id, $end_id );
		$object_count = $range_edges['item_count'];

		// Ensure no division by 0.
		if ( 0 === (int) $object_count ) {
			return 1;
		}

		// Default Bucket sizes.
		$bucket_size = 10000; // Default bucket size is 10,000 items.
		switch ( $table ) {
			case 'postmeta':
			case 'commentmeta':
			case 'order_itemmeta':
				$bucket_size = 1000; // Meta bucket size is restricted to 1000 items.
		}

		return (int) ceil( $object_count / $bucket_size );
	}

	/**
	 * Return an instance for `Table_Checksum`, depending on the table.
	 *
	 * Some tables require custom instances, due to different checksum logic.
	 *
	 * @param string $table The table that we want to get the instance for.
	 * @param null   $salt  Salt to be used when generating the checksums.
	 * @param false  $perform_text_conversion Should we perform text encoding conversion when calculating the checksum.
	 *
	 * @return Table_Checksum|Table_Checksum_Usermeta
	 * @throws Exception Might throw an exception if any of the input parameters were invalid.
	 */
	public function get_table_checksum_instance( $table, $salt = null, $perform_text_conversion = false ) {
		if ( 'users' === $table ) {
			return new Table_Checksum_Users( $table, $salt, $perform_text_conversion );
		}
		if ( 'usermeta' === $table ) {
			return new Table_Checksum_Usermeta( $table, $salt, $perform_text_conversion );
		}

		return new Table_Checksum( $table, $salt, $perform_text_conversion );
	}
}
