<?php
/**
 * Sync architecture prototype.
 *
 * To run tests: phpunit --testsuite sync --filter New_Sync
 *
 * @author Dan Walmsley
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

/**
 * A high-level interface for objects that store synced WordPress data.
 * Useful for ensuring that different storage mechanisms implement the
 * required semantics for storing all the data that we sync.
 */
interface Replicastore_Interface {
	/**
	 * Empty and reset the replicastore.
	 *
	 * @access public
	 */
	public function reset();

	/**
	 * Ran when full sync has just started.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 */
	public function full_sync_start( $config );

	/**
	 * Ran when full sync has just finished.
	 *
	 * @access public
	 *
	 * @param string $checksum Deprecated since 7.3.0.
	 */
	public function full_sync_end( $checksum );

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
	 */
	public function post_count( $status = null, $min_id = null, $max_id = null );

	/**
	 * Retrieve the posts with a particular post status.
	 *
	 * @access public
	 *
	 * @param string $status Post status.
	 * @param int    $min_id Minimum post ID.
	 * @param int    $max_id Maximum post ID.
	 */
	public function get_posts( $status = null, $min_id = null, $max_id = null );

	/**
	 * Retrieve a post object by the post ID.
	 *
	 * @access public
	 *
	 * @param int $id Post ID.
	 */
	public function get_post( $id );

	/**
	 * Update or insert a post.
	 *
	 * @access public
	 *
	 * @param \WP_Post $post   Post object.
	 * @param bool     $silent Whether to perform a silent action.
	 */
	public function upsert_post( $post, $silent = false );

	/**
	 * Delete a post by the post ID.
	 *
	 * @access public
	 *
	 * @param int $post_id Post ID.
	 */
	public function delete_post( $post_id );

	/**
	 * Retrieve the checksum for posts within a range.
	 *
	 * @access public
	 *
	 * @param int $min_id Minimum post ID.
	 * @param int $max_id Maximum post ID.
	 */
	public function posts_checksum( $min_id = null, $max_id = null );

	/**
	 * Retrieve the checksum for post meta within a range.
	 *
	 * @access public
	 *
	 * @param int $min_id Minimum post meta ID.
	 * @param int $max_id Maximum post meta ID.
	 */
	public function post_meta_checksum( $min_id = null, $max_id = null );

	/**
	 * Retrieve the number of comments with a particular comment status within a certain range.
	 *
	 * @access public
	 *
	 * @param string $status Comment status.
	 * @param int    $min_id Minimum comment ID.
	 * @param int    $max_id Maximum comment ID.
	 */
	public function comment_count( $status = null, $min_id = null, $max_id = null );

	/**
	 * Retrieve the comments with a particular comment status.
	 *
	 * @access public
	 *
	 * @param string $status Comment status.
	 * @param int    $min_id Minimum comment ID.
	 * @param int    $max_id Maximum comment ID.
	 */
	public function get_comments( $status = null, $min_id = null, $max_id = null );

	/**
	 * Retrieve a comment object by the comment ID.
	 *
	 * @access public
	 *
	 * @param int $id Comment ID.
	 */
	public function get_comment( $id );

	/**
	 * Update or insert a comment.
	 *
	 * @access public
	 *
	 * @param \WP_Comment $comment Comment object.
	 */
	public function upsert_comment( $comment );

	/**
	 * Trash a comment by the comment ID.
	 *
	 * @access public
	 *
	 * @param int $comment_id Comment ID.
	 */
	public function trash_comment( $comment_id );

	/**
	 * Mark a comment by the comment ID as spam.
	 *
	 * @access public
	 *
	 * @param int $comment_id Comment ID.
	 */
	public function spam_comment( $comment_id );

	/**
	 * Delete a comment by the comment ID.
	 *
	 * @access public
	 *
	 * @param int $comment_id Comment ID.
	 */
	public function delete_comment( $comment_id );

	/**
	 * Trash the comments of a post.
	 *
	 * @access public
	 *
	 * @param int   $post_id  Post ID.
	 * @param array $statuses Post statuses.
	 */
	public function trashed_post_comments( $post_id, $statuses );

	/**
	 * Untrash the comments of a post.
	 *
	 * @access public
	 *
	 * @param int $post_id Post ID.
	 */
	public function untrashed_post_comments( $post_id );

	/**
	 * Retrieve the checksum for comments within a range.
	 *
	 * @access public
	 *
	 * @param int $min_id Minimum comment ID.
	 * @param int $max_id Maximum comment ID.
	 */
	public function comments_checksum( $min_id = null, $max_id = null );

	/**
	 * Retrieve the checksum for comment meta within a range.
	 *
	 * @access public
	 *
	 * @param int $min_id Minimum comment meta ID.
	 * @param int $max_id Maximum comment meta ID.
	 */
	public function comment_meta_checksum( $min_id = null, $max_id = null );

	/**
	 * Update the value of an option.
	 *
	 * @access public
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Option value.
	 */
	public function update_option( $option, $value );

	/**
	 * Retrieve an option value based on an option name.
	 *
	 * @access public
	 *
	 * @param string $option  Name of option to retrieve.
	 * @param mixed  $default Optional. Default value to return if the option does not exist.
	 */
	public function get_option( $option, $default = false );

	/**
	 * Remove an option by name.
	 *
	 * @access public
	 *
	 * @param string $option Name of option to remove.
	 */
	public function delete_option( $option );

	/**
	 * Change the info of the current theme.
	 *
	 * @access public
	 *
	 * @param array $theme_info Theme info array.
	 */
	public function set_theme_info( $theme_info );

	/**
	 * Whether the current theme supports a certain feature.
	 *
	 * @access public
	 *
	 * @param string $feature Name of the feature.
	 */
	public function current_theme_supports( $feature );

	/**
	 * Retrieve metadata for the specified object.
	 *
	 * @access public
	 *
	 * @param string $type      Meta type.
	 * @param int    $object_id ID of the object.
	 * @param string $meta_key  Meta key.
	 * @param bool   $single    If true, return only the first value of the specified meta_key.
	 */
	public function get_metadata( $type, $object_id, $meta_key = '', $single = false );

	/**
	 * Stores remote meta key/values alongside an ID mapping key.
	 *
	 * @access public
	 *
	 * @param string $type       Meta type.
	 * @param int    $object_id  ID of the object.
	 * @param string $meta_key   Meta key.
	 * @param mixed  $meta_value Meta value.
	 * @param int    $meta_id    ID of the meta.
	 */
	public function upsert_metadata( $type, $object_id, $meta_key, $meta_value, $meta_id );

	/**
	 * Delete metadata for the specified object.
	 *
	 * @access public
	 *
	 * @param string $type      Meta type.
	 * @param int    $object_id ID of the object.
	 * @param array  $meta_ids  IDs of the meta objects to delete.
	 */
	public function delete_metadata( $type, $object_id, $meta_ids );

	/**
	 * Delete metadata with a certain key for the specified objects.
	 *
	 * @access public
	 *
	 * @param string $type       Meta type.
	 * @param array  $object_ids IDs of the objects.
	 * @param string $meta_key   Meta key.
	 */
	public function delete_batch_metadata( $type, $object_ids, $meta_key );

	/**
	 * Retrieve value of a constant based on the constant name.
	 *
	 * @access public
	 *
	 * @param string $constant Name of constant to retrieve.
	 */
	public function get_constant( $constant );

	/**
	 * Set the value of a constant.
	 *
	 * @access public
	 *
	 * @param string $constant Name of constant to retrieve.
	 * @param mixed  $value    Value set for the constant.
	 */
	public function set_constant( $constant, $value );

	/**
	 * Retrieve the number of the available updates of a certain type.
	 * Type is one of: `plugins`, `themes`, `wordpress`, `translations`, `total`, `wp_update_version`.
	 *
	 * @access public
	 *
	 * @param string $type Type of updates to retrieve.
	 */
	public function get_updates( $type );

	/**
	 * Set the available updates of a certain type.
	 * Type is one of: `plugins`, `themes`, `wordpress`, `translations`, `total`, `wp_update_version`.
	 *
	 * @access public
	 *
	 * @param string $type    Type of updates to set.
	 * @param int    $updates Total number of updates.
	 */
	public function set_updates( $type, $updates );

	/**
	 * Retrieve a callable value based on its name.
	 *
	 * @access public
	 *
	 * @param string $callable Name of the callable to retrieve.
	 */
	public function get_callable( $callable );

	/**
	 * Update the value of a callable.
	 *
	 * @access public
	 *
	 * @param string $callable Callable name.
	 * @param mixed  $value    Callable value.
	 */
	public function set_callable( $callable, $value );

	/**
	 * Retrieve a network option value based on a network option name.
	 *
	 * @access public
	 *
	 * @param string $option Name of network option to retrieve.
	 */
	public function get_site_option( $option );

	/**
	 * Update the value of a network option.
	 *
	 * @access public
	 *
	 * @param string $option Network option name.
	 * @param mixed  $value  Network option value.
	 */
	public function update_site_option( $option, $value );

	/**
	 * Remove a network option by name.
	 *
	 * @access public
	 *
	 * @param string $option Name of option to remove.
	 */
	public function delete_site_option( $option );

	/**
	 * Retrieve the terms from a particular taxonomy.
	 *
	 * @access public
	 *
	 * @param string $taxonomy Taxonomy slug.
	 */
	public function get_terms( $taxonomy );

	/**
	 * Retrieve a particular term.
	 *
	 * @access public
	 *
	 * @param string $taxonomy   Taxonomy slug.
	 * @param int    $term_id    ID of the term.
	 * @param string $term_key   ID Field `term_id` or `term_taxonomy_id`.
	 */
	public function get_term( $taxonomy, $term_id, $term_key = 'term_id' );

	/**
	 * Insert or update a term.
	 *
	 * @access public
	 *
	 * @param \WP_Term $term_object Term object.
	 */
	public function update_term( $term_object );

	/**
	 * Delete a term by the term ID and its corresponding taxonomy.
	 *
	 * @access public
	 *
	 * @param int    $term_id  Term ID.
	 * @param string $taxonomy Taxonomy slug.
	 */
	public function delete_term( $term_id, $taxonomy );

	/**
	 * Retrieve all terms from a taxonomy that are related to an object with a particular ID.
	 *
	 * @access public
	 *
	 * @param int    $object_id Object ID.
	 * @param string $taxonomy  Taxonomy slug.
	 */
	public function get_the_terms( $object_id, $taxonomy );

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
	public function update_object_terms( $object_id, $taxonomy, $terms, $append );

	/**
	 * Remove certain term relationships from the specified object.
	 *
	 * @access public
	 *
	 * @todo Refactor to not use interpolated values when preparing the SQL query.
	 *
	 * @param int   $object_id ID of the object.
	 * @param array $tt_ids    Term taxonomy IDs.
	 */
	public function delete_object_terms( $object_id, $tt_ids );

	/**
	 * Retrieve the number of users.
	 *
	 * @access public
	 */
	public function user_count();

	/**
	 * Retrieve a user object by the user ID.
	 *
	 * @access public
	 *
	 * @param int $user_id User ID.
	 */
	public function get_user( $user_id );

	/**
	 * Insert or update a user.
	 *
	 * @access public
	 *
	 * @param \WP_User $user User object.
	 */
	public function upsert_user( $user );

	/**
	 * Delete a user.
	 *
	 * @access public
	 *
	 * @param int $user_id User ID.
	 */
	public function delete_user( $user_id );

	/**
	 * Update/insert user locale.
	 *
	 * @access public
	 *
	 * @param int    $user_id User ID.
	 * @param string $locale  The user locale.
	 */
	public function upsert_user_locale( $user_id, $locale );

	/**
	 * Delete user locale.
	 *
	 * @access public
	 *
	 * @param int $user_id User ID.
	 */
	public function delete_user_locale( $user_id );

	/**
	 * Retrieve the user locale.
	 *
	 * @access public
	 *
	 * @param int $user_id User ID.
	 */
	public function get_user_locale( $user_id );

	/**
	 * Retrieve the allowed mime types for the user.
	 *
	 * @access public
	 *
	 * @param int $user_id User ID.
	 */
	public function get_allowed_mime_types( $user_id );

	/**
	 * Retrieve all the checksums we are interested in.
	 * Currently that is posts, comments, post meta and comment meta.
	 *
	 * @access public
	 */
	public function checksum_all();

	/**
	 * Retrieve the checksum histogram for a specific object type.
	 *
	 * @access public
	 *
	 * @param string $object_type Object type.
	 * @param int    $buckets     Number of buckets to split the objects to.
	 * @param int    $start_id    Minimum object ID.
	 * @param int    $end_id      Maximum object ID.
	 */
	public function checksum_histogram( $object_type, $buckets, $start_id = null, $end_id = null );
}
