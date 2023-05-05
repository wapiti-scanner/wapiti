<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module Name: Copy Post
 * Module Description: Enable the option to copy entire posts and pages, including tags and settings
 * Sort Order: 15
 * First Introduced: 7.0
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Writing
 * Feature: Writing
 * Additional Search Queries: copy, duplicate
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Copy Post class.
 */
class Jetpack_Copy_Post {
	/**
	 * Jetpack_Copy_Post_By_Param constructor.
	 * Add row actions to post/page/CPT listing screens.
	 * Process any `?copy` param if on a create new post/page/CPT screen.
	 *
	 * @return void
	 */
	public function __construct() {
		if ( 'edit.php' === $GLOBALS['pagenow'] ) {
			add_filter( 'post_row_actions', array( $this, 'add_row_action' ), 10, 2 );
			add_filter( 'page_row_actions', array( $this, 'add_row_action' ), 10, 2 );
			return;
		}

		if ( ! empty( $_GET['jetpack-copy'] ) && 'post-new.php' === $GLOBALS['pagenow'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- update_post_data() handles access check.
			add_action( 'wp_insert_post', array( $this, 'update_post_data' ), 10, 3 );
			add_filter( 'pre_option_default_post_format', '__return_empty_string' );
		}
	}

	/**
	 * Update the new (target) post data with the source post data.
	 *
	 * @param int     $target_post_id Target post ID.
	 * @param WP_Post $post           Target post object (not used).
	 * @param bool    $update         Whether this is an existing post being updated or not.
	 * @return void
	 */
	public function update_post_data( $target_post_id, $post, $update ) {
		// This `$update` check avoids infinite loops of trying to update our updated post.
		if ( $update ) {
			return;
		}

		// Shouldn't happen, since this filter is only added when the value isn't empty, but check anyway.
		if ( empty( $_GET['jetpack-copy'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$source_post = get_post( intval( $_GET['jetpack-copy'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! $source_post instanceof WP_Post ||
			! $this->user_can_access_post( $source_post->ID ) ||
			! $this->validate_post_type( $source_post ) ) {
			return;
		}

		$update_results = array(
			'update_content'         => $this->update_content( $source_post, $target_post_id ),
			'update_featured_image'  => $this->update_featured_image( $source_post, $target_post_id ),
			'update_post_format'     => $this->update_post_format( $source_post, $target_post_id ),
			'update_likes_sharing'   => $this->update_likes_sharing( $source_post, $target_post_id ),
			'update_post_type_terms' => $this->update_post_type_terms( $source_post, $target_post_id ),
		);

		// Required to satisfy get_default_post_to_edit(), which has these filters after post creation.
		add_filter( 'default_title', array( $this, 'filter_title' ), 10, 2 );
		add_filter( 'default_content', array( $this, 'filter_content' ), 10, 2 );
		add_filter( 'default_excerpt', array( $this, 'filter_excerpt' ), 10, 2 );

		// Required to avoid the block editor from adding default blocks according to post format.
		add_filter( 'block_editor_settings_all', array( $this, 'remove_post_format_template' ) );

		/**
		 * Fires after all updates have been performed, and default content filters have been added.
		 * Allows for any cleanup or post operations, and default content filters can be removed or modified.
		 *
		 * @module copy-post
		 *
		 * @since 7.0.0
		 *
		 * @param WP_Post $source_post Post object that was copied.
		 * @param int     $target_post_id Target post ID.
		 * @param array   $update_results Results of all update operations, allowing action to be taken.
		 */
		do_action( 'jetpack_copy_post', $source_post, $target_post_id, $update_results );
	}

	/**
	 * Determine if the current user has edit access to the source post.
	 *
	 * @param int $post_id Source post ID (the post being copied).
	 * @return bool True if user has the meta cap of `edit_post` for the given post ID, false otherwise.
	 */
	protected function user_can_access_post( $post_id ) {
		return current_user_can( 'edit_post', $post_id );
	}

	/**
	 * Update the target post's title, content, excerpt, categories, and tags.
	 *
	 * @param WP_Post $source_post Post object to be copied.
	 * @param int     $target_post_id Target post ID.
	 * @return int    0 on failure, or the updated post ID on success.
	 */
	protected function update_content( $source_post, $target_post_id ) {
		$data = array(
			'ID'             => $target_post_id,
			'post_title'     => $source_post->post_title,
			'post_content'   => $source_post->post_content,
			'post_excerpt'   => $source_post->post_excerpt,
			'comment_status' => $source_post->comment_status,
			'ping_status'    => $source_post->ping_status,
			'post_category'  => wp_get_post_categories( $source_post->ID ),
			'post_password'  => $source_post->post_password,
			'tags_input'     => $source_post->tags_input,
		);

		/**
		 * Fires just before the target post is updated with its new data.
		 * Allows for final data adjustments before updating the target post.
		 *
		 * @module copy-post
		 *
		 * @since 7.0.0
		 *
		 * @param array $data Post data with which to update the target (new) post.
		 * @param WP_Post $source_post Post object being copied.
		 * @param int     $target_post_id Target post ID.
		 */
		$data = apply_filters( 'jetpack_copy_post_data', $data, $source_post, $target_post_id );
		return wp_update_post( $data );
	}

	/**
	 * Update terms for post types.
	 *
	 * @param WP_Post $source_post Post object to be copied.
	 * @param int     $target_post_id Target post ID.
	 * @return array Results of attempts to set each term to the target (new) post.
	 */
	protected function update_post_type_terms( $source_post, $target_post_id ) {
		$results = array();

		$bypassed_post_types = apply_filters( 'jetpack_copy_post_bypassed_post_types', array( 'post', 'page' ), $source_post, $target_post_id );
		if ( in_array( $source_post->post_type, $bypassed_post_types, true ) ) {
			return $results;
		}

		$taxonomies = get_object_taxonomies( $source_post, 'objects' );
		foreach ( $taxonomies as $taxonomy ) {
			$terms     = wp_get_post_terms( $source_post->ID, $taxonomy->name, array( 'fields' => 'ids' ) );
			$results[] = wp_set_post_terms( $target_post_id, $terms, $taxonomy->name );
		}

		return $results;
	}

	/**
	 * Update the target post's featured image.
	 *
	 * @param WP_Post $source_post Post object to be copied.
	 * @param int     $target_post_id Target post ID.
	 * @return int|bool Meta ID if the key didn't exist, true on successful update, false on failure.
	 */
	protected function update_featured_image( $source_post, $target_post_id ) {
		$featured_image_id = get_post_thumbnail_id( $source_post );
		return update_post_meta( $target_post_id, '_thumbnail_id', $featured_image_id );
	}

	/**
	 * Update the target post's post format.
	 *
	 * @param WP_Post $source_post Post object to be copied.
	 * @param int     $target_post_id Target post ID.
	 * @return array|WP_Error|false WP_Error on error, array of affected term IDs on success.
	 */
	protected function update_post_format( $source_post, $target_post_id ) {
		$post_format = get_post_format( $source_post );
		return set_post_format( $target_post_id, $post_format );
	}

	/**
	 * Ensure the block editor doesn't modify the source post content for non-standard post formats.
	 *
	 * @param array $settings Settings to be passed into the block editor.
	 * @return array Settings with any `template` key removed.
	 */
	public function remove_post_format_template( $settings ) {
		unset( $settings['template'] );
		return $settings;
	}

	/**
	 * Update the target post's Likes and Sharing statuses.
	 *
	 * @param WP_Post $source_post Post object to be copied.
	 * @param int     $target_post_id Target post ID.
	 * @return array Array with the results of each update action.
	 */
	protected function update_likes_sharing( $source_post, $target_post_id ) {
		$likes   = get_post_meta( $source_post->ID, 'switch_like_status', true );
		$sharing = get_post_meta( $source_post->ID, 'sharing_disabled', true );

		if ( '' !== $likes ) {
			$likes_result = update_post_meta( $target_post_id, 'switch_like_status', $likes );
		} else {
			$likes_result = null;
		}

		if ( '' !== $sharing ) {
			$sharing_result = update_post_meta( $target_post_id, 'sharing_disabled', $sharing );
		} else {
			$sharing_result = null;
		}

		return array(
			'likes'   => $likes_result,
			'sharing' => $sharing_result,
		);
	}

	/**
	 * Update the target post's title.
	 *
	 * @param string  $post_title Post title determined by `get_default_post_to_edit()`.
	 * @param WP_Post $post       Post object of newly-inserted post.
	 * @return string             Updated post title from source post.
	 */
	public function filter_title( $post_title, $post ) {
		return $post->post_title;
	}

	/**
	 * Update the target post's content (`post_content`).
	 *
	 * @param string  $post_content Post content determined by `get_default_post_to_edit()`.
	 * @param WP_Post $post         Post object of newly-inserted post.
	 * @return string               Updated post content from source post.
	 */
	public function filter_content( $post_content, $post ) {
		return $post->post_content;
	}

	/**
	 * Update the target post's excerpt.
	 *
	 * @param string  $post_excerpt Post excerpt determined by `get_default_post_to_edit()`.
	 * @param WP_Post $post         Post object of newly-inserted post.
	 * @return string               Updated post excerpt from source post.
	 */
	public function filter_excerpt( $post_excerpt, $post ) {
		return $post->post_excerpt;
	}

	/**
	 * Validate the post type to be used for the target post.
	 *
	 * @param WP_Post $post Post object of current post in listing.
	 * @return bool True if the post type is in a list of supported psot types; false otherwise.
	 */
	protected function validate_post_type( $post ) {
		/**
		 * Fires when determining if the "Copy" row action should be made available.
		 * Allows overriding supported post types.
		 *
		 * @module copy-post
		 *
		 * @since 7.0.0
		 *
		 * @param array   Post types supported by default.
		 * @param WP_Post $post Post object of current post in listing.
		 */
		$valid_post_types = apply_filters(
			'jetpack_copy_post_post_types',
			array(
				'post',
				'page',
				'jetpack-testimonial',
				'jetpack-portfolio',
			),
			$post
		);
		return in_array( $post->post_type, $valid_post_types, true );
	}

	/**
	 * Add a "Copy" row action to supported posts/pages/CPTs on list views.
	 *
	 * @param array   $actions Existing actions.
	 * @param WP_Post $post    Post object of current post in list.
	 * @return array           Array of updated row actions.
	 */
	public function add_row_action( $actions, $post ) {
		if ( ! $this->user_can_access_post( $post->ID ) ||
			! $post instanceof WP_Post ||
			! $this->validate_post_type( $post ) ) {
			return $actions;
		}

		$edit_url    = add_query_arg(
			array(
				'post_type'    => $post->post_type,
				'jetpack-copy' => $post->ID,
			),
			admin_url( 'post-new.php' )
		);
		$edit_action = array(
			'jetpack-copy' => sprintf(
				'<a href="%s" aria-label="%s">%s</a>',
				esc_url( $edit_url ),
				esc_attr__( 'Copy this post.', 'jetpack' ),
				esc_html__( 'Copy', 'jetpack' )
			),
		);

		// Insert the Copy action before the Trash action.
		$edit_offset     = array_search( 'trash', array_keys( $actions ), true );
		$updated_actions = array_merge(
			array_slice( $actions, 0, $edit_offset ),
			$edit_action,
			array_slice( $actions, $edit_offset )
		);

		/**
		 * Fires after the new Copy action has been added to the row actions.
		 * Allows changes to the action presentation, or other final checks.
		 *
		 * @module copy-post
		 *
		 * @since 7.0.0
		 *
		 * @param array   $updated_actions Updated row actions with the Copy Post action.
		 * @param array   $actions Original row actions passed to this filter.
		 * @param WP_Post $post Post object of current post in listing.
		 */
		return apply_filters( 'jetpack_copy_post_row_actions', $updated_actions, $actions, $post );
	}
}

/**
 * Instantiate an instance of Jetpack_Copy_Post on the `admin_init` hook.
 */
function jetpack_copy_post_init() {
	new Jetpack_Copy_Post();
}
add_action( 'admin_init', 'jetpack_copy_post_init' );
