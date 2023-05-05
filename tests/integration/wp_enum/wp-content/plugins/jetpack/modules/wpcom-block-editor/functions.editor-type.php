<?php
/**
 * This file contains some 'remember' functions inspired by the core Classic Editor Plugin
 * Used to align the 'last editor' metadata so that it is set on all Jetpack and WPCOM sites
 *
 * @package automattic/jetpack
 */

namespace Jetpack\EditorType;

/**
 * Remember when the classic editor was used to edit a post.
 *
 * @param object $post The post being editted.
 */
function remember_classic_editor( $post ) {
	$post_type = get_post_type( $post );

	if ( $post_type && post_type_supports( $post_type, 'editor' ) ) {
		remember_editor( $post->ID, 'classic-editor' );
	}
}

/**
 * Remember when the block editor was used to edit a post.
 *
 * @param  array                   $editor_settings This is hooked into a filter and this is the settings that are passed in.
 * @param  WP_Block_Editor_Context $post            The block editor context.
 *
 * @return array The unmodified $editor_settings parameter.
 */
function remember_block_editor( $editor_settings, $post ) {
	if ( ! empty( $post->post ) ) {
		$post = $post->post;
	}

	if ( empty( $post ) ) {
		return $editor_settings;
	}

	$post_type = get_post_type( $post );
	if ( $post_type && can_edit_post_type( $post_type ) ) {
		remember_editor( $post->ID, 'block-editor' );
	}

	return $editor_settings;
}

/**
 * Sets the metadata for the specified post and editor.
 *
 * @param int    $post_id The ID of the post to set the metadata for.
 * @param string $editor  String name of the editor, 'classic-editor' or 'block-editor'.
 */
function remember_editor( $post_id, $editor ) {
	if ( get_post_meta( $post_id, '_last_editor_used_jetpack', true ) !== $editor ) {
		update_post_meta( $post_id, '_last_editor_used_jetpack', $editor );
	}
}

/**
 * Checks whether the block editor can be used with the given post type.
 *
 * @param  string $post_type The post type to check.
 * @return bool              Whether the block editor can be used to edit the supplied post type.
 */
function can_edit_post_type( $post_type ) {
	$can_edit = false;

	if ( function_exists( 'gutenberg_can_edit_post_type' ) ) {
		$can_edit = gutenberg_can_edit_post_type( $post_type );
	} elseif ( function_exists( 'use_block_editor_for_post_type' ) ) {
		$can_edit = use_block_editor_for_post_type( $post_type );
	}

	return $can_edit;
}
