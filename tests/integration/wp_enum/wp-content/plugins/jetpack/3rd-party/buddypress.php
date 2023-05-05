<?php
/**
 * 3rd Party Integration for BuddyPress.
 *
 * @package automattic/jetpack.
 */

namespace Automattic\Jetpack\Third_Party;

add_filter( 'bp_core_pre_avatar_handle_upload', __NAMESPACE__ . '\blobphoto' );

/**
 * Adds filters for skipping photon during pre_avatar_handle_upload.
 *
 * @param bool $bool Passthrough of filter's original content. No changes made.
 *
 * @return bool
 */
function blobphoto( $bool ) {
	add_filter( 'jetpack_photon_skip_image', '__return_true' );

	return $bool;
}
