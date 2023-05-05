<?php

namespace WPForms\Access;

/**
 * Access/Capability management.
 *
 * @since 1.5.8
 */
class Capabilities {

	/**
	 * Init class.
	 *
	 * @since 1.5.8
	 */
	public function init() {
	}

	/**
	 * Init conditions.
	 *
	 * @since 1.5.8.2
	 */
	public function init_allowed() {

		return false;
	}

	/**
	 * Check permissions for currently logged in user.
	 *
	 * @since 1.5.8
	 *
	 * @param array|string $caps Capability name(s).
	 * @param int          $id   Optional. ID of the specific object to check against if capability is a "meta" cap.
	 *                           "Meta" capabilities, e.g. 'edit_post', 'edit_user', etc., are capabilities used
	 *                           by map_meta_cap() to map to other "primitive" capabilities, e.g. 'edit_posts',
	 *                           edit_others_posts', etc. Accessed via func_get_args() and passed to WP_User::has_cap(),
	 *                           then map_meta_cap().
	 *
	 * @return bool
	 */
	public function current_user_can( $caps = [], $id = 0 ) {

		return \current_user_can( \wpforms_get_capability_manage_options() );
	}

	/**
	 * Get a first valid capability from an array of capabilities.
	 *
	 * @since 1.5.8
	 *
	 * @param array $caps Array of capabilities to check.
	 *
	 * @return string
	 */
	public function get_menu_cap( $caps ) {

		return \wpforms_get_capability_manage_options();
	}
}
