<?php
/**
 * A user roles class for Jetpack.
 *
 * @package automattic/jetpack-roles
 */

namespace Automattic\Jetpack;

/**
 * Class Automattic\Jetpack\Roles
 *
 * Contains utilities for translating user roles to capabilities and vice versa.
 */
class Roles {
	/**
	 * Map of roles we care about, and their corresponding minimum capabilities.
	 *
	 * @access protected
	 *
	 * @var array
	 */
	protected $capability_translations = array(
		'administrator' => 'manage_options',
		'editor'        => 'edit_others_posts',
		'author'        => 'publish_posts',
		'contributor'   => 'edit_posts',
		'subscriber'    => 'read',
	);

	/**
	 * Get the role of the current user.
	 *
	 * @access public
	 *
	 * @return string|boolean Current user's role, false if not enough capabilities for any of the roles.
	 */
	public function translate_current_user_to_role() {
		foreach ( $this->capability_translations as $role => $cap ) {
			if ( current_user_can( $role ) || current_user_can( $cap ) ) {
				return $role;
			}
		}

		return false;
	}

	/**
	 * Get the role of a particular user.
	 *
	 * @access public
	 *
	 * @param \WP_User $user User object.
	 * @return string|boolean User's role, false if not enough capabilities for any of the roles.
	 */
	public function translate_user_to_role( $user ) {
		foreach ( $this->capability_translations as $role => $cap ) {
			if ( user_can( $user, $role ) || user_can( $user, $cap ) ) {
				return $role;
			}
		}

		return false;
	}

	/**
	 * Get the minimum capability for a role.
	 *
	 * @access public
	 *
	 * @param string $role Role name.
	 * @return string|boolean Capability, false if role isn't mapped to any capabilities.
	 */
	public function translate_role_to_cap( $role ) {
		if ( ! isset( $this->capability_translations[ $role ] ) ) {
			return false;
		}

		return $this->capability_translations[ $role ];
	}
}
