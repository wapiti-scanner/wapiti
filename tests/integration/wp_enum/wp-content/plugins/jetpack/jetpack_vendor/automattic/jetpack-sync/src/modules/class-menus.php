<?php
/**
 * Menus sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

/**
 * Class to handle sync for menus.
 */
class Menus extends Module {
	/**
	 * Navigation menu items that were added but not synced yet.
	 *
	 * @access private
	 *
	 * @var array
	 */
	private $nav_items_just_added = array();

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'menus';
	}

	/**
	 * Initialize menus action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		add_action( 'wp_create_nav_menu', $callable, 10, 2 );
		add_action( 'wp_update_nav_menu', array( $this, 'update_nav_menu' ), 10, 2 );
		add_action( 'wp_add_nav_menu_item', array( $this, 'update_nav_menu_add_item' ), 10, 3 );
		add_action( 'wp_update_nav_menu_item', array( $this, 'update_nav_menu_update_item' ), 10, 3 );
		add_action( 'post_updated', array( $this, 'remove_just_added_menu_item' ), 10, 2 );

		add_action( 'jetpack_sync_updated_nav_menu', $callable, 10, 2 );
		add_action( 'jetpack_sync_updated_nav_menu_add_item', $callable, 10, 4 );
		add_action( 'jetpack_sync_updated_nav_menu_update_item', $callable, 10, 4 );
		add_action( 'delete_nav_menu', $callable, 10, 3 );
	}

	/**
	 * Nav menu update handler.
	 *
	 * @access public
	 *
	 * @param int   $menu_id ID of the menu.
	 * @param array $menu_data An array of menu data.
	 */
	public function update_nav_menu( $menu_id, $menu_data = array() ) {
		if ( empty( $menu_data ) ) {
			return;
		}
		/**
		 * Helps sync log that a nav menu was updated.
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.0.0
		 *
		 * @param int   $menu_id ID of the menu.
		 * @param array $menu_data An array of menu data.
		 */
		do_action( 'jetpack_sync_updated_nav_menu', $menu_id, $menu_data );
	}

	/**
	 * Nav menu item addition handler.
	 *
	 * @access public
	 *
	 * @param int   $menu_id       ID of the menu.
	 * @param int   $nav_item_id   ID of the new menu item.
	 * @param array $nav_item_args Arguments used to add the menu item.
	 */
	public function update_nav_menu_add_item( $menu_id, $nav_item_id, $nav_item_args ) {
		$menu_data                    = wp_get_nav_menu_object( $menu_id );
		$this->nav_items_just_added[] = $nav_item_id;
		/**
		 * Helps sync log that a new menu item was added.
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.0.0
		 *
		 * @param int   $menu_id       ID of the menu.
		 * @param array $menu_data     An array of menu data.
		 * @param int   $nav_item_id   ID of the new menu item.
		 * @param array $nav_item_args Arguments used to add the menu item.
		 */
		do_action( 'jetpack_sync_updated_nav_menu_add_item', $menu_id, $menu_data, $nav_item_id, $nav_item_args );
	}

	/**
	 * Nav menu item update handler.
	 *
	 * @access public
	 *
	 * @param int   $menu_id       ID of the menu.
	 * @param int   $nav_item_id   ID of the new menu item.
	 * @param array $nav_item_args Arguments used to update the menu item.
	 */
	public function update_nav_menu_update_item( $menu_id, $nav_item_id, $nav_item_args ) {
		if ( in_array( $nav_item_id, $this->nav_items_just_added, true ) ) {
			return;
		}
		$menu_data = wp_get_nav_menu_object( $menu_id );
		/**
		 * Helps sync log that an update to the menu item happened.
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.0.0
		 *
		 * @param int   $menu_id       ID of the menu.
		 * @param array $menu_data     An array of menu data.
		 * @param int   $nav_item_id   ID of the new menu item.
		 * @param array $nav_item_args Arguments used to update the menu item.
		 */
		do_action( 'jetpack_sync_updated_nav_menu_update_item', $menu_id, $menu_data, $nav_item_id, $nav_item_args );
	}

	/**
	 * Remove menu items that have already been saved from the "just added" list.
	 *
	 * @access public
	 *
	 * @param int      $nav_item_id ID of the new menu item.
	 * @param \WP_Post $post_after  Nav menu item post object after the update.
	 */
	public function remove_just_added_menu_item( $nav_item_id, $post_after ) {
		if ( 'nav_menu_item' !== $post_after->post_type ) {
			return;
		}
		$this->nav_items_just_added = array_diff( $this->nav_items_just_added, array( $nav_item_id ) );
	}
}
