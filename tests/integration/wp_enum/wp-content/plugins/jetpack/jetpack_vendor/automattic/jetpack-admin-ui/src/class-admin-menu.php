<?php
/**
 * Admin Menu Registration
 *
 * @package automattic/jetpack-admin-ui
 */

namespace Automattic\Jetpack\Admin_UI;

/**
 * This class offers a wrapper to add_submenu_page and makes sure stand-alone plugin's menu items are always added under the Jetpack top level menu.
 * If the Jetpack top level was not previously registered by other plugin, it will be registered here.
 */
class Admin_Menu {

	const PACKAGE_VERSION = '0.2.20';

	/**
	 * Whether this class has been initialized
	 *
	 * @var boolean
	 */
	private static $initialized = false;

	/**
	 * List of menu items enqueued to be added
	 *
	 * @var array
	 */
	private static $menu_items = array();

	/**
	 * Initialize the class and set up the main hook
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! self::$initialized ) {
			self::$initialized = true;
			self::handle_akismet_menu();
			add_action( 'admin_menu', array( __CLASS__, 'admin_menu_hook_callback' ), 1000 ); // Jetpack uses 998.
		}
	}

	/**
	 * Handles the Akismet menu item when used alongside other stand-alone plugins
	 *
	 * When Jetpack plugin is present, Akismet menu item is moved under the Jetpack top level menu, but if Akismet is active alongside other stand-alone plugins,
	 * we use this method to move the menu item.
	 */
	private static function handle_akismet_menu() {
		if ( ! class_exists( 'Jetpack' ) && class_exists( 'Akismet_Admin' ) ) {
			// Prevent Akismet from adding a menu item.
			add_action(
				'admin_menu',
				function () {
					remove_action( 'admin_menu', array( 'Akismet_Admin', 'admin_menu' ), 5 );
				},
				4
			);

			// Add an Anti-spam menu item for Jetpack.
			self::add_menu( __( 'Anti-Spam', 'jetpack-admin-ui' ), __( 'Anti-Spam', 'jetpack-admin-ui' ), 'manage_options', 'akismet-key-config', array( 'Akismet_Admin', 'display_page' ) );

		}
	}

	/**
	 * Callback to the admin_menu hook that will register the enqueued menu items
	 *
	 * @return void
	 */
	public static function admin_menu_hook_callback() {
		$can_see_toplevel_menu  = true;
		$jetpack_plugin_present = class_exists( 'Jetpack_React_Page' );
		$icon                   = method_exists( '\Automattic\Jetpack\Assets\Logo', 'get_base64_logo' )
			? ( new \Automattic\Jetpack\Assets\Logo() )->get_base64_logo()
			: 'dashicons-admin-plugins';

		if ( ! $jetpack_plugin_present ) {
			add_menu_page(
				'Jetpack',
				'Jetpack',
				'read',
				'jetpack',
				'__return_null',
				$icon,
				3
			);

			// If Jetpack plugin is not present, user will only be able to see this menu if they have enough capability to at least one of the sub menus being added.
			$can_see_toplevel_menu = false;
		}

		/**
		 * The add_sub_menu function has a bug and will not keep the right order of menu items.
		 *
		 * @see https://core.trac.wordpress.org/ticket/52035
		 * Let's order the items before registering them.
		 * Since this all happens after the Jetpack plugin menu items were added, all items will be added after Jetpack plugin items - unless position is very low number (smaller than the number of menu items present in Jetpack plugin).
		 */
		usort(
			self::$menu_items,
			function ( $a, $b ) {
				$position_a = empty( $a['position'] ) ? 0 : $a['position'];
				$position_b = empty( $b['position'] ) ? 0 : $b['position'];
				return $position_a - $position_b;
			}
		);

		foreach ( self::$menu_items as $menu_item ) {
			if ( ! current_user_can( $menu_item['capability'] ) ) {
				continue;
			}

			$can_see_toplevel_menu = true;

			add_submenu_page(
				'jetpack',
				$menu_item['page_title'],
				$menu_item['menu_title'],
				$menu_item['capability'],
				$menu_item['menu_slug'],
				$menu_item['function'],
				$menu_item['position']
			);
		}

		if ( ! $jetpack_plugin_present ) {
			remove_submenu_page( 'jetpack', 'jetpack' );
		}

		if ( ! $can_see_toplevel_menu ) {
			remove_menu_page( 'jetpack' );
		}
	}

	/**
	 * Adds a new submenu to the Jetpack Top level menu
	 *
	 * The parameters this method accepts are the same as @see add_submenu_page. This class will
	 * aggreagate all menu items registered by stand-alone plugins and make sure they all go under the same
	 * Jetpack top level menu. It will also handle the top level menu registration in case the Jetpack plugin is not present.
	 *
	 * @param string   $page_title  The text to be displayed in the title tags of the page when the menu
	 *                              is selected.
	 * @param string   $menu_title  The text to be used for the menu.
	 * @param string   $capability  The capability required for this menu to be displayed to the user.
	 * @param string   $menu_slug   The slug name to refer to this menu by. Should be unique for this menu
	 *                              and only include lowercase alphanumeric, dashes, and underscores characters
	 *                              to be compatible with sanitize_key().
	 * @param callable $function    The function to be called to output the content for this page.
	 * @param int      $position    The position in the menu order this item should appear.
	 *
	 * @return string The resulting page's hook_suffix
	 */
	public static function add_menu( $page_title, $menu_title, $capability, $menu_slug, $function, $position = null ) {
		self::init();
		self::$menu_items[] = compact( 'page_title', 'menu_title', 'capability', 'menu_slug', 'function', 'position' );

		/**
		 * Let's return the page hook so consumers can use.
		 * We know all pages will be under Jetpack top level menu page, so we can hardcode the first part of the string.
		 * Using get_plugin_page_hookname here won't work because the top level page is not registered yet.
		 */
		return 'jetpack_page_' . $menu_slug;
	}

	/**
	 * Gets the slug for the first item under the Jetpack top level menu
	 *
	 * @return string|null
	 */
	public static function get_top_level_menu_item_slug() {
		global $submenu;
		if ( ! empty( $submenu['jetpack'] ) ) {
			$item = reset( $submenu['jetpack'] );
			if ( isset( $item[2] ) ) {
				return $item[2];
			}
		}
	}

	/**
	 * Gets the URL for the first item under the Jetpack top level menu
	 *
	 * @param string $fallback If Jetpack menu is not there or no children is found, return this fallback instead. Default to admin_url().
	 * @return string
	 */
	public static function get_top_level_menu_item_url( $fallback = false ) {
		$slug = self::get_top_level_menu_item_slug();

		if ( $slug ) {
			$url = menu_page_url( $slug, false );
			return $url;
		}

		$url = $fallback ? $fallback : admin_url();
		return $url;
	}

}
