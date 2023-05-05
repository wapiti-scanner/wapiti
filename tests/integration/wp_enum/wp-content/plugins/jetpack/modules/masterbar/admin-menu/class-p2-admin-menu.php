<?php
/**
 * P2 Admin Menu file.
 *
 * @package Jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

require_once __DIR__ . '/class-wpcom-admin-menu.php';

/**
 * Class P2_Admin_Menu.
 */
class P2_Admin_Menu extends WPcom_Admin_Menu {

	/**
	 * Slug for the "Appearance" menu item.
	 *
	 * @var string
	 */
	private $appearance_slug = 'themes.php';

	/**
	 * Slug for the "Jetpack" menu item.
	 *
	 * @var string
	 */
	private $jetpack_slug = 'jetpack';

	/**
	 * Slug for the "Upgrades" menu item.
	 *
	 * @var string
	 */
	private $upgrades_slug = 'paid-upgrades.php';

	/**
	 * Slug for the "Plugins" menu item.
	 *
	 * @var string
	 */
	private $plugins_slug = 'plugins.php';

	/**
	 * Slug for the "Tools" menu item.
	 *
	 * @var string
	 */
	private $tools_slug = 'tools.php';

	/**
	 * Whether or not the P2 is a hub.
	 *
	 * @var bool
	 */
	private $is_hub = false;

	/**
	 * Whether or not the P2 has a paid plan.
	 *
	 * @var bool
	 */
	private $is_paid = false;

	/**
	 * P2_Admin_Menu constructor.
	 */
	protected function __construct() {
		parent::__construct();

		if (
			defined( 'IS_WPCOM' ) && IS_WPCOM &&
			function_exists( 'require_lib' )
		) {
			require_lib( 'wpforteams' );

			$current_blog_id = get_current_blog_id();
			$this->is_hub    = \WPForTeams\Workspace\is_workspace_hub( $current_blog_id );
			$this->is_paid   = \WPForTeams\has_p2_plus_plan( \WPForTeams\Workspace\get_hub_blog_id_from_blog_id( $current_blog_id ) );
		}
		// Appearance -> AMP. This needs to be called here in the constructor.
		// Running it from reregister_menu_items is not early enough.
		remove_action( 'admin_menu', 'amp_add_customizer_link' );
	}

	/**
	 * Create the desired menu output.
	 */
	public function reregister_menu_items() {
		parent::reregister_menu_items();

		if ( ! $this->is_hub ) {
			$this->remove_menus_for_p2_space();
		} else {
			$this->remove_menus_for_hub();
		}

		$this->remove_menus_for_all_p2s();
	}

	/**
	 * Remove menu items that are not applicable for P2 workspace sites.
	 */
	private function remove_menus_for_p2_space() {
		// Non-hub P2s can't have plans at all.
		remove_menu_page( $this->upgrades_slug );
		// Jetpack -> Backup.
		remove_submenu_page( $this->jetpack_slug, 'https://wordpress.com/backup/' . $this->domain );
		// Appearance -> Themes.
		remove_submenu_page( $this->appearance_slug, 'https://wordpress.com/themes/' . $this->domain );
		// Appearance -> Additional CSS.
		$customize_custom_css_url = add_query_arg(
			array( 'autofocus' => array( 'section' => 'css_nudge' ) ),
			'https://wordpress.com/customize/' . $this->domain
		);
		remove_submenu_page( $this->appearance_slug, $customize_custom_css_url );

		// Tools
		remove_submenu_page( $this->tools_slug, 'https://wordpress.com/marketing/tools/' . $this->domain );
		remove_submenu_page( $this->tools_slug, 'https://wordpress.com/earn/' . $this->domain );
	}

	/**
	 * Remove menu items that are not applicable for P2 hubs.
	 */
	private function remove_menus_for_hub() {
		// Hubs can have plans, but not domain and email products.
		remove_submenu_page( $this->upgrades_slug, 'https://wordpress.com/domains/manage/' . $this->domain );
		remove_submenu_page( $this->upgrades_slug, 'https://wordpress.com/email/' . $this->domain );
		// Stats.
		remove_menu_page( 'https://wordpress.com/stats/day/' . $this->domain );
		// Hide posts.
		remove_menu_page( 'edit.php' );
		// Hide pages.
		remove_menu_page( 'edit.php?post_type=page' );
		// Hide media.
		remove_menu_page( 'https://wordpress.com/media/' . $this->domain );
		// Hide comments.
		remove_menu_page( 'https://wordpress.com/comments/all/' . $this->domain );
		// Hide appearance.
		remove_menu_page( $this->appearance_slug );
		// Tools.
		remove_submenu_page( $this->tools_slug, 'https://wordpress.com/marketing/tools/' . $this->domain );
		remove_submenu_page( $this->tools_slug, 'https://wordpress.com/earn/' . $this->domain );
		remove_submenu_page( $this->tools_slug, 'https://wordpress.com/import/' . $this->domain );
		remove_submenu_page( $this->tools_slug, 'https://wordpress.com/export/' . $this->domain );
		add_submenu_page( $this->tools_slug, __( 'Integrations', 'jetpack' ), __( 'Integrations', 'jetpack' ), 'manage_options', 'https://wordpress.com/marketing/connections/' . $this->domain, null, 0 );
		// Hide settings.
		remove_submenu_page( 'options-general.php', 'options-reading.php' );
		remove_submenu_page( 'options-general.php', 'options-writing.php' );
		remove_submenu_page( 'options-general.php', 'options-discussion.php' );
	}

	/**
	 * Remove menu items that are not applicable for all P2s.
	 */
	private function remove_menus_for_all_p2s() {
		// Remove Jetpack menu item.
		remove_menu_page( $this->jetpack_slug );

		// The following menu items are hidden for both hubs and P2 sites.
		remove_menu_page( 'link-manager.php' );
		remove_menu_page( 'feedback' );
		remove_menu_page( $this->plugins_slug );
		remove_menu_page( 'https://wordpress.com/plugins/' . $this->domain );
		remove_menu_page( 'https://wordpress.com/inbox/' . $this->domain );

		remove_submenu_page( 'https://wordpress.com/settings/general/' . $this->domain, 'sharing' );
		remove_submenu_page( 'https://wordpress.com/settings/general/' . $this->domain, 'polls&action=options' );
		remove_submenu_page( 'https://wordpress.com/settings/general/' . $this->domain, 'ratings&action=options' );
		remove_submenu_page(
			'options-general.php',
			'https://wordpress.com/hosting-config/' . $this->domain
		);
		remove_submenu_page(
			'https://wordpress.com/settings/general/' . $this->domain,
			'https://wordpress.com/marketing/sharing-buttons/' . $this->domain
		);

		/** This action is documented in `wp-content/plugins/p2-editor/classes/p2-editor-admin.php` */
		if ( apply_filters( 'p2tenberg_admin_patterns', apply_filters( 'p2editor_admin_patterns', true ) ) !== true ) {
			remove_menu_page( 'edit.php?post_type=p2_pattern' );
		}
		remove_submenu_page(
			'edit.php?post_type=p2_pattern',
			'edit-tags.php?taxonomy=post_tag&amp;post_type=p2_pattern'
		);

		// Hide performance settings.
		remove_submenu_page( 'options-general.php', 'https://wordpress.com/settings/performance/' . $this->domain );
	}

	/**
	 * Override, don't add the woocommerce installation menu on any p2s.
	 *
	 * @param array|null $current_plan The site's plan.
	 */
	public function add_woocommerce_installation_menu( $current_plan = null ) {} // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
}
