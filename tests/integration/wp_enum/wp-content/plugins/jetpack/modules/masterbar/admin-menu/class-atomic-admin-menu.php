<?php
/**
 * Atomic Admin Menu file.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

use Automattic\Jetpack\Blaze;
use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Status;
use Jetpack_Plan;

require_once __DIR__ . '/class-admin-menu.php';

/**
 * Class Atomic_Admin_Menu.
 */
class Atomic_Admin_Menu extends Admin_Menu {

	/**
	 * Atomic_Admin_Menu constructor.
	 */
	protected function __construct() {
		parent::__construct();

		add_action( 'wp_enqueue_scripts', array( $this, 'dequeue_scripts' ), 20 );
		add_action( 'admin_enqueue_scripts', array( $this, 'dequeue_scripts' ), 20 );
		add_action( 'wp_ajax_sidebar_state', array( $this, 'ajax_sidebar_state' ) );
		add_action( 'wp_ajax_jitm_dismiss', array( $this, 'wp_ajax_jitm_dismiss' ) );
		add_action( 'wp_ajax_upsell_nudge_jitm', array( $this, 'wp_ajax_upsell_nudge_jitm' ) );
		add_filter( 'block_editor_settings_all', array( $this, 'site_editor_dashboard_link' ) );

		if ( ! $this->is_api_request ) {
			add_filter( 'submenu_file', array( $this, 'override_the_theme_installer' ), 10, 2 );
		}

		add_action(
			'admin_menu',
			function () {
				remove_action( 'admin_menu', 'gutenberg_menu', 9 );
			},
			0
		);
	}

	/**
	 * Dequeues unnecessary scripts.
	 */
	public function dequeue_scripts() {
		wp_dequeue_script( 'a8c_wpcom_masterbar_overrides' ); // Initially loaded in modules/masterbar/masterbar/class-masterbar.php.
	}

	/**
	 * Determines whether the current locale is right-to-left (RTL).
	 *
	 * Performs the check against the current locale set on the WordPress.com's account settings.
	 * See `Masterbar::__construct` in `modules/masterbar/masterbar/class-masterbar.php`.
	 */
	public function is_rtl() {
		return get_user_option( 'jetpack_wpcom_is_rtl' );
	}

	/**
	 * Create the desired menu output.
	 */
	public function reregister_menu_items() {
		parent::reregister_menu_items();

		$this->add_my_home_menu();
		$this->remove_gutenberg_menu();

		if ( ! get_option( 'wpcom_is_staging_site' ) ) {
			$this->add_inbox_menu();
		}

		// Not needed outside of wp-admin.
		if ( ! $this->is_api_request ) {
			$this->add_browse_sites_link();
			$this->add_site_card_menu();
			$this->add_new_site_link();
		}

		$this->add_woocommerce_installation_menu();

		ksort( $GLOBALS['menu'] );
	}

	/**
	 * Get the preferred view for the given screen.
	 *
	 * @param string $screen Screen identifier.
	 * @param bool   $fallback_global_preference (Optional) Whether the global preference for all screens should be used
	 *                                           as fallback if there is no specific preference for the given screen.
	 *                                           Default: true.
	 * @return string
	 */
	public function get_preferred_view( $screen, $fallback_global_preference = true ) {
		// Export on Atomic sites are always managed on WP Admin.
		if ( in_array( $screen, array( 'export.php' ), true ) ) {
			return self::CLASSIC_VIEW;
		}

		/**
		 * When Jetpack SSO is disabled, we need to force Calypso because it might create confusion to be redirected to WP-Admin.
		 * Furthermore, because we don't display the quick switcher, users having an WP-Admin interface by default won't be able to go back to the Calyso version.
		 */
		if ( ! \Jetpack::is_module_active( 'sso' ) ) {
			return self::DEFAULT_VIEW;
		}

		return parent::get_preferred_view( $screen, $fallback_global_preference );
	}

	/**
	 * Adds Plugins menu.
	 */
	public function add_plugins_menu() {
		global $submenu;

		// Calypso plugins screens link.
		$plugins_slug = 'https://wordpress.com/plugins/' . $this->domain;

		// Link to the Marketplace on sites that can't manage plugins.
		if (
			function_exists( 'wpcom_site_has_feature' ) &&
			! wpcom_site_has_feature( \WPCOM_Features::MANAGE_PLUGINS )
		) {
			add_menu_page( __( 'Plugins', 'jetpack' ), __( 'Plugins', 'jetpack' ), 'manage_options', $plugins_slug, null, 'dashicons-admin-plugins', '65' );
			return;
		}

		if ( ! isset( $submenu['plugins.php'] ) ) {
			return;
		}

		$plugins_submenu = $submenu['plugins.php'];

		// Move "Add New" plugin submenu to the top position.
		foreach ( $plugins_submenu as $submenu_key => $submenu_keys ) {
			if ( 'plugin-install.php' === $submenu_keys[2] ) {
				// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				$submenu['plugins.php'] = array( $submenu_key => $plugins_submenu[ $submenu_key ] ) + $plugins_submenu;
			}
		}

		$submenus_to_update = array( 'plugin-install.php' => $plugins_slug );

		$this->update_submenus( 'plugins.php', $submenus_to_update );
	}

	/**
	 * Adds the site switcher link if user has more than one site.
	 */
	public function add_browse_sites_link() {
		$site_count = get_user_option( 'wpcom_site_count' );
		if ( ! $site_count || $site_count < 2 ) {
			return;
		}

		// Add the menu item.
		add_menu_page( __( 'site-switcher', 'jetpack' ), __( 'Browse sites', 'jetpack' ), 'read', 'https://wordpress.com/sites', null, 'dashicons-arrow-left-alt2', 0 );
		add_filter( 'add_menu_classes', array( $this, 'set_browse_sites_link_class' ) );
	}

	/**
	 * Adds a custom element class for Site Switcher menu item.
	 *
	 * @param array $menu Associative array of administration menu items.
	 *
	 * @return array
	 */
	public function set_browse_sites_link_class( array $menu ) {
		foreach ( $menu as $key => $menu_item ) {
			if ( 'site-switcher' !== $menu_item[3] ) {
				continue;
			}

			$menu[ $key ][4] = add_cssclass( 'site-switcher', $menu_item[4] );
			break;
		}

		return $menu;
	}

	/**
	 * Adds a link to the menu to create a new site.
	 */
	public function add_new_site_link() {
		$site_count = get_user_option( 'wpcom_site_count' );
		if ( $site_count && $site_count > 1 ) {
			return;
		}

		add_menu_page( __( 'Add New Site', 'jetpack' ), __( 'Add New Site', 'jetpack' ), 'read', 'https://wordpress.com/start?ref=calypso-sidebar', null, 'dashicons-plus-alt' );
	}

	/**
	 * Adds site card component.
	 */
	public function add_site_card_menu() {
		$default        = plugins_url( 'globe-icon.svg', __FILE__ );
		$icon           = get_site_icon_url( 32, $default );
		$blog_name      = get_option( 'blogname' ) !== '' ? get_option( 'blogname' ) : $this->domain;
		$is_coming_soon = ( new Status() )->is_coming_soon();

		$badge = '';
		if ( ( function_exists( 'site_is_private' ) && site_is_private() ) || $is_coming_soon ) {
			$badge .= sprintf(
				'<span class="site__badge site__badge-private">%s</span>',
				$is_coming_soon ? esc_html__( 'Coming Soon', 'jetpack' ) : esc_html__( 'Private', 'jetpack' )
			);
		}

		$site_card = '
<div class="site__info">
	<div class="site__title">%1$s</div>
	<div class="site__domain">%2$s</div>
	%3$s
</div>';

		$site_card = sprintf(
			$site_card,
			$blog_name,
			$this->domain,
			$badge
		);

		add_menu_page( 'site-card', $site_card, 'read', get_home_url(), null, $icon, 1 );
		add_filter( 'add_menu_classes', array( $this, 'set_site_card_menu_class' ) );
	}

	/**
	 * Adds a custom element class and id for Site Card's menu item.
	 *
	 * @param array $menu Associative array of administration menu items.
	 *
	 * @return array
	 */
	public function set_site_card_menu_class( array $menu ) {
		foreach ( $menu as $key => $menu_item ) {
			if ( 'site-card' !== $menu_item[3] ) {
				continue;
			}

			$classes = ' toplevel_page_site-card';

			// webclip.png is the default on WoA sites. Anything other than that means we have a custom site icon.
			if ( has_site_icon() && 'https://s0.wp.com/i/webclip.png' !== get_site_icon_url( 512 ) ) {
				$classes .= ' has-site-icon';
			}

			$menu[ $key ][4] = $menu_item[4] . $classes;
			$menu[ $key ][5] = 'toplevel_page_site_card';
			break;
		}

		return $menu;
	}

	/**
	 * Returns the first available upsell nudge.
	 *
	 * @return array
	 */
	public function get_upsell_nudge() {
		$jitm         = \Automattic\Jetpack\JITMS\JITM::get_instance();
		$message_path = 'calypso:sites:sidebar_notice';
		$message      = $jitm->get_messages( $message_path, wp_json_encode( array( 'message_path' => $message_path ) ), false );

		if ( isset( $message[0] ) ) {
			$message = $message[0];
			return array(
				'content'                      => $message->content->message,
				'cta'                          => $message->CTA->message, // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				'link'                         => $message->CTA->link, // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				'tracks_impression_event_name' => $message->tracks->display->name,
				'tracks_impression_cta_name'   => $message->tracks->display->props->cta_name,
				'tracks_click_event_name'      => $message->tracks->click->name,
				'tracks_click_cta_name'        => $message->tracks->click->props->cta_name,
				'dismissible'                  => $message->is_dismissible,
				'feature_class'                => $message->feature_class,
				'id'                           => $message->id,
			);
		}
	}

	/**
	 * Adds Stats menu.
	 */
	public function add_stats_menu() {
		$menu_title = __( 'Stats', 'jetpack' );

		if (
			! $this->is_api_request &&
			\Jetpack::is_module_active( 'stats' ) &&
			function_exists( 'stats_get_image_chart_src' )
		) {
			$img_src = esc_attr(
				stats_get_image_chart_src( 'admin-bar-hours-scale-2x', array( 'masterbar' => '' ) )
			);
			$alt     = esc_attr__( 'Hourly views', 'jetpack' );

			$menu_title .= "<img class='sidebar-unified__sparkline' src='$img_src' width='80' height='20' alt='$alt'>";
		}

		add_menu_page( __( 'Stats', 'jetpack' ), $menu_title, 'edit_posts', 'https://wordpress.com/stats/day/' . $this->domain, null, 'dashicons-chart-bar', 3 );
	}

	/**
	 * Adds Upgrades menu.
	 *
	 * @param string $plan The current WPCOM plan of the blog.
	 */
	public function add_upgrades_menu( $plan = null ) {

		if ( get_option( 'wpcom_is_staging_site' ) ) {
			return;
		}
		$products = Jetpack_Plan::get();
		if ( array_key_exists( 'product_name_short', $products ) ) {
			$plan = $products['product_name_short'];
		}
		parent::add_upgrades_menu( $plan );

		$last_upgrade_submenu_position = $this->get_submenu_item_count( 'paid-upgrades.php' );

		add_submenu_page( 'paid-upgrades.php', __( 'Domains', 'jetpack' ), __( 'Domains', 'jetpack' ), 'manage_options', 'https://wordpress.com/domains/manage/' . $this->domain, null, $last_upgrade_submenu_position - 1 );

		/**
		 * Whether to show the WordPress.com Emails submenu under the main Upgrades menu.
		 *
		 * @use add_filter( 'jetpack_show_wpcom_upgrades_email_menu', '__return_true' );
		 * @module masterbar
		 *
		 * @since 9.7.0
		 *
		 * @param bool $show_wpcom_upgrades_email_menu Load the WordPress.com Emails submenu item. Default to false.
		 */
		if ( apply_filters( 'jetpack_show_wpcom_upgrades_email_menu', false ) ) {
			add_submenu_page( 'paid-upgrades.php', __( 'Emails', 'jetpack' ), __( 'Emails', 'jetpack' ), 'manage_options', 'https://wordpress.com/email/' . $this->domain, null, $last_upgrade_submenu_position );
		}
	}

	/**
	 * Adds Settings menu.
	 */
	public function add_options_menu() {
		parent::add_options_menu();

		if ( Jetpack_Plan::supports( 'security-settings' ) ) {
			add_submenu_page(
				'options-general.php',
				esc_attr__( 'Security', 'jetpack' ),
				__( 'Security', 'jetpack' ),
				'manage_options',
				'https://wordpress.com/settings/security/' . $this->domain,
				null,
				2
			);
		}

		add_submenu_page( 'options-general.php', esc_attr__( 'Hosting Configuration', 'jetpack' ), __( 'Hosting Configuration', 'jetpack' ), 'manage_options', 'https://wordpress.com/hosting-config/' . $this->domain, null, 11 );

		// Page Optimize is active by default on all Atomic sites and registers a Settings > Performance submenu which
		// would conflict with our own Settings > Performance that links to Calypso, so we hide it it since the Calypso
		// performance settings already have a link to Page Optimize settings page.
		$this->hide_submenu_page( 'options-general.php', 'page-optimize' );

		if ( Blaze::should_initialize() ) {
			add_submenu_page( 'tools.php', esc_attr__( 'Advertising', 'jetpack' ), __( 'Advertising', 'jetpack' ), 'manage_options', 'https://wordpress.com/advertising/' . $this->domain, null, 1 );
		}
	}

	/**
	 * Adds Tools menu entries.
	 */
	public function add_tools_menu() {
		parent::add_tools_menu();

		/**
		 * Whether to show the WordPress.com Site Logs submenu under the main Tools menu.
		 *
		 * @use add_filter( 'jetpack_show_wpcom_site_logs_menu', '__return_true' );
		 * @module masterbar
		 *
		 * @since 12.0
		 *
		 * @param bool $show_wpcom_site_logs_menu Load the WordPress.com Site Logs submenu item. Default to false.
		 */
		if ( apply_filters( 'jetpack_show_wpcom_site_logs_menu', false ) ) {
			add_submenu_page( 'tools.php', esc_attr__( 'Site Logs', 'jetpack' ), __( 'Site Logs', 'jetpack' ), 'manage_options', 'https://wordpress.com/site-logs/' . $this->domain, null, 7 );
		}
	}

	/**
	 * Override the global submenu_file for theme-install.php page so the WP Admin menu item gets highlighted correctly.
	 *
	 * @param string $submenu_file The current pages $submenu_file global variable value.
	 * @return string | null
	 */
	public function override_the_theme_installer( $submenu_file ) {
		global $pagenow;

		if ( 'themes.php' === $submenu_file && 'theme-install.php' === $pagenow ) {
			return null;
		}
		return $submenu_file;
	}

	/**
	 * Also remove the Gutenberg plugin menu.
	 */
	public function remove_gutenberg_menu() {
		// Always remove the Gutenberg menu.
		remove_menu_page( 'gutenberg' );
	}

	/**
	 * Saves the sidebar state ( expanded / collapsed ) via an ajax request.
	 */
	public function ajax_sidebar_state() {
		$expanded = isset( $_REQUEST['expanded'] ) ? filter_var( wp_unslash( $_REQUEST['expanded'] ), FILTER_VALIDATE_BOOLEAN ) : false; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		Client::wpcom_json_api_request_as_user(
			'/me/preferences',
			'2',
			array(
				'method' => 'POST',
			),
			(object) array( 'calypso_preferences' => (object) array( 'sidebarCollapsed' => ! $expanded ) ),
			'wpcom'
		);

		wp_die();
	}

	/**
	 * Handle ajax requests to dismiss a just-in-time-message
	 */
	public function wp_ajax_jitm_dismiss() {
		check_ajax_referer( 'jitm_dismiss' );
		$jitm = \Automattic\Jetpack\JITMS\JITM::get_instance();
		if ( isset( $_REQUEST['id'] ) && isset( $_REQUEST['feature_class'] ) ) {
			$jitm->dismiss( sanitize_text_field( wp_unslash( $_REQUEST['id'] ) ), sanitize_text_field( wp_unslash( $_REQUEST['feature_class'] ) ) );
		}
		wp_die();
	}
}
