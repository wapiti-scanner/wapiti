<?php

/**
 * Register menu elements and do other global tasks.
 *
 * @since 1.0.0
 */
class WPForms_Admin_Menu {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		// Let's make some menus.
		add_action( 'admin_menu', [ $this, 'register_menus' ], 9 );
		add_action( 'admin_head', [ $this, 'hide_wpforms_submenu_items' ] );
		add_action( 'admin_head', [ $this, 'adjust_pro_menu_item' ] );
		add_action( 'admin_head', [ $this, 'admin_menu_styles' ], 11 );

		// Plugins page settings link.
		add_filter( 'plugin_action_links_' . plugin_basename( WPFORMS_PLUGIN_DIR . 'wpforms.php' ), [ $this, 'settings_link' ], 10, 4 );
	}

	/**
	 * Register our menus.
	 *
	 * @since 1.0.0
	 */
	public function register_menus() {

		$manage_cap = wpforms_get_capability_manage_options();
		$access     = wpforms()->get( 'access' );

		if ( ! method_exists( $access, 'get_menu_cap' ) ) {
			return;
		}

		// Default Forms top level menu item.
		add_menu_page(
			esc_html__( 'WPForms', 'wpforms-lite' ),
			esc_html__( 'WPForms', 'wpforms-lite' ),
			$access->get_menu_cap( 'view_forms' ),
			'wpforms-overview',
			[ $this, 'admin_page' ],
			'data:image/svg+xml;base64,' . base64_encode( '<svg width="1792" height="1792" viewBox="0 0 1792 1792" xmlns="http://www.w3.org/2000/svg"><path fill="#9ea3a8" d="M643 911v128h-252v-128h252zm0-255v127h-252v-127h252zm758 511v128h-341v-128h341zm0-256v128h-672v-128h672zm0-255v127h-672v-127h672zm135 860v-1240q0-8-6-14t-14-6h-32l-378 256-210-171-210 171-378-256h-32q-8 0-14 6t-6 14v1240q0 8 6 14t14 6h1240q8 0 14-6t6-14zm-855-1110l185-150h-406zm430 0l221-150h-406zm553-130v1240q0 62-43 105t-105 43h-1240q-62 0-105-43t-43-105v-1240q0-62 43-105t105-43h1240q62 0 105 43t43 105z"/></svg>' ),
			apply_filters( 'wpforms_menu_position', '58.9' )
		);

		// All Forms sub menu item.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'WPForms', 'wpforms-lite' ),
			esc_html__( 'All Forms', 'wpforms-lite' ),
			$access->get_menu_cap( 'view_forms' ),
			'wpforms-overview',
			[ $this, 'admin_page' ]
		);

		// Add New sub menu item.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'WPForms Builder', 'wpforms-lite' ),
			esc_html__( 'Add New', 'wpforms-lite' ),
			$access->get_menu_cap( [ 'create_forms', 'edit_forms' ] ),
			'wpforms-builder',
			[ $this, 'admin_page' ]
		);

		// Entries sub menu item.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'Form Entries', 'wpforms-lite' ),
			esc_html__( 'Entries', 'wpforms-lite' ),
			$access->get_menu_cap( 'view_entries' ),
			'wpforms-entries',
			[ $this, 'admin_page' ]
		);

		do_action_deprecated(
			'wpform_admin_menu',
			[ $this ],
			'1.5.5 of the WPForms plugin',
			'wpforms_admin_menu'
		);
		do_action( 'wpforms_admin_menu', $this );

		// Templates sub menu item.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'WPForms Templates', 'wpforms-lite' ),
			esc_html__( 'Form Templates', 'wpforms-lite' ) . $this->get_new_badge_html(),
			$access->get_menu_cap( 'create_forms' ),
			'wpforms-templates',
			[ $this, 'admin_page' ]
		);

		// Settings sub menu item.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'WPForms Settings', 'wpforms-lite' ),
			esc_html__( 'Settings', 'wpforms-lite' ),
			$manage_cap,
			'wpforms-settings',
			[ $this, 'admin_page' ]
		);

		// Tools sub menu item.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'WPForms Tools', 'wpforms-lite' ),
			esc_html__( 'Tools', 'wpforms-lite' ),
			$access->get_menu_cap( [ 'create_forms', 'view_forms', 'view_entries' ] ),
			'wpforms-tools',
			[ $this, 'admin_page' ]
		);

		// Hidden placeholder paged used for misc content.
		add_submenu_page(
			'wpforms-settings',
			esc_html__( 'WPForms', 'wpforms-lite' ),
			esc_html__( 'Info', 'wpforms-lite' ),
			$access->get_menu_cap( 'any' ),
			'wpforms-page',
			[ $this, 'admin_page' ]
		);

		// Addons submenu page.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'WPForms Addons', 'wpforms-lite' ),
			'<span style="color:#f18500">' . esc_html__( 'Addons', 'wpforms-lite' ) . '</span>',
			$manage_cap,
			'wpforms-addons',
			[ $this, 'admin_page' ]
		);

		// Analytics submenu page.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'Analytics', 'wpforms-lite' ),
			esc_html__( 'Analytics', 'wpforms-lite' ),
			$manage_cap,
			WPForms\Admin\Pages\Analytics::SLUG,
			[ $this, 'admin_page' ]
		);

		// SMTP submenu page.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'SMTP', 'wpforms-lite' ),
			esc_html__( 'SMTP', 'wpforms-lite' ),
			$manage_cap,
			WPForms\Admin\Pages\SMTP::SLUG,
			[ $this, 'admin_page' ]
		);

		// About submenu page.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'About WPForms', 'wpforms-lite' ),
			esc_html__( 'About Us', 'wpforms-lite' ),
			$access->get_menu_cap( 'any' ),
			WPForms_About::SLUG,
			[ $this, 'admin_page' ]
		);

		// Community submenu page.
		add_submenu_page(
			'wpforms-overview',
			esc_html__( 'Community', 'wpforms-lite' ),
			esc_html__( 'Community', 'wpforms-lite' ),
			$manage_cap,
			WPForms\Admin\Pages\Community::SLUG,
			[ $this, 'admin_page' ]
		);

		if ( ! wpforms()->is_pro() ) {
			add_submenu_page(
				'wpforms-overview',
				esc_html__( 'Upgrade to Pro', 'wpforms-lite' ),
				esc_html__( 'Upgrade to Pro', 'wpforms-lite' ),
				$manage_cap,
				wpforms_admin_upgrade_link( 'admin-menu' )
			);
		}
	}

	/**
	 * Hide "Add New" admin menu item if a user can't create forms.
	 *
	 * @since 1.5.8
	 */
	public function hide_wpforms_submenu_items() {

		if ( wpforms_current_user_can( 'create_forms' ) ) {
			return;
		}

		global $submenu;

		if ( ! isset( $submenu['wpforms-overview'] ) ) {
			return;
		}

		foreach ( $submenu['wpforms-overview'] as $key => $item ) {
			if ( isset( $item[2] ) && 'wpforms-builder' === $item[2] ) {
				unset( $submenu['wpforms-overview'][ $key ] );
				break;
			}
		}

		$this->hide_wpforms_menu_item();
	}

	/**
	 * Hide "WPForms" admin menu if it has no submenu items.
	 *
	 * @since 1.5.8
	 */
	public function hide_wpforms_menu_item() {

		global $submenu, $menu;

		if ( ! empty( $submenu['wpforms-overview'] ) ) {
			return;
		}

		unset( $submenu['wpforms-overview'] );

		foreach ( $menu as $key => $item ) {
			if ( isset( $item[2] ) && 'wpforms-overview' === $item[2] ) {
				unset( $menu[ $key ] );
				break;
			}
		}
	}

	/**
	 * Alias method for backward compatibility.
	 *
	 * @since 1.7.4
	 * @deprecated 1.7.8
	 */
	public function style_upgrade_pro_link() {

		_deprecated_function( __METHOD__, '1.7.8 of the WPForms plugin', __CLASS__ . '::adjust_pro_menu_item()' );

		$this->adjust_pro_menu_item();
	}

	/**
	 * Add the PRO badge to left sidebar menu item.
	 *
	 * @since 1.7.8
	 * @deprecated 1.8.1
	 */
	public function adjust_pro_menu_item_class() {

		_deprecated_function( __METHOD__, '1.8.1 of the WPForms plugin', __CLASS__ . '::adjust_pro_menu_item()' );

		$this->adjust_pro_menu_item();
	}

	/**
	 * Make changes to the PRO menu item.
	 *
	 * @since 1.8.1
	 */
	public function adjust_pro_menu_item() {

		global $submenu;

		// Bail if plugin menu is not registered.
		if ( ! isset( $submenu['wpforms-overview'] ) ) {
			return;
		}

		$upgrade_link_position = key(
			array_filter(
				$submenu['wpforms-overview'],
				static function( $item ) {

					return strpos( $item[2], 'https://wpforms.com/lite-upgrade' ) !== false;
				}
			)
		);

		// Bail if "Upgrade to Pro" menu item is not registered.
		if ( $upgrade_link_position === null ) {
			return;
		}

		// Add the PRO badge to the menu item.
		// phpcs:disable WordPress.WP.GlobalVariablesOverride.Prohibited
		if ( isset( $submenu['wpforms-overview'][ $upgrade_link_position ][4] ) ) {
			$submenu['wpforms-overview'][ $upgrade_link_position ][4] .= ' wpforms-sidebar-upgrade-pro';
		} else {
			$submenu['wpforms-overview'][ $upgrade_link_position ][] = 'wpforms-sidebar-upgrade-pro';
		}

		$current_screen      = get_current_screen();
		$upgrade_utm_content = $current_screen === null ? 'Upgrade to Pro' : 'Upgrade to Pro - ' . $current_screen->base;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$upgrade_utm_content = empty( $_GET['view'] ) ? $upgrade_utm_content : $upgrade_utm_content . ': ' . sanitize_key( $_GET['view'] );

		// Add utm_content to the menu item.
		$submenu['wpforms-overview'][ $upgrade_link_position ][2] = esc_url(
			add_query_arg(
				'utm_content',
				$upgrade_utm_content,
				$submenu['wpforms-overview'][ $upgrade_link_position ][2]
			)
		);
		// phpcs:enable WordPress.WP.GlobalVariablesOverride.Prohibited
	}

	/**
	 * Wrapper for the hook to render our custom settings pages.
	 *
	 * @since 1.0.0
	 */
	public function admin_page() {
		do_action( 'wpforms_admin_page' );
	}

	/**
	 * Add settings link to the Plugins page.
	 *
	 * @since 1.3.9
	 *
	 * @param array  $links       Plugin row links.
	 * @param string $plugin_file Path to the plugin file relative to the plugins directory.
	 * @param array  $plugin_data An array of plugin data. See `get_plugin_data()`.
	 * @param string $context     The plugin context.
	 *
	 * @return array $links
	 */
	public function settings_link( $links, $plugin_file, $plugin_data, $context ) {

		$custom['pro'] = sprintf(
			'<a href="%1$s" aria-label="%2$s" target="_blank" rel="noopener noreferrer" 
				style="color: #00a32a; font-weight: 700;" 
				onmouseover="this.style.color=\'#008a20\';" 
				onmouseout="this.style.color=\'#00a32a\';"
				>%3$s</a>',
			esc_url(
				add_query_arg(
					[
						'utm_content'  => 'Get+WPForms+Pro',
						'utm_campaign' => 'liteplugin',
						'utm_medium'   => 'all-plugins',
						'utm_source'   => 'WordPress',
						'utm_locale'   => wpforms_sanitize_key( get_locale() ),
					],
					'https://wpforms.com/lite-upgrade/'
				)
			),
			esc_attr__( 'Upgrade to WPForms Pro', 'wpforms-lite' ),
			esc_html__( 'Get WPForms Pro', 'wpforms-lite' )
		);

		$custom['settings'] = sprintf(
			'<a href="%s" aria-label="%s">%s</a>',
			esc_url(
				add_query_arg(
					[ 'page' => 'wpforms-settings' ],
					admin_url( 'admin.php' )
				)
			),
			esc_attr__( 'Go to WPForms Settings page', 'wpforms-lite' ),
			esc_html__( 'Settings', 'wpforms-lite' )
		);

		$custom['docs'] = sprintf(
			'<a href="%1$s" aria-label="%2$s" target="_blank" rel="noopener noreferrer">%3$s</a>',
			esc_url(
				add_query_arg(
					[
						'utm_content'  => 'Documentation',
						'utm_campaign' => 'liteplugin',
						'utm_medium'   => 'all-plugins',
						'utm_source'   => 'WordPress',
					],
					'https://wpforms.com/docs/'
				)
			),
			esc_attr__( 'Read the documentation', 'wpforms-lite' ),
			esc_html__( 'Docs', 'wpforms-lite' )
		);

		return array_merge( $custom, (array) $links );
	}

	/**
	 * Get the HTML for the "NEW!" badge.
	 *
	 * @since 1.7.8
	 *
	 * @return string
	 */
	private function get_new_badge_html() {

		return '<span class="wpforms-menu-new">&nbsp;NEW!</span>';
	}

	/**
	 * Output inline styles for the admin menu.
	 *
	 * @since 1.7.8
	 */
	public function admin_menu_styles() {

		$styles = '#adminmenu .wpforms-menu-new { color: #f18500; vertical-align: super; font-size: 9px; font-weight: 600; padding-left: 2px; }';

		if ( ! wpforms()->is_pro() ) {
			$styles .= 'a.wpforms-sidebar-upgrade-pro { background-color: #00a32a !important; color: #fff !important; font-weight: 600 !important; }';
		}

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		printf( '<style>%s</style>', $styles );
	}
}

new WPForms_Admin_Menu();
