<?php
/**
 * Admin Menu file.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

use Automattic\Jetpack\Assets\Logo;
use Automattic\Jetpack\Redirect;

require_once __DIR__ . '/class-base-admin-menu.php';

/**
 * Class Admin_Menu.
 */
class Admin_Menu extends Base_Admin_Menu {

	/**
	 * Create the desired menu output.
	 */
	public function reregister_menu_items() {
		// Remove separators.
		remove_menu_page( 'separator1' );

		$this->add_stats_menu();
		$this->add_upgrades_menu();
		$this->add_posts_menu();
		$this->add_media_menu();
		$this->add_page_menu();
		$this->add_testimonials_menu();
		$this->add_portfolio_menu();
		$this->add_comments_menu();
		$this->add_appearance_menu();
		$this->add_plugins_menu();
		$this->add_users_menu();
		$this->add_tools_menu();
		$this->add_options_menu();
		$this->add_jetpack_menu();

		// Remove Links Manager menu since its usage is discouraged. https://github.com/Automattic/wp-calypso/issues/51188.
		// @see https://core.trac.wordpress.org/ticket/21307#comment:73.
		if ( $this->should_disable_links_manager() ) {
			remove_menu_page( 'link-manager.php' );
		}

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
		// When no preferred view has been set for "Users > All Users" or "Settings > General", keep the previous
		// behavior that forced the default view regardless of the global preference.
		if (
			$fallback_global_preference &&
			in_array( $screen, array( 'users.php', 'options-general.php' ), true )
		) {
			$preferred_view = parent::get_preferred_view( $screen, false );
			if ( self::UNKNOWN_VIEW === $preferred_view ) {
				return self::DEFAULT_VIEW;
			}
			return $preferred_view;
		}

		return parent::get_preferred_view( $screen, $fallback_global_preference );
	}

	/**
	 * Point the Site Editor's `< Dashboard` link to wpcom home.
	 *
	 * Although this isn't strictly an admin menu item, it belongs here because it's part of
	 * changing wp-admin links to their wp.com equivalents.
	 *
	 * @param  array $settings Editor settings.
	 * @return array           Updated Editor settings.
	 */
	public function site_editor_dashboard_link( $settings ) {
		$settings['__experimentalDashboardLink'] = 'https://wordpress.com/home/' . $this->domain;
		return $settings;
	}

	/**
	 * Check if Links Manager is being used.
	 */
	public function should_disable_links_manager() {
		// The max ID number of the auto-generated links.
		// See /wp-content/mu-plugins/wpcom-wp-install-defaults.php in WP.com.
		$max_default_id = 10;

		// We are only checking the latest entry link_id so are limiting the query to 1.
		$link_manager_links = get_bookmarks(
			array(
				'orderby'        => 'link_id',
				'order'          => 'DESC',
				'limit'          => 1,
				'hide_invisible' => 0,
			)
		);

		// Ordered links by ID descending, check if the first ID is more than $max_default_id.
		if ( count( $link_manager_links ) > 0 && $link_manager_links[0]->link_id > $max_default_id ) {
			return false;
		}

		return true;
	}

	/**
	 * Adds My Home menu.
	 */
	public function add_my_home_menu() {
		$this->update_menu( 'index.php', 'https://wordpress.com/home/' . $this->domain, __( 'My Home', 'jetpack' ), 'edit_posts', 'dashicons-admin-home' );
	}

	/**
	 * Adds Inbox menu.
	 */
	public function add_inbox_menu() {
		add_menu_page( __( 'Inbox', 'jetpack' ), __( 'Inbox', 'jetpack' ), 'manage_options', 'https://wordpress.com/inbox/' . $this->domain, null, 'dashicons-email', '4.64424' );
	}

	/**
	 * Adds Stats menu.
	 */
	public function add_stats_menu() {
		add_menu_page( __( 'Stats', 'jetpack' ), __( 'Stats', 'jetpack' ), 'view_stats', 'https://wordpress.com/stats/day/' . $this->domain, null, 'dashicons-chart-bar', 3 );
	}

	/**
	 * Adds Upgrades menu.
	 *
	 * @param string $plan The current WPCOM plan of the blog.
	 */
	public function add_upgrades_menu( $plan = null ) {
		global $menu;

		$menu_exists = false;
		foreach ( $menu as $item ) {
			if ( 'paid-upgrades.php' === $item[2] ) {
				$menu_exists = true;
				break;
			}
		}

		if ( ! $menu_exists ) {
			if ( $plan ) {
				// Add display:none as a default for cases when CSS is not loaded.
				$site_upgrades = '%1$s<span class="inline-text" style="display:none">%2$s</span>';
				$site_upgrades = sprintf(
					$site_upgrades,
					__( 'Upgrades', 'jetpack' ),
					// phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralText
					__( $plan, 'jetpack' )
				);
			} else {
				$site_upgrades = __( 'Upgrades', 'jetpack' );
			}

			add_menu_page( __( 'Upgrades', 'jetpack' ), $site_upgrades, 'manage_options', 'paid-upgrades.php', null, 'dashicons-cart', 4 );
		}

		add_submenu_page( 'paid-upgrades.php', __( 'Plans', 'jetpack' ), __( 'Plans', 'jetpack' ), 'manage_options', 'https://wordpress.com/plans/' . $this->domain, null, 1 );
		add_submenu_page( 'paid-upgrades.php', __( 'Purchases', 'jetpack' ), __( 'Purchases', 'jetpack' ), 'manage_options', 'https://wordpress.com/purchases/subscriptions/' . $this->domain, null, 2 );

		if ( ! $menu_exists ) {
			// Remove the submenu auto-created by Core.
			$this->hide_submenu_page( 'paid-upgrades.php', 'paid-upgrades.php' );
		}
	}

	/**
	 * Adds Posts menu.
	 */
	public function add_posts_menu() {
		$submenus_to_update = array();

		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'edit.php' ) ) {
			$submenus_to_update['edit.php']     = 'https://wordpress.com/posts/' . $this->domain;
			$submenus_to_update['post-new.php'] = 'https://wordpress.com/post/' . $this->domain;
		}

		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'edit-tags.php?taxonomy=category' ) ) {
			$submenus_to_update['edit-tags.php?taxonomy=category'] = 'https://wordpress.com/settings/taxonomies/category/' . $this->domain;
		}

		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'edit-tags.php?taxonomy=post_tag' ) ) {
			$submenus_to_update['edit-tags.php?taxonomy=post_tag'] = 'https://wordpress.com/settings/taxonomies/post_tag/' . $this->domain;
		}

		$this->update_submenus( 'edit.php', $submenus_to_update );
	}

	/**
	 * Adds Media menu.
	 */
	public function add_media_menu() {
		if ( self::CLASSIC_VIEW === $this->get_preferred_view( 'upload.php' ) ) {
			return;
		}

		$this->hide_submenu_page( 'upload.php', 'media-new.php' );

		$this->update_menu( 'upload.php', 'https://wordpress.com/media/' . $this->domain );
	}

	/**
	 * Adds Page menu.
	 */
	public function add_page_menu() {
		if ( self::CLASSIC_VIEW === $this->get_preferred_view( 'edit.php?post_type=page' ) ) {
			return;
		}

		$submenus_to_update = array(
			'edit.php?post_type=page'     => 'https://wordpress.com/pages/' . $this->domain,
			'post-new.php?post_type=page' => 'https://wordpress.com/page/' . $this->domain,
		);
		$this->update_submenus( 'edit.php?post_type=page', $submenus_to_update );
	}

	/**
	 * Adds Testimonials menu.
	 */
	public function add_testimonials_menu() {
		$this->add_custom_post_type_menu( 'jetpack-testimonial' );
	}

	/**
	 * Adds Portfolio menu.
	 */
	public function add_portfolio_menu() {
		$this->add_custom_post_type_menu( 'jetpack-portfolio' );
	}

	/**
	 * Adds a custom post type menu.
	 *
	 * @param string $post_type Custom post type.
	 */
	public function add_custom_post_type_menu( $post_type ) {
		if ( self::CLASSIC_VIEW === $this->get_preferred_view( 'edit.php?post_type=' . $post_type ) ) {
			return;
		}

		$submenus_to_update = array(
			'edit.php?post_type=' . $post_type     => 'https://wordpress.com/types/' . $post_type . '/' . $this->domain,
			'post-new.php?post_type=' . $post_type => 'https://wordpress.com/edit/' . $post_type . '/' . $this->domain,
		);
		$this->update_submenus( 'edit.php?post_type=' . $post_type, $submenus_to_update );
	}

	/**
	 * Adds Comments menu.
	 */
	public function add_comments_menu() {
		if ( self::CLASSIC_VIEW === $this->get_preferred_view( 'edit-comments.php' ) ) {
			return;
		}

		$this->update_menu( 'edit-comments.php', 'https://wordpress.com/comments/all/' . $this->domain );
	}

	/**
	 * Adds Appearance menu.
	 *
	 * @return string The Customizer URL.
	 */
	public function add_appearance_menu() {
		$request_uri                     = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$default_customize_slug          = add_query_arg( 'return', rawurlencode( remove_query_arg( wp_removable_query_args(), $request_uri ) ), 'customize.php' );
		$default_customize_header_slug_1 = add_query_arg( array( 'autofocus' => array( 'control' => 'header_image' ) ), $default_customize_slug );
		// TODO: Remove WPCom_Theme_Customizer::modify_header_menu_links() and WPcom_Custom_Header::modify_admin_menu_links().
		$default_customize_header_slug_2     = admin_url( 'themes.php?page=custom-header' );
		$default_customize_background_slug_1 = add_query_arg( array( 'autofocus' => array( 'control' => 'background_image' ) ), $default_customize_slug );
		// TODO: Remove Colors_Manager::modify_header_menu_links() and Colors_Manager_Common::modify_header_menu_links().
		$default_customize_background_slug_2 = add_query_arg( array( 'autofocus' => array( 'section' => 'colors_manager_tool' ) ), admin_url( 'customize.php' ) );

		if ( $this->is_api_request ) {
			// In case this is an api request we will have to add the 'return' querystring via JS.
			$customize_url = 'customize.php';
		} else {
			$customize_url = $default_customize_slug;
		}

		$submenus_to_update = array(
			$default_customize_slug              => $customize_url,
			$default_customize_header_slug_1     => add_query_arg( array( 'autofocus' => array( 'control' => 'header_image' ) ), $customize_url ),
			$default_customize_header_slug_2     => add_query_arg( array( 'autofocus' => array( 'control' => 'header_image' ) ), $customize_url ),
			$default_customize_background_slug_1 => add_query_arg( array( 'autofocus' => array( 'section' => 'colors_manager_tool' ) ), $customize_url ),
			$default_customize_background_slug_2 => add_query_arg( array( 'autofocus' => array( 'section' => 'colors_manager_tool' ) ), $customize_url ),
		);

		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'themes.php' ) ) {
			$submenus_to_update['themes.php'] = 'https://wordpress.com/themes/' . $this->domain;
		}

		$this->update_submenus( 'themes.php', $submenus_to_update );

		$this->hide_submenu_page( 'themes.php', 'custom-header' );
		$this->hide_submenu_page( 'themes.php', 'custom-background' );

		return $customize_url;
	}

	/**
	 * Adds Plugins menu.
	 */
	public function add_plugins_menu() {
		$this->hide_submenu_page( 'plugins.php', 'plugin-install.php' );
		$this->hide_submenu_page( 'plugins.php', 'plugin-editor.php' );

		$this->update_menu( 'plugins.php', 'https://wordpress.com/plugins/' . $this->domain );
	}

	/**
	 * Adds Users menu.
	 */
	public function add_users_menu() {
		$submenus_to_update = array(
			'profile.php' => 'https://wordpress.com/me',
		);

		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'users.php' ) ) {
			$submenus_to_update['users.php']    = 'https://wordpress.com/people/team/' . $this->domain;
			$submenus_to_update['user-new.php'] = 'https://wordpress.com/people/new/' . $this->domain;
		}

		$slug = current_user_can( 'list_users' ) ? 'users.php' : 'profile.php';
		$this->update_submenus( $slug, $submenus_to_update );
		add_submenu_page( $slug, esc_attr__( 'Account Settings', 'jetpack' ), __( 'Account Settings', 'jetpack' ), 'read', 'https://wordpress.com/me/account' );
	}

	/**
	 * Adds Tools menu.
	 */
	public function add_tools_menu() {
		$submenus_to_update = array();
		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'import.php' ) ) {
			$submenus_to_update['import.php'] = 'https://wordpress.com/import/' . $this->domain;
		}
		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'export.php' ) ) {
			$submenus_to_update['export.php'] = 'https://wordpress.com/export/' . $this->domain;
		}
		$this->update_submenus( 'tools.php', $submenus_to_update );

		$this->hide_submenu_page( 'tools.php', 'tools.php' );
		$this->hide_submenu_page( 'tools.php', 'delete-blog' );

		add_submenu_page( 'tools.php', esc_attr__( 'Marketing', 'jetpack' ), __( 'Marketing', 'jetpack' ), 'publish_posts', 'https://wordpress.com/marketing/tools/' . $this->domain, null, 0 );
		add_submenu_page( 'tools.php', esc_attr__( 'Earn', 'jetpack' ), __( 'Earn', 'jetpack' ), 'manage_options', 'https://wordpress.com/earn/' . $this->domain, null, 1 );
	}

	/**
	 * Adds Settings menu.
	 */
	public function add_options_menu() {
		$submenus_to_update = array();

		$this->hide_submenu_page( 'options-general.php', 'sharing' );

		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'options-general.php' ) ) {
			$submenus_to_update['options-general.php'] = 'https://wordpress.com/settings/general/' . $this->domain;
		}

		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'options-writing.php' ) ) {
			$submenus_to_update['options-writing.php'] = 'https://wordpress.com/settings/writing/' . $this->domain;
		}

		if (
			/**
			 * Filter to enable the modernized Reading Settings in Calypso UI.
			 *
			 * @since 11.8
			 * @module masterbar
			 *
			 * @param bool false Should the modernized Reading Settings be enabled? Default to false.
			 */
			apply_filters( 'calypso_use_modernized_reading_settings', false )
			&& self::DEFAULT_VIEW === $this->get_preferred_view( 'options-reading.php' )
		) {
			$submenus_to_update['options-reading.php'] = 'https://wordpress.com/settings/reading/' . $this->domain;
		}

		if ( self::DEFAULT_VIEW === $this->get_preferred_view( 'options-discussion.php' ) ) {
			$submenus_to_update['options-discussion.php'] = 'https://wordpress.com/settings/discussion/' . $this->domain;
		}

		$this->update_submenus( 'options-general.php', $submenus_to_update );

		add_submenu_page( 'options-general.php', esc_attr__( 'Performance', 'jetpack' ), __( 'Performance', 'jetpack' ), 'manage_options', 'https://wordpress.com/settings/performance/' . $this->domain, null, 1 );
	}

	/**
	 * Adds Jetpack menu.
	 */
	public function add_jetpack_menu() {
		$this->add_admin_menu_separator( 50, 'manage_options' );

		$icon            = ( new Logo() )->get_base64_logo();
		$is_menu_updated = $this->update_menu( 'jetpack', null, null, null, $icon, 51 );
		if ( ! $is_menu_updated ) {
			add_menu_page( esc_attr__( 'Jetpack', 'jetpack' ), __( 'Jetpack', 'jetpack' ), 'manage_options', 'jetpack', null, $icon, 51 );
		}

		add_submenu_page( 'jetpack', esc_attr__( 'Activity Log', 'jetpack' ), __( 'Activity Log', 'jetpack' ), 'manage_options', 'https://wordpress.com/activity-log/' . $this->domain, null, 2 );
		add_submenu_page( 'jetpack', esc_attr__( 'Backup', 'jetpack' ), __( 'Backup', 'jetpack' ), 'manage_options', 'https://wordpress.com/backup/' . $this->domain, null, 3 );

		$this->hide_submenu_page( 'jetpack', 'jetpack#/settings' );
		$this->hide_submenu_page( 'jetpack', 'stats' );
		$this->hide_submenu_page( 'jetpack', esc_url( Redirect::get_url( 'calypso-backups' ) ) );
		$this->hide_submenu_page( 'jetpack', esc_url( Redirect::get_url( 'calypso-scanner' ) ) );

		if ( ! $is_menu_updated ) {
			// Remove the submenu auto-created by Core just to be sure that there no issues on non-admin roles.
			remove_submenu_page( 'jetpack', 'jetpack' );
		}
	}

	/**
	 * Add the calypso /woocommerce-installation/ menu item.
	 *
	 * @param array $current_plan The site's plan if they have one. This is passed from WPcom_Admin_Menu to prevent
	 * redundant database queries.
	 */
	public function add_woocommerce_installation_menu( $current_plan = null ) {
		/**
		 * Whether to show the WordPress.com WooCommerce Installation menu.
		 *
		 * @use add_filter( 'jetpack_show_wpcom_woocommerce_installation_menu', '__return_true' );
		 * @module masterbar
		 * @since 10.3.0
		 * @param bool $jetpack_show_wpcom_woocommerce_installation_menu Load the WordPress.com WooCommerce Installation menu item. Default to false.
		 * @param array $current_plan Data about the current site's plan.
		 */
		if ( apply_filters( 'jetpack_show_wpcom_woocommerce_installation_menu', false, $current_plan ) ) {
			$this->add_admin_menu_separator( 54, 'activate_plugins' );

			$icon_url = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDI0IDEwMjQiPjxwYXRoIGZpbGw9IiNhMmFhYjIiIGQ9Ik02MTIuMTkyIDQyNi4zMzZjMC02Ljg5Ni0zLjEzNi01MS42LTI4LTUxLjYtMzcuMzYgMC00Ni43MDQgNzIuMjU2LTQ2LjcwNCA4Mi42MjQgMCAzLjQwOCAzLjE1MiA1OC40OTYgMjguMDMyIDU4LjQ5NiAzNC4xOTItLjAzMiA0Ni42NzItNzIuMjg4IDQ2LjY3Mi04OS41MnptMjAyLjE5MiAwYzAtNi44OTYtMy4xNTItNTEuNi0yOC4wMzItNTEuNi0zNy4yOCAwLTQ2LjYwOCA3Mi4yNTYtNDYuNjA4IDgyLjYyNCAwIDMuNDA4IDMuMDcyIDU4LjQ5NiAyNy45NTIgNTguNDk2IDM0LjE5Mi0uMDMyIDQ2LjY4OC03Mi4yODggNDYuNjg4LTg5LjUyek0xNDEuMjk2Ljc2OGMtNjguMjI0IDAtMTIzLjUwNCA1NS40ODgtMTIzLjUwNCAxMjMuOTJ2NjUwLjcyYzAgNjguNDMyIDU1LjI5NiAxMjMuOTIgMTIzLjUwNCAxMjMuOTJoMzM5LjgwOGwxMjMuNTA0IDEyMy45MzZWODk5LjMyOGgyNzguMDQ4YzY4LjIyNCAwIDEyMy41Mi01NS40NzIgMTIzLjUyLTEyMy45MnYtNjUwLjcyYzAtNjguNDMyLTU1LjI5Ni0xMjMuOTItMTIzLjUyLTEyMy45MmgtNzQxLjM2em01MjYuODY0IDQyMi4xNmMwIDU1LjA4OC0zMS4wODggMTU0Ljg4LTEwMi42NCAxNTQuODgtNi4yMDggMC0xOC40OTYtMy42MTYtMjUuNDI0LTYuMDE2LTMyLjUxMi0xMS4xNjgtNTAuMTkyLTQ5LjY5Ni01Mi4zNTItNjYuMjU2IDAgMC0zLjA3Mi0xNy43OTItMy4wNzItNDAuNzUyIDAtMjIuOTkyIDMuMDcyLTQ1LjMyOCAzLjA3Mi00NS4zMjggMTUuNTUyLTc1LjcyOCA0My41NTItMTA2LjczNiA5Ni40NDgtMTA2LjczNiA1OS4wNzItLjAzMiA4My45NjggNTguNTI4IDgzLjk2OCAxMTAuMjA4ek00ODYuNDk2IDMwMi40YzAgMy4zOTItNDMuNTUyIDE0MS4xNjgtNDMuNTUyIDIxMy40MjR2NzUuNzEyYy0yLjU5MiAxMi4wOC00LjE2IDI0LjE0NC0yMS44MjQgMjQuMTQ0LTQ2LjYwOCAwLTg4Ljg4LTE1MS40NzItOTIuMDE2LTE2MS44NC02LjIwOCA2Ljg5Ni02Mi4yNCAxNjEuODQtOTYuNDQ4IDE2MS44NC0yNC44NjQgMC00My41NTItMTEzLjY0OC00Ni42MDgtMTIzLjkzNkMxNzYuNzA0IDQzNi42NzIgMTYwIDMzNC4yMjQgMTYwIDMyNy4zMjhjMC0yMC42NzIgMS4xNTItMzguNzM2IDI2LjA0OC0zOC43MzYgNi4yMDggMCAyMS42IDYuMDY0IDIzLjcxMiAxNy4xNjggMTEuNjQ4IDYyLjAzMiAxNi42ODggMTIwLjUxMiAyOS4xNjggMTg1Ljk2OCAxLjg1NiAyLjkyOCAxLjUwNCA3LjAwOCA0LjU2IDEwLjQzMiAzLjE1Mi0xMC4yODggNjYuOTI4LTE2OC43ODQgOTQuOTYtMTY4Ljc4NCAyMi41NDQgMCAzMC40IDQ0LjU5MiAzMy41MzYgNjEuODI0IDYuMjA4IDIwLjY1NiAxMy4wODggNTUuMjE2IDIyLjQxNiA4Mi43NTIgMC0xMy43NzYgMTIuNDgtMjAzLjEyIDY1LjM5Mi0yMDMuMTIgMTguNTkyLjAzMiAyNi43MDQgNi45MjggMjYuNzA0IDI3LjU2OHpNODcwLjMyIDQyMi45MjhjMCA1NS4wODgtMzEuMDg4IDE1NC44OC0xMDIuNjQgMTU0Ljg4LTYuMTkyIDAtMTguNDQ4LTMuNjE2LTI1LjQyNC02LjAxNi0zMi40MzItMTEuMTY4LTUwLjE3Ni00OS42OTYtNTIuMjg4LTY2LjI1NiAwIDAtMy44ODgtMTcuOTItMy44ODgtNDAuODk2czMuODg4LTQ1LjE4NCAzLjg4OC00NS4xODRjMTUuNTUyLTc1LjcyOCA0My40ODgtMTA2LjczNiA5Ni4zODQtMTA2LjczNiA1OS4xMDQtLjAzMiA4My45NjggNTguNTI4IDgzLjk2OCAxMTAuMjA4eiIvPjwvc3ZnPg==';
			$menu_url = 'https://wordpress.com/woocommerce-installation/' . $this->domain;

			// Only show the menu if the user has the capability to activate_plugins.
			add_menu_page( esc_attr__( 'WooCommerce', 'jetpack' ), esc_attr__( 'WooCommerce', 'jetpack' ), 'activate_plugins', $menu_url, null, $icon_url, 55 );
		}
	}

	/**
	 * AJAX handler for retrieving the upsell nudge.
	 */
	public function wp_ajax_upsell_nudge_jitm() {
		check_ajax_referer( 'upsell_nudge_jitm' );

		$nudge = $this->get_upsell_nudge();
		if ( ! $nudge ) {
			wp_die();
		}

		$link = $nudge['link'];
		if ( substr( $link, 0, 1 ) === '/' ) {
			$link = 'https://wordpress.com' . $link;
		}
		?>
		<li class="wp-not-current-submenu menu-top menu-icon-generic toplevel_page_site-notices" id="toplevel_page_site-notices">
			<a href="<?php echo esc_url( $link ); ?>" class="wp-not-current-submenu menu-top menu-icon-generic toplevel_page_site-notices">
				<div class="wp-menu-arrow">
					<div></div>
				</div>
				<div class="wp-menu-image dashicons-before dashicons-admin-generic" aria-hidden="true"><br></div>
				<div class="wp-menu-name">
					<div class="upsell_banner">
						<div class="banner__info">
							<div class="banner__title">
								<?php echo wp_kses( $nudge['content'], array() ); ?>
							</div>
						</div>
						<div class="banner__action">
							<button type="button" class="button">
								<?php echo wp_kses( $nudge['cta'], array() ); ?>
							</button>
						</div>
						<?php if ( $nudge['dismissible'] ) : ?>
							<svg xmlns="http://www.w3.org/2000/svg" data-feature_class="<?php echo esc_attr( $nudge['feature_class'] ); ?>" data-feature_id="<?php echo esc_attr( $nudge['id'] ); ?>" viewBox="0 0 24 24" class="gridicon gridicons-cross dismissible-card__close-icon" height="24" width="24"><g><path d="M18.36 19.78L12 13.41l-6.36 6.37-1.42-1.42L10.59 12 4.22 5.64l1.42-1.42L12 10.59l6.36-6.36 1.41 1.41L13.41 12l6.36 6.36z"></path></g></svg>
						<?php endif; ?>
					</div>
				</div>
			</a>
		</li>
		<?php
		wp_die();
	}

	/**
	 * Returns the first available upsell nudge.
	 * Needs to be implemented separately for each child menu class.
	 * Empty by default.
	 *
	 * @return array
	 */
	public function get_upsell_nudge() {
		return array();
	}
}
