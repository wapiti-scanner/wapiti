<?php
/**
 * Base Admin Menu file.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

use Automattic\Jetpack\Status;

/**
 * Class Base_Admin_Menu
 */
abstract class Base_Admin_Menu {
	/**
	 * Holds class instances.
	 *
	 * @var array
	 */
	protected static $instances;

	/**
	 * Whether the current request is a REST API request.
	 *
	 * @var bool
	 */
	protected $is_api_request = false;

	/**
	 * Domain of the current site.
	 *
	 * @var string
	 */
	protected $domain;

	/**
	 * The CSS classes used to hide the submenu items in navigation.
	 *
	 * @var string
	 */
	const HIDE_CSS_CLASS = 'hide-if-js';

	/**
	 * Identifier denoting that the default WordPress.com view should be used for a certain screen.
	 *
	 * @var string
	 */
	const DEFAULT_VIEW = 'default';

	/**
	 * Identifier denoting that the classic WP Admin view should be used for a certain screen.
	 *
	 * @var string
	 */
	const CLASSIC_VIEW = 'classic';

	/**
	 * Identifier denoting no preferred view has been set for a certain screen.
	 *
	 * @var string
	 */
	const UNKNOWN_VIEW = 'unknown';

	/**
	 * Base_Admin_Menu constructor.
	 */
	protected function __construct() {
		$this->is_api_request = defined( 'REST_REQUEST' ) && REST_REQUEST || isset( $_SERVER['REQUEST_URI'] ) && 0 === strpos( filter_var( wp_unslash( $_SERVER['REQUEST_URI'] ) ), '/?rest_route=%2Fwpcom%2Fv2%2Fadmin-menu' );
		$this->domain         = ( new Status() )->get_site_suffix();

		add_action( 'admin_menu', array( $this, 'reregister_menu_items' ), 99998 );
		add_action( 'admin_menu', array( $this, 'hide_parent_of_hidden_submenus' ), 99999 );

		if ( ! $this->is_api_request ) {
			add_filter( 'admin_menu', array( $this, 'override_svg_icons' ), 99999 );
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_scripts' ), 11 );
			add_action( 'admin_head', array( $this, 'set_site_icon_inline_styles' ) );
			add_action( 'in_admin_header', array( $this, 'add_dashboard_switcher' ) );
			add_action( 'admin_footer', array( $this, 'dashboard_switcher_scripts' ) );
			add_action( 'admin_menu', array( $this, 'handle_preferred_view' ), 99997 );
			add_filter( 'admin_body_class', array( $this, 'admin_body_class' ) );
			add_action( 'adminmenu', array( $this, 'inject_core_mobile_toggle' ) );
		}
	}

	/**
	 * Returns class instance.
	 *
	 * @return Admin_Menu
	 */
	public static function get_instance() {
		$class = static::class;

		if ( empty( static::$instances[ $class ] ) ) {
			static::$instances[ $class ] = new $class();
		}

		return static::$instances[ $class ];
	}

	/**
	 * Updates the menu data of the given menu slug.
	 *
	 * @param string $slug Slug of the menu to update.
	 * @param string $url New menu URL.
	 * @param string $title New menu title.
	 * @param string $cap New menu capability.
	 * @param string $icon New menu icon.
	 * @param int    $position New menu position.
	 * @return bool Whether the menu has been updated.
	 */
	public function update_menu( $slug, $url = null, $title = null, $cap = null, $icon = null, $position = null ) {
		global $menu, $submenu;

		$menu_item     = null;
		$menu_position = null;

		foreach ( $menu as $i => $item ) {
			if ( $slug === $item[2] ) {
				$menu_item     = $item;
				$menu_position = $i;
				break;
			}
		}

		if ( ! $menu_item ) {
			return false;
		}

		if ( $title ) {
			$menu_item[0] = $title;
			$menu_item[3] = esc_attr( $title );
		}

		if ( $cap ) {
			$menu_item[1] = $cap;
		}

		// Change parent slug only if there are no submenus (the slug of the 1st submenu will be used if there are submenus).
		if ( $url ) {
			$this->hide_submenu_page( $slug, $slug );

			if ( ! isset( $submenu[ $slug ] ) || ! $this->has_visible_items( $submenu[ $slug ] ) ) {
				$menu_item[2] = $url;
			}
		}

		if ( $icon ) {
			$menu_item[4] = 'menu-top';
			$menu_item[6] = $icon;
		}

		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		unset( $menu[ $menu_position ] );
		if ( $position ) {
			$menu_position = $position;
		}
		$this->set_menu_item( $menu_item, $menu_position );

		// Only add submenu when there are other submenu items.
		if ( $url && isset( $submenu[ $slug ] ) && $this->has_visible_items( $submenu[ $slug ] ) ) {
			add_submenu_page( $slug, $menu_item[3], $menu_item[0], $menu_item[1], $url, null, 0 );
		}

		return true;
	}

	/**
	 * Updates the submenus of the given menu slug.
	 *
	 * It hides the menu by adding the `hide-if-js` css class and duplicates the submenu with the new slug.
	 *
	 * @param string $slug Menu slug.
	 * @param array  $submenus_to_update Array of new submenu slugs.
	 */
	public function update_submenus( $slug, $submenus_to_update ) {
		global $submenu;

		if ( ! isset( $submenu[ $slug ] ) ) {
			return;
		}

		// This is needed for cases when the submenus to update have the same new slug.
		$submenus_to_update = array_filter(
			$submenus_to_update,
			static function ( $item, $old_slug ) {
				return $item !== $old_slug;
			},
			ARRAY_FILTER_USE_BOTH
		);

		/**
		 * Iterate over all submenu items and add the hide the submenus with CSS classes.
		 * This is done separately of the second foreach because the position of the submenu might change.
		 */
		foreach ( $submenu[ $slug ] as $index => $item ) {
			if ( ! array_key_exists( $item[2], $submenus_to_update ) ) {
				continue;
			}

			$this->hide_submenu_element( $index, $slug, $item );
		}

		$submenu_items = array_values( $submenu[ $slug ] );

		/**
		 * Iterate again over the submenu array. We need a copy of the array because add_submenu_page will add new elements
		 * to submenu array that might cause an infinite loop.
		 */
		foreach ( $submenu_items as $i => $submenu_item ) {
			if ( ! array_key_exists( $submenu_item[2], $submenus_to_update ) ) {
				continue;
			}

			add_submenu_page(
				$slug,
				isset( $submenu_item[3] ) ? $submenu_item[3] : '',
				isset( $submenu_item[0] ) ? $submenu_item[0] : '',
				isset( $submenu_item[1] ) ? $submenu_item[1] : 'read',
				$submenus_to_update[ $submenu_item[2] ],
				'',
				0 === $i ? 0 : $i + 1
			);
		}
	}

	/**
	 * Adds a menu separator.
	 *
	 * @param int    $position The position in the menu order this item should appear.
	 * @param string $cap Optional. The capability required for this menu to be displayed to the user.
	 *                         Default: 'read'.
	 */
	public function add_admin_menu_separator( $position = null, $cap = 'read' ) {
		$menu_item = array(
			'',                                  // Menu title (ignored).
			$cap,                                // Required capability.
			wp_unique_id( 'separator-custom-' ), // URL or file (ignored, but must be unique).
			'',                                  // Page title (ignored).
			'wp-menu-separator',                 // CSS class. Identifies this item as a separator.
		);

		$this->set_menu_item( $menu_item, $position );
	}

	/**
	 * Enqueues scripts and styles.
	 */
	public function enqueue_scripts() {
		if ( $this->is_rtl() ) {
			$css_path = 'admin-menu-rtl.css';
		} else {
			$css_path = 'admin-menu.css';
		}

		wp_enqueue_style(
			'jetpack-admin-menu',
			plugins_url( $css_path, __FILE__ ),
			array(),
			JETPACK__VERSION
		);

		wp_style_add_data( 'jetpack-admin-menu', 'rtl', $this->is_rtl() );
		$this->configure_colors_for_rtl_stylesheets();

		wp_enqueue_script(
			'jetpack-admin-menu',
			plugins_url( 'admin-menu.js', __FILE__ ),
			array(),
			JETPACK__VERSION,
			true
		);

		wp_localize_script(
			'jetpack-admin-menu',
			'jetpackAdminMenu',
			array(
				'upsellNudgeJitm'  => wp_create_nonce( 'upsell_nudge_jitm' ),
				'jitmDismissNonce' => wp_create_nonce( 'jitm_dismiss' ),
			)
		);
	}

	/**
	 * Mark the core colors stylesheets as RTL depending on the value from the environment.
	 * This fixes a core issue where the extra RTL data is not added to the colors stylesheet.
	 * https://core.trac.wordpress.org/ticket/53090
	 */
	public function configure_colors_for_rtl_stylesheets() {
		wp_style_add_data( 'colors', 'rtl', $this->is_rtl() );
	}

	/**
	 * Injects inline-styles for site icon for when third-party plugins remove enqueued stylesheets.
	 * Unable to use wp_add_inline_style as plugins remove styles from all non-standard handles
	 */
	public function set_site_icon_inline_styles() {
		echo '<style>
			#adminmenu .toplevel_page_site-card .wp-menu-image,
			#adminmenu .toplevel_page_site-card .wp-menu-image img {
				height: 32px;
				width: 32px;
			}
		</style>';
	}

	/**
	 * Hide the submenu page based on slug and return the item that was hidden.
	 *
	 * Instead of actually removing the submenu item, a safer approach is to hide it and filter it in the API response.
	 * In this manner we'll avoid breaking third-party plugins depending on items that no longer exist.
	 *
	 * A false|array value is returned to be consistent with remove_submenu_page() function
	 *
	 * @param string $menu_slug The parent menu slug.
	 * @param string $submenu_slug The submenu slug that should be hidden.
	 * @return false|array
	 */
	public function hide_submenu_page( $menu_slug, $submenu_slug ) {
		global $submenu;

		if ( ! isset( $submenu[ $menu_slug ] ) ) {
			return false;
		}

		foreach ( $submenu[ $menu_slug ] as $i => $item ) {
			if ( $submenu_slug !== $item[2] ) {
				continue;
			}

			$this->hide_submenu_element( $i, $menu_slug, $item );

			return $item;
		}

		return false;
	}

	/**
	 * Apply the hide-if-js CSS class to a submenu item.
	 *
	 * @param int    $index The position of a submenu item in the submenu array.
	 * @param string $parent_slug The parent slug.
	 * @param array  $item The submenu item.
	 */
	public function hide_submenu_element( $index, $parent_slug, $item ) {
		global $submenu;

		$css_classes = empty( $item[4] ) ? self::HIDE_CSS_CLASS : $item[4] . ' ' . self::HIDE_CSS_CLASS;

		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$submenu [ $parent_slug ][ $index ][4] = $css_classes;
	}

	/**
	 * Check if the menu has submenu items visible
	 *
	 * @param array $submenu_items The submenu items.
	 * @return bool
	 */
	public function has_visible_items( $submenu_items ) {
		$visible_items = array_filter(
			$submenu_items,
			array( $this, 'is_item_visible' )
		);

		return array() !== $visible_items;
	}

	/**
	 * Return the number of existing submenu items under the supplied parent slug.
	 *
	 * @param string $parent_slug The slug of the parent menu.
	 * @return int The number of submenu items under $parent_slug.
	 */
	public function get_submenu_item_count( $parent_slug ) {
		global $submenu;

		if ( empty( $parent_slug ) || empty( $submenu[ $parent_slug ] ) || ! is_array( $submenu[ $parent_slug ] ) ) {
			return 0;
		}

		return count( $submenu[ $parent_slug ] );
	}

	/**
	 * Adds the given menu item in the specified position.
	 *
	 * @param array $item The menu item to add.
	 * @param int   $position The position in the menu order this item should appear.
	 */
	public function set_menu_item( $item, $position = null ) {
		global $menu;

		// Handle position (avoids overwriting menu items already populated in the given position).
		// Inspired by https://core.trac.wordpress.org/browser/trunk/src/wp-admin/menu.php?rev=49837#L160.
		if ( null === $position ) {
			$menu[] = $item; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		} elseif ( isset( $menu[ "$position" ] ) ) {
			$position            = $position + substr( base_convert( md5( $item[2] . $item[0] ), 16, 10 ), -5 ) * 0.00001;
			$menu[ "$position" ] = $item; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		} else {
			$menu[ $position ] = $item; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		}
	}

	/**
	 * Determines whether the current locale is right-to-left (RTL).
	 */
	public function is_rtl() {
		return is_rtl();
	}

	/**
	 * Checks for any SVG icons in the menu, and overrides things so that
	 * we can display the icon in the correct colour for the theme.
	 */
	public function override_svg_icons() {
		global $menu;

		$svg_items = array();
		foreach ( $menu as $idx => $menu_item ) {
			// Menu items that don't have icons, for example separators, have less than 7
			// elements, partly because the 7th is the icon. So, if we have less than 7,
			// let's skip it.
			if ( count( $menu_item ) < 7 ) {
				continue;
			}

			// If the hookname contain a URL than sanitize it by replacing invalid characters.
			if ( false !== strpos( $menu_item[5], '://' ) ) {
				$menu_item[5] = preg_replace( '![:/.]+!', '_', $menu_item[5] );
			}

			if ( 0 === strpos( $menu_item[6], 'data:image/svg+xml' ) && 'site-card' !== $menu_item[3] ) {
				$svg_items[]   = array(
					'icon' => $menu_item[6],
					'id'   => $menu_item[5],
				);
				$menu_item[4] .= ' menu-svg-icon';
				$menu_item[6]  = 'none';
			}
			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			$menu[ $idx ] = $menu_item;
		}
		if ( count( $svg_items ) > 0 ) {
			$styles = '.menu-svg-icon .wp-menu-image { background-repeat: no-repeat; background-position: center center } ';
			foreach ( $svg_items as $svg_item ) {
				$styles .= sprintf( '#%s .wp-menu-image { background-image: url( "%s" ) }', $svg_item['id'], $svg_item['icon'] );
			}
			$styles .= '@supports ( mask-image: none ) or ( -webkit-mask-image: none ) { ';
			$styles .= '.menu-svg-icon .wp-menu-image { background-image: none; } ';
			$styles .= '.menu-svg-icon .wp-menu-image::before { background-color: currentColor; ';
			$styles .= 'mask-size: contain; mask-position: center center; mask-repeat: no-repeat; ';
			$styles .= '-webkit-mask-size: contain; -webkit-mask-position: center center; -webkit-mask-repeat: no-repeat; content:"" } ';
			foreach ( $svg_items as $svg_item ) {
				$styles .= sprintf(
					'#%s .wp-menu-image { background-image: none; } #%s .wp-menu-image::before{ mask-image: url( "%s" ); -webkit-mask-image: url( "%s" ) }',
					$svg_item['id'],
					$svg_item['id'],
					$svg_item['icon'],
					$svg_item['icon']
				);
			}
			$styles .= '}';

			wp_register_style( 'svg-menu-overrides', false, array(), '20210331' );
			wp_enqueue_style( 'svg-menu-overrides' );
			wp_add_inline_style( 'svg-menu-overrides', $styles );
		}
	}

	/**
	 * Hide menus that are unauthorized and don't have visible submenus and cases when the menu has the same slug
	 * as the first submenu item.
	 *
	 * This must be done at the end of menu and submenu manipulation in order to avoid performing this check each time
	 * the submenus are altered.
	 */
	public function hide_parent_of_hidden_submenus() {
		global $menu, $submenu;

		$this->sort_hidden_submenus();

		foreach ( $menu as $menu_index => $menu_item ) {
			$has_submenus = isset( $submenu[ $menu_item[2] ] );

			// Skip if the menu doesn't have submenus.
			if ( ! $has_submenus ) {
				continue;
			}

			// If the first submenu item is hidden then we should also hide the parent.
			// Since the submenus are ordered by self::HIDE_CSS_CLASS (hidden submenus should be at the end of the array),
			// we can say that if the first submenu is hidden then we should also hide the menu.
			$first_submenu_item       = array_values( $submenu[ $menu_item[2] ] )[0];
			$is_first_submenu_visible = $this->is_item_visible( $first_submenu_item );

			// if the user does not have access to the menu and the first submenu is hidden, then hide the menu.
			if ( ! current_user_can( $menu_item[1] ) && ! $is_first_submenu_visible ) {
				// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				$menu[ $menu_index ][4] = self::HIDE_CSS_CLASS;
			}

			// if the menu has the same slug as the first submenu then hide the submenu.
			if ( $menu_item[2] === $first_submenu_item[2] && ! $is_first_submenu_visible ) {
				// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				$menu[ $menu_index ][4] = self::HIDE_CSS_CLASS;
			}
		}
	}

	/**
	 * Sort the hidden submenus by moving them at the end of the array in order to avoid WP using them as default URLs.
	 *
	 * This operation has to be done at the end of submenu manipulation in order to guarantee that the hidden submenus
	 * are at the end of the array.
	 */
	public function sort_hidden_submenus() {
		global $submenu;

		foreach ( $submenu as $menu_slug => $submenu_items ) {
			foreach ( $submenu_items as $submenu_index => $submenu_item ) {
				if ( $this->is_item_visible( $submenu_item ) ) {
					continue;
				}

				unset( $submenu[ $menu_slug ][ $submenu_index ] );
				// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				$submenu[ $menu_slug ][] = $submenu_item;
			}
		}
	}

	/**
	 * Check if the given item is visible or not in the admin menu.
	 *
	 * @param array $item A menu or submenu array.
	 */
	public function is_item_visible( $item ) {
		return ! isset( $item[4] ) || false === strpos( $item[4], self::HIDE_CSS_CLASS );
	}

	/**
	 * Adds a dashboard switcher to the list of screen meta links of the current page.
	 */
	public function add_dashboard_switcher() {
		$menu_mappings = require __DIR__ . '/menu-mappings.php';
		$screen        = $this->get_current_screen();

		// Let's show the switcher only in screens that we have a Calypso mapping to switch to.
		if ( empty( $menu_mappings[ $screen ] ) ) {
			return;
		}
		?>
		<div id="view-link-wrap" class="hide-if-no-js screen-meta-toggle">
			<button type="button" id="view-link" class="button show-settings" aria-expanded="false"><?php echo esc_html_x( 'View', 'View options to switch between', 'jetpack' ); ?></button>
		</div>
		<div id="view-wrap" class="screen-options-tab__wrapper hide-if-no-js hidden" tabindex="-1">
			<div class="screen-options-tab__dropdown" data-testid="screen-options-dropdown">
				<div class="screen-switcher">
					<a class="screen-switcher__button" href="<?php echo esc_url( add_query_arg( 'preferred-view', 'default' ) ); ?>" data-view="default">
						<strong><?php esc_html_e( 'Default view', 'jetpack' ); ?></strong>
						<?php esc_html_e( 'Our WordPress.com redesign for a better experience.', 'jetpack' ); ?>
					</a>
					<button class="screen-switcher__button"  data-view="classic">
						<strong><?php esc_html_e( 'Classic view', 'jetpack' ); ?></strong>
						<?php esc_html_e( 'The classic WP-Admin WordPress interface.', 'jetpack' ); ?>
					</button>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Adds a script to append the dashboard switcher to screen meta
	 */
	public function dashboard_switcher_scripts() {
		wp_add_inline_script(
			'common',
			"(function( $ ) {
				$( '#view-link-wrap' ).appendTo( '#screen-meta-links' );

				var viewLink = $( '#view-link' );
				var viewWrap = $( '#view-wrap' );

				viewLink.on( 'click', function() {
					viewWrap.toggle();
					viewLink.toggleClass( 'screen-meta-active' );
				} );

				$( document ).on( 'mouseup', function( event ) {
					if ( ! viewLink.is( event.target ) && ! viewWrap.is( event.target ) && viewWrap.has( event.target ).length === 0 ) {
						viewWrap.hide();
						viewLink.removeClass( 'screen-meta-active' );
					}
				});
			})( jQuery );"
		);
	}

	/**
	 * Sets the given view as preferred for the givens screen.
	 *
	 * @param string $screen Screen identifier.
	 * @param string $view Preferred view.
	 */
	public function set_preferred_view( $screen, $view ) {
		$preferred_views            = $this->get_preferred_views();
		$screen                     = str_replace( '?post_type=post', '', $screen );
		$preferred_views[ $screen ] = $view;
		update_user_option( get_current_user_id(), 'jetpack_admin_menu_preferred_views', $preferred_views );
	}

	/**
	 * Get the preferred views for all screens.
	 *
	 * @return array
	 */
	public function get_preferred_views() {
		$preferred_views = get_user_option( 'jetpack_admin_menu_preferred_views' );

		if ( ! $preferred_views ) {
			return array();
		}

		return $preferred_views;
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
		$preferred_views = $this->get_preferred_views();

		if ( ! isset( $preferred_views[ $screen ] ) ) {
			if ( ! $fallback_global_preference ) {
				return self::UNKNOWN_VIEW;
			}
			return $this->should_link_to_wp_admin() ? self::CLASSIC_VIEW : self::DEFAULT_VIEW;
		}

		return $preferred_views[ $screen ];
	}

	/**
	 * Gets the identifier of the current screen.
	 *
	 * @return string
	 */
	public function get_current_screen() {
		// phpcs:disable WordPress.Security.NonceVerification
		global $pagenow;
		$screen = isset( $_REQUEST['screen'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['screen'] ) ) : $pagenow;
		if ( isset( $_GET['post_type'] ) ) {
			$screen = add_query_arg( 'post_type', sanitize_text_field( wp_unslash( $_GET['post_type'] ) ), $screen );
		}
		if ( isset( $_GET['taxonomy'] ) ) {
			$screen = add_query_arg( 'taxonomy', sanitize_text_field( wp_unslash( $_GET['taxonomy'] ) ), $screen );
		}
		if ( isset( $_GET['page'] ) ) {
			$screen = add_query_arg( 'page', sanitize_text_field( wp_unslash( $_GET['page'] ) ), $screen );
		}
		return $screen;
		// phpcs:enable WordPress.Security.NonceVerification
	}

	/**
	 * Stores the preferred view for the current screen.
	 */
	public function handle_preferred_view() {
		// phpcs:disable WordPress.Security.NonceVerification
		if ( ! isset( $_GET['preferred-view'] ) ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification
		$preferred_view = sanitize_key( $_GET['preferred-view'] );

		if ( ! in_array( $preferred_view, array( self::DEFAULT_VIEW, self::CLASSIC_VIEW ), true ) ) {
			return;
		}

		$current_screen = $this->get_current_screen();

		$this->set_preferred_view( $current_screen, $preferred_view );

		/**
		 * Dashboard Quick switcher action triggered when a user switches to a different view.
		 *
		 * @module masterbar
		 *
		 * @since 9.9.1
		 *
		 * @param string The current screen of the user.
		 * @param string The preferred view the user selected.
		 */
		\do_action( 'jetpack_dashboard_switcher_changed_view', $current_screen, $preferred_view );

		if ( self::DEFAULT_VIEW === $preferred_view ) {
			// Redirect to default view if that's the newly preferred view.
			$menu_mappings = require __DIR__ . '/menu-mappings.php';
			if ( isset( $menu_mappings[ $current_screen ] ) ) {
				// Using `wp_redirect` intentionally because we're redirecting to Calypso.
				wp_redirect( $menu_mappings[ $current_screen ] . $this->domain ); // phpcs:ignore WordPress.Security.SafeRedirect
				exit;
			}
		} elseif ( self::CLASSIC_VIEW === $preferred_view ) {
			// Removes the `preferred-view` param from the URL to avoid issues with
			// screens that don't expect this param to be present in the URL.
			wp_safe_redirect( remove_query_arg( 'preferred-view' ) );
			exit;
		}
		// phpcs:enable WordPress.Security.NonceVerification
	}

	/**
	 * Adds the necessary CSS class to the admin body class.
	 *
	 * @param string $admin_body_classes Contains all the admin body classes.
	 *
	 * @return string
	 */
	public function admin_body_class( $admin_body_classes ) {
		return " is-nav-unification $admin_body_classes ";
	}

	/**
	 * Whether to use wp-admin pages rather than Calypso.
	 *
	 * Options:
	 * false - Calypso (Default).
	 * true  - wp-admin.
	 *
	 * @return bool
	 */
	public function should_link_to_wp_admin() {
		return get_user_option( 'jetpack_admin_menu_link_destination' );
	}

	/**
	 * Injects the core's mobile toggle for proper positioning of the submenus.
	 *
	 * @see https://core.trac.wordpress.org/ticket/32747
	 *
	 * @return void
	 */
	public function inject_core_mobile_toggle() {
		echo '<span id="wp-admin-bar-menu-toggle" style="display: none!important">';
	}

	/**
	 * Create the desired menu output.
	 */
	abstract public function reregister_menu_items();
}
