<?php
/**
 * Masterbar file.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Device_Detection\User_Agent_Info;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Scan\Admin_Bar_Notice;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Status\Host;
use GP_Locale;
use GP_Locales;
use Jetpack;
use Jetpack_AMP_Support;
use Jetpack_Plan;
use WP_Admin_Bar;

/**
 * Provides custom admin bar instead of the default WordPress admin bar.
 */
class Masterbar {
	/**
	 * Use for testing changes made to remotely enqueued scripts and styles on your sandbox.
	 * If not set it will default to loading the ones from WordPress.com.
	 *
	 * @var string $sandbox_url
	 */
	private $sandbox_url = '';

	/**
	 * Current locale.
	 *
	 * @var string
	 */
	private $locale;

	/**
	 * WordPress.com user locale of the connected user.
	 *
	 * @var string
	 */
	private $user_locale;

	/**
	 * Current User ID.
	 *
	 * @var int
	 */
	private $user_id;
	/**
	 * WordPress.com user data of the connected user.
	 *
	 * @var array
	 */
	private $user_data;
	/**
	 * WordPress.com username for the connected user.
	 *
	 * @var string
	 */
	private $user_login;
	/**
	 * WordPress.com email address for the connected user.
	 *
	 * @var string
	 */
	private $user_email;
	/**
	 * WordPress.com display name for the connected user.
	 *
	 * @var string
	 */
	private $display_name;
	/**
	 * Site URL sanitized for usage in WordPress.com slugs.
	 *
	 * @var string
	 */
	private $primary_site_slug;
	/**
	 * Whether the text direction is RTL (based on connected WordPress.com user's interface settings).
	 *
	 * @var boolean
	 */
	private $is_rtl;
	/**
	 * Number of sites owned by connected WordPress.com user.
	 *
	 * @var int
	 */
	private $user_site_count;
	/**
	 * If the site is hosted on WordPress.com on Atomic
	 *
	 * @var bool
	 */
	private $site_woa;

	/**
	 * Constructor
	 */
	public function __construct() {
		$this->user_id      = get_current_user_id();
		$connection_manager = new Connection_Manager( 'jetpack' );

		if ( ! $connection_manager->is_user_connected( $this->user_id ) ) {
			return;
		}

		$this->user_data       = $connection_manager->get_connected_user_data( $this->user_id );
		$this->user_login      = isset( $this->user_data['login'] ) ? $this->user_data['login'] : '';
		$this->user_email      = isset( $this->user_data['email'] ) ? $this->user_data['email'] : '';
		$this->display_name    = isset( $this->user_data['display_name'] ) ? $this->user_data['display_name'] : '';
		$this->user_site_count = isset( $this->user_data['site_count'] ) ? $this->user_data['site_count'] : '';
		$this->is_rtl          = isset( $this->user_data['text_direction'] ) && 'rtl' === $this->user_data['text_direction'];
		$this->user_locale     = isset( $this->user_data['user_locale'] ) ? $this->user_data['user_locale'] : '';
		$this->site_woa        = ( new Host() )->is_woa_site();

		// Store part of the connected user data as user options so it can be used
		// by other files of the masterbar module without making another XMLRPC
		// request. Although `get_connected_user_data` tries to save the data for
		// future uses on a transient, the data is not guaranteed to be cached.
		update_user_option( $this->user_id, 'jetpack_wpcom_is_rtl', $this->is_rtl ? '1' : '0' );
		if ( isset( $this->user_data['use_wp_admin_links'] ) ) {
			update_user_option( $this->user_id, 'jetpack_admin_menu_link_destination', $this->user_data['use_wp_admin_links'] ? '1' : '0' );
		}
		// If Atomic, store and install user locale.
		if ( $this->site_woa ) {
			$this->user_locale = $this->get_jetpack_locale( $this->user_locale );
			$this->install_locale( $this->user_locale );
			update_user_option( $this->user_id, 'locale', $this->user_locale, true );
		}

		add_action( 'admin_bar_init', array( $this, 'init' ) );

		if ( ! empty( $this->user_data['ID'] ) ) {
			// Post logout on the site, also log the user out of WordPress.com.
			add_filter( 'logout_redirect', array( $this, 'maybe_logout_user_from_wpcom' ) );
		}
	}

	/**
	 * Initialize our masterbar.
	 */
	public function init() {
		$this->locale = $this->get_locale();

		// Don't show the masterbar on WordPress mobile apps.
		if ( User_Agent_Info::is_mobile_app() ) {
			add_filter( 'show_admin_bar', '__return_false' );
			return;
		}

		// Disable the Masterbar on AMP views.
		if (
			class_exists( 'Jetpack_AMP_Support' )
			&& Jetpack_AMP_Support::is_amp_available()
			&& Jetpack_AMP_Support::is_amp_request()
		) {
			return;
		}

		Assets::add_resource_hint(
			array(
				'//s0.wp.com',
				'//0.gravatar.com',
				'//1.gravatar.com',
				'//2.gravatar.com',
			),
			'dns-prefetch'
		);

		// WordPress.com on Atomic only.
		if ( $this->site_woa ) {
			/*
			 * override user setting that hides masterbar from site's front.
			 * https://github.com/Automattic/jetpack/issues/7667
			 */
			add_filter( 'show_admin_bar', '__return_true' );
		}

		// Used to build menu links that point directly to Calypso.
		$this->primary_site_slug = ( new Status() )->get_site_suffix();

		// Used for display purposes and for building WP Admin links.
		$this->primary_site_url = str_replace( '::', '/', $this->primary_site_slug );

		add_filter( 'admin_body_class', array( $this, 'admin_body_class' ) );

		add_action( 'wp_before_admin_bar_render', array( $this, 'replace_core_masterbar' ), 99999 );

		add_action( 'wp_enqueue_scripts', array( $this, 'add_styles_and_scripts' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'add_styles_and_scripts' ) );

		add_action( 'wp_enqueue_scripts', array( $this, 'remove_core_styles' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'remove_core_styles' ) );

		if ( Jetpack::is_module_active( 'notes' ) && $this->is_rtl ) {
			// Override Notification module to include RTL styles.
			add_action( 'a8c_wpcom_masterbar_enqueue_rtl_notification_styles', '__return_true' );
		}

		// Hides and replaces the language dropdown for the current user, on WoA.
		if ( $this->site_woa &&
			defined( 'IS_PROFILE_PAGE' ) && IS_PROFILE_PAGE ) {
			add_action( 'user_edit_form_tag', array( $this, 'hide_language_dropdown' ) );
			add_action( 'personal_options', array( $this, 'replace_language_dropdown' ), 9 );
		}
	}

	/**
	 * Log out from WordPress.com when logging out of the local site.
	 *
	 * @param string $redirect_to The redirect destination URL.
	 */
	public function maybe_logout_user_from_wpcom( $redirect_to ) {
		/**
		 * Whether we should sign out from wpcom too when signing out from the masterbar.
		 *
		 * @since 5.9.0
		 *
		 * @param bool $masterbar_should_logout_from_wpcom True by default.
		 */
		$masterbar_should_logout_from_wpcom = apply_filters( 'jetpack_masterbar_should_logout_from_wpcom', true );
		if (
			// No need to check for a nonce here, it happens further up.
			isset( $_GET['context'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			&& 'masterbar' === $_GET['context'] // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			&& $masterbar_should_logout_from_wpcom
		) {
			/**
			 * Hook into the log out event happening from the Masterbar.
			 *
			 * @since 5.1.0
			 * @since 7.9.0 Added the $wpcom_user_id parameter to the action.
			 *
			 * @module masterbar
			 *
			 * @param int $wpcom_user_id WordPress.com User ID.
			 */
			do_action( 'wp_masterbar_logout', $this->user_data['ID'] );
		}

		return $redirect_to;
	}

	/**
	 * Adds CSS classes to admin body tag.
	 *
	 * @since 5.1
	 *
	 * @param string $admin_body_classes CSS classes that will be added.
	 *
	 * @return string
	 */
	public function admin_body_class( $admin_body_classes ) {
		return "$admin_body_classes jetpack-masterbar";
	}

	/**
	 * Remove the default Admin Bar CSS.
	 */
	public function remove_core_styles() {
		/*
		 * Notifications need the admin bar styles,
		 * so let's not remove them when the module is active.
		 */
		if ( ! Jetpack::is_module_active( 'notes' ) ) {
			wp_dequeue_style( 'admin-bar' );
		}
	}

	/**
	 * Enqueue our own CSS and JS to display our custom admin bar.
	 */
	public function add_styles_and_scripts() {

		if ( $this->is_rtl ) {
			wp_enqueue_style( 'a8c-wpcom-masterbar-rtl', $this->wpcom_static_url( '/wp-content/mu-plugins/admin-bar/rtl/wpcom-admin-bar-rtl.css' ), array(), JETPACK__VERSION );
			wp_enqueue_style( 'a8c-wpcom-masterbar-overrides-rtl', $this->wpcom_static_url( '/wp-content/mu-plugins/admin-bar/masterbar-overrides/rtl/masterbar-rtl.css' ), array(), JETPACK__VERSION );
		} else {
			wp_enqueue_style( 'a8c-wpcom-masterbar', $this->wpcom_static_url( '/wp-content/mu-plugins/admin-bar/wpcom-admin-bar.css' ), array(), JETPACK__VERSION );
			wp_enqueue_style( 'a8c-wpcom-masterbar-overrides', $this->wpcom_static_url( '/wp-content/mu-plugins/admin-bar/masterbar-overrides/masterbar.css' ), array(), JETPACK__VERSION );
		}

		// Local overrides.
		wp_enqueue_style( 'a8c_wpcom_css_override', plugins_url( 'overrides.css', __FILE__ ), array(), JETPACK__VERSION );

		if ( ! Jetpack::is_module_active( 'notes ' ) ) {
			// Masterbar is relying on some icons from noticons.css.
			wp_enqueue_style( 'noticons', $this->wpcom_static_url( '/i/noticons/noticons.css' ), array(), JETPACK__VERSION . '-' . gmdate( 'oW' ) );
		}

		wp_enqueue_script(
			'jetpack-accessible-focus',
			Assets::get_file_url_for_environment( '_inc/build/accessible-focus.min.js', '_inc/accessible-focus.js' ),
			array(),
			JETPACK__VERSION,
			false
		);
		wp_enqueue_script(
			'a8c_wpcom_masterbar_tracks_events',
			Assets::get_file_url_for_environment(
				'_inc/build/masterbar/masterbar/tracks-events.min.js',
				'modules/masterbar/masterbar/tracks-events.js'
			),
			array(),
			JETPACK__VERSION,
			false
		);

		wp_enqueue_script(
			'a8c_wpcom_masterbar_overrides',
			$this->wpcom_static_url( '/wp-content/mu-plugins/admin-bar/masterbar-overrides/masterbar.js' ),
			array( 'jquery' ),
			JETPACK__VERSION,
			false
		);
	}

	/**
	 * Get base URL where our CSS and JS will come from.
	 *
	 * @param string $file File path for a static resource.
	 */
	private function wpcom_static_url( $file ) {
		if ( ! empty( $this->sandbox_url ) ) {
			// For testing undeployed changes to remotely enqueued scripts and styles.
			return set_url_scheme( $this->sandbox_url . $file, 'https' );
		}

		$url = 'https://s0.wp.com' . $file;

		return set_url_scheme( $url, 'https' );
	}

	/**
	 * Remove the default admin bar items and replace it with our own admin bar.
	 */
	public function replace_core_masterbar() {
		global $wp_admin_bar;

		if ( ! is_object( $wp_admin_bar ) ) {
			return false;
		}

		$this->clear_core_masterbar( $wp_admin_bar );
		$this->build_wpcom_masterbar( $wp_admin_bar );
	}

	/**
	 * Remove all existing toolbar entries from core Masterbar
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin Bar instance.
	 */
	public function clear_core_masterbar( $wp_admin_bar ) {
		foreach ( $wp_admin_bar->get_nodes() as $node ) {
			$wp_admin_bar->remove_node( $node->id );
		}
	}

	/**
	 * Add entries corresponding to WordPress.com Masterbar
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin Bar instance.
	 */
	public function build_wpcom_masterbar( $wp_admin_bar ) {
		// Menu groups.
		$this->wpcom_adminbar_add_secondary_groups( $wp_admin_bar );

		// Left part.
		$this->add_my_sites_submenu( $wp_admin_bar );
		$this->add_reader_submenu( $wp_admin_bar );

		// Right part.
		if ( Jetpack::is_module_active( 'notes' ) ) {
			$this->add_notifications( $wp_admin_bar );
		}

		$this->add_me_submenu( $wp_admin_bar );
		$this->add_write_button( $wp_admin_bar );

		// Recovery mode exit.
		if ( function_exists( 'wp_admin_bar_recovery_mode_menu' ) ) {
			wp_admin_bar_recovery_mode_menu( $wp_admin_bar );
		}

		if ( class_exists( 'Automattic\Jetpack\Scan\Admin_Bar_Notice' ) ) {
			$scan_admin_bar_notice = Admin_Bar_Notice::instance();
			$scan_admin_bar_notice->add_threats_to_toolbar( $wp_admin_bar );
		}
	}

	/**
	 * Get WordPress.com current locale name.
	 */
	public function get_locale() {
		$wpcom_locale = get_locale();

		if ( ! class_exists( 'GP_Locales' ) ) {
			if ( defined( 'JETPACK__GLOTPRESS_LOCALES_PATH' ) && file_exists( JETPACK__GLOTPRESS_LOCALES_PATH ) ) {
				require JETPACK__GLOTPRESS_LOCALES_PATH;
			}
		}

		if ( class_exists( 'GP_Locales' ) ) {
			$wpcom_locale_object = GP_Locales::by_field( 'wp_locale', get_locale() );
			if ( $wpcom_locale_object instanceof GP_Locale ) {
				$wpcom_locale = $wpcom_locale_object->slug;
			}
		}

		return $wpcom_locale;
	}

	/**
	 * Get Jetpack locale name.
	 *
	 * @param  string $slug Locale slug.
	 * @return string Jetpack locale.
	 */
	public function get_jetpack_locale( $slug = '' ) {
		if ( ! class_exists( 'GP_Locales' ) ) {
			if ( defined( 'JETPACK__GLOTPRESS_LOCALES_PATH' ) && file_exists( JETPACK__GLOTPRESS_LOCALES_PATH ) ) {
				require JETPACK__GLOTPRESS_LOCALES_PATH;
			}
		}

		if ( class_exists( 'GP_Locales' ) ) {
			$jetpack_locale_object = GP_Locales::by_field( 'slug', $slug );
			if ( $jetpack_locale_object instanceof GP_Locale ) {
				$jetpack_locale = $jetpack_locale_object->wp_locale ? $jetpack_locale_object->wp_locale : 'en_US';
			}
		}

		if ( isset( $jetpack_locale ) ) {
			return $jetpack_locale;
		}

		return 'en_US';
	}

	/**
	 * Install locale if not yet available.
	 *
	 * @param string $locale The new locale slug.
	 */
	public function install_locale( $locale = '' ) {
		if ( ! in_array( $locale, get_available_languages(), true )
			&& ! empty( $locale ) && current_user_can( 'install_languages' ) ) {

			if ( ! function_exists( 'wp_download_language_pack' ) ) {
				require_once ABSPATH . 'wp-admin/includes/translation-install.php';
			}

			if ( ! function_exists( 'request_filesystem_credentials' ) ) {
				require_once ABSPATH . 'wp-admin/includes/file.php';
			}

			if ( wp_can_install_language_pack() ) {
				wp_download_language_pack( $locale );
				load_default_textdomain( $locale );
			}
		}
	}

	/**
	 * Hide language dropdown on user edit form.
	 */
	public function hide_language_dropdown() {
		add_filter( 'get_available_languages', '__return_empty_array' );
	}

	/**
	 * Replace language dropdown with link to WordPress.com.
	 */
	public function replace_language_dropdown() {
		$language_row  = printf( '<tr class="user-language-wrap"><th scope="row">' );
		$language_row .= printf(
			'<label for="locale">%1$s<span class="dashicons dashicons-translation" aria-hidden="true"></span></label>',
			esc_html__( 'Language', 'jetpack' )
		);
		$language_row .= printf( '</th><td>' );
		$language_row .= printf(
			'<a target="_blank" href="%1$s">%2$s</a>',
			esc_url( 'https://wordpress.com/me/account' ),
			esc_html__( 'Set your profile language on WordPress.com.', 'jetpack' )
		);
		$language_row .= printf( '</td></tr>' );
		return $language_row;
	}

	/**
	 * Add the Notifications menu item.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin Bar instance.
	 */
	public function add_notifications( $wp_admin_bar ) {
		$wp_admin_bar->add_node(
			array(
				'id'     => 'notes',
				'title'  => '<span id="wpnt-notes-unread-count" class="wpnt-loading wpn-read"></span>
						 <span class="screen-reader-text">' . esc_html__( 'Notifications', 'jetpack' ) . '</span>
						 <span class="noticon noticon-bell"></span>',
				'meta'   => array(
					'html'  => '<div id="wpnt-notes-panel2" style="display:none" lang="' . esc_attr( $this->locale ) . '" dir="' . ( $this->is_rtl ? 'rtl' : 'ltr' ) . '">' .
								'<div class="wpnt-notes-panel-header">' .
								'<span class="wpnt-notes-header">' .
								esc_html__( 'Notifications', 'jetpack' ) .
								'</span>' .
								'<span class="wpnt-notes-panel-link">' .
								'</span>' .
								'</div>' .
								'</div>',
					'class' => 'menupop mb-trackable',
				),
				'parent' => 'top-secondary',
			)
		);
	}

	/**
	 * Add the "Reader" menu item in the root default group.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin Bar instance.
	 */
	public function add_reader_submenu( $wp_admin_bar ) {
		$wp_admin_bar->add_menu(
			array(
				'parent' => 'root-default',
				'id'     => 'newdash',
				'title'  => esc_html__( 'Reader', 'jetpack' ),
				'href'   => 'https://wordpress.com/read',
				'meta'   => array(
					'class' => 'mb-trackable',
				),
			)
		);

		/** This filter is documented in modules/masterbar.php */
		if ( apply_filters( 'jetpack_load_admin_menu_class', false ) ) {
			return;
		}

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'newdash',
				'id'     => 'streams-header',
				'title'  => esc_html_x(
					'Streams',
					'Title for Reader sub-menu that contains followed sites, likes, and search',
					'jetpack'
				),
				'meta'   => array(
					'class' => 'ab-submenu-header',
				),
			)
		);

		$following_title = $this->create_menu_item_pair(
			array(
				'url'   => Redirect::get_url( 'calypso-read' ),
				'id'    => 'wp-admin-bar-followed-sites',
				'label' => esc_html__( 'Followed Sites', 'jetpack' ),
			),
			array(
				'url'   => Redirect::get_url( 'calypso-following-edit' ),
				'id'    => 'wp-admin-bar-reader-followed-sites-manage',
				'label' => esc_html__( 'Manage', 'jetpack' ),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'newdash',
				'id'     => 'following',
				'title'  => $following_title,
				'meta'   => array( 'class' => 'inline-action' ),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'newdash',
				'id'     => 'discover-discover',
				'title'  => esc_html__( 'Discover', 'jetpack' ),
				'href'   => Redirect::get_url( 'calypso-discover' ),
				'meta'   => array(
					'class' => 'mb-icon-spacer',
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'newdash',
				'id'     => 'discover-search',
				'title'  => esc_html__( 'Search', 'jetpack' ),
				'href'   => Redirect::get_url( 'calypso-read-search' ),
				'meta'   => array(
					'class' => 'mb-icon-spacer',
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'newdash',
				'id'     => 'my-activity-my-likes',
				'title'  => esc_html__( 'My Likes', 'jetpack' ),
				'href'   => Redirect::get_url( 'calypso-activities-likes' ),
				'meta'   => array(
					'class' => 'mb-icon-spacer',
				),
			)
		);
	}

	/**
	 * Merge 2 menu items together into 2 link tags.
	 *
	 * @param array $primary   Array of menu information.
	 * @param array $secondary Array of menu information.
	 */
	public function create_menu_item_pair( $primary, $secondary ) {
		$primary_class   = 'ab-item ab-primary mb-icon';
		$secondary_class = 'ab-secondary';

		$primary_anchor   = $this->create_menu_item_anchor( $primary_class, $primary['url'], $primary['label'], $primary['id'] );
		$secondary_anchor = $this->create_menu_item_anchor( $secondary_class, $secondary['url'], $secondary['label'], $secondary['id'] );

		return $primary_anchor . $secondary_anchor;
	}

	/**
	 * Create a link tag based on information about a menu item.
	 *
	 * @param string $class Menu item CSS class.
	 * @param string $url   URL you go to when clicking on the menu item.
	 * @param string $label Menu item title.
	 * @param string $id    Menu item slug.
	 */
	public function create_menu_item_anchor( $class, $url, $label, $id ) {
		return '<a href="' . $url . '" class="' . $class . '" id="' . $id . '">' . $label . '</a>';
	}

	/**
	 * Add Secondary groups for submenu items.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin Bar instance.
	 */
	public function wpcom_adminbar_add_secondary_groups( $wp_admin_bar ) {
		$wp_admin_bar->add_group(
			array(
				'id'   => 'root-default',
				'meta' => array(
					'class' => 'ab-top-menu',
				),
			)
		);

		$wp_admin_bar->add_group(
			array(
				'parent' => 'blog',
				'id'     => 'blog-secondary',
				'meta'   => array(
					'class' => 'ab-sub-secondary',
				),
			)
		);

		$wp_admin_bar->add_group(
			array(
				'id'   => 'top-secondary',
				'meta' => array(
					'class' => 'ab-top-secondary',
				),
			)
		);
	}

	/**
	 * Add User info menu item.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin Bar instance.
	 */
	public function add_me_submenu( $wp_admin_bar ) {
		$user_id = get_current_user_id();
		if ( empty( $user_id ) ) {
			return;
		}

		$avatar = get_avatar( $this->user_email, 32, 'mm', '', array( 'force_display' => true ) );
		$class  = empty( $avatar ) ? 'mb-trackable' : 'with-avatar mb-trackable';

		// Add the 'Me' menu.
		$wp_admin_bar->add_menu(
			array(
				'id'     => 'my-account',
				'parent' => 'top-secondary',
				'title'  => $avatar . '<span class="ab-text">' . esc_html__( 'Me', 'jetpack' ) . '</span>',
				'href'   => 'https://wordpress.com/me',
				'meta'   => array(
					'class' => $class,
				),
			)
		);

		/** This filter is documented in modules/masterbar.php */
		if ( apply_filters( 'jetpack_load_admin_menu_class', false ) ) {
			return;
		}

		$id = 'user-actions';
		$wp_admin_bar->add_group(
			array(
				'parent' => 'my-account',
				'id'     => $id,
			)
		);

		$settings_url = Redirect::get_url( 'calypso-me-account' );

		$logout_url = wp_logout_url();
		$logout_url = add_query_arg( 'context', 'masterbar', $logout_url );

		$user_info  = get_avatar( $this->user_email, 128, 'mm', '', array( 'force_display' => true ) );
		$user_info .= '<span class="display-name">' . $this->display_name . '</span>';
		$user_info .= '<a class="username" href="https://gravatar.com/' . $this->user_login . '">@' . $this->user_login . '</a>';

		$user_info .= sprintf(
			'<div><a href="%s" class="ab-sign-out">%s</a></div>',
			$logout_url,
			esc_html__( 'Sign Out', 'jetpack' )
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'user-info',
				'title'  => $user_info,
				'meta'   => array(
					'class'    => 'user-info user-info-item',
					'tabindex' => -1,
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'profile-header',
				'title'  => esc_html__( 'Profile', 'jetpack' ),
				'meta'   => array(
					'class' => 'ab-submenu-header',
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'my-profile',
				'title'  => esc_html__( 'My Profile', 'jetpack' ),
				'href'   => Redirect::get_url( 'calypso-me' ),
				'meta'   => array(
					'class' => 'mb-icon',
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'account-settings',
				'title'  => esc_html__( 'Account Settings', 'jetpack' ),
				'href'   => $settings_url,
				'meta'   => array(
					'class' => 'mb-icon',
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'billing',
				'title'  => esc_html__( 'Manage Purchases', 'jetpack' ),
				'href'   => Redirect::get_url( 'calypso-me-purchases' ),
				'meta'   => array(
					'class' => 'mb-icon',
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'security',
				'title'  => esc_html__( 'Security', 'jetpack' ),
				'href'   => Redirect::get_url( 'calypso-me-security' ),
				'meta'   => array(
					'class' => 'mb-icon',
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'notifications',
				'title'  => esc_html__( 'Notifications', 'jetpack' ),
				'href'   => Redirect::get_url( 'calypso-me-notifications' ),
				'meta'   => array(
					'class' => 'mb-icon',
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'special-header',
				'title'  => esc_html_x(
					'Special',
					'Title for Me sub-menu that contains Get Apps, Next Steps, and Help options',
					'jetpack'
				),
				'meta'   => array(
					'class' => 'ab-submenu-header',
				),
			)
		);

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'get-apps',
				'title'  => esc_html__( 'Get Apps', 'jetpack' ),
				'href'   => Redirect::get_url( 'calypso-me-get-apps' ),
				'meta'   => array(
					'class' => 'mb-icon user-info-item',
				),
			)
		);

		$help_link = Redirect::get_url( 'jetpack-support' );

		if ( $this->site_woa ) {
			$help_link = Redirect::get_url( 'calypso-help' );
		}

		$wp_admin_bar->add_menu(
			array(
				'parent' => $id,
				'id'     => 'help',
				'title'  => esc_html__( 'Help', 'jetpack' ),
				'href'   => $help_link,
				'meta'   => array(
					'class' => 'mb-icon user-info-item',
				),
			)
		);
	}

	/**
	 * Add Write Menu item.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin Bar instance.
	 */
	public function add_write_button( $wp_admin_bar ) {
		$current_user = wp_get_current_user();

		$posting_blog_id = get_current_blog_id();
		if ( ! is_user_member_of_blog( get_current_user_id(), get_current_blog_id() ) ) {
			$posting_blog_id = $current_user->primary_blog;
		}

		$user_can_post = current_user_can_for_blog( $posting_blog_id, 'publish_posts' );

		if ( ! $posting_blog_id || ! $user_can_post ) {
			return;
		}

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'top-secondary',
				'id'     => 'ab-new-post',
				'href'   => admin_url( 'post-new.php' ),
				'title'  => '<span>' . esc_html__( 'Write', 'jetpack' ) . '</span>',
				'meta'   => array(
					'class' => 'mb-trackable',
				),
			)
		);
	}

	/**
	 * Add the "My Site" menu item in the root default group.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin Bar instance.
	 */
	public function add_my_sites_submenu( $wp_admin_bar ) {
		$current_user = wp_get_current_user();

		$blog_name = get_bloginfo( 'name' );
		if ( empty( $blog_name ) ) {
			$blog_name = $this->primary_site_slug;
		}

		if ( mb_strlen( $blog_name ) > 20 ) {
			$blog_name = mb_substr( html_entity_decode( $blog_name, ENT_QUOTES ), 0, 20 ) . '&hellip;';
		}

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'root-default',
				'id'     => 'blog',
				'title'  => _n( 'My Site', 'My Sites', $this->user_site_count, 'jetpack' ),
				'href'   => 'https://wordpress.com/sites/' . $this->primary_site_url,
				'meta'   => array(
					'class' => 'my-sites mb-trackable',
				),
			)
		);

		/** This filter is documented in modules/masterbar.php */
		if ( apply_filters( 'jetpack_load_admin_menu_class', false ) ) {
			return;
		}

		if ( $this->user_site_count > 1 ) {
			$wp_admin_bar->add_menu(
				array(
					'parent' => 'blog',
					'id'     => 'switch-site',
					'title'  => esc_html__( 'Switch Site', 'jetpack' ),
					'href'   => Redirect::get_url( 'calypso-sites' ),
				)
			);
		} else {
			$wp_admin_bar->add_menu(
				array(
					'parent' => 'blog',
					'id'     => 'new-site',
					'title'  => esc_html__( '+ Add New WordPress', 'jetpack' ),
					'href'   => Redirect::get_url( 'calypso-start', array( 'query' => 'ref=admin-bar-logged-in' ) ),
				)
			);
		}

		if ( is_user_member_of_blog( $current_user->ID ) ) {
			$blavatar = '';
			$class    = 'current-site';

			if ( has_site_icon() ) {
				$src      = get_site_icon_url();
				$blavatar = '<img class="avatar" src="' . esc_attr( $src ) . '" alt="Current site avatar">';
				$class    = 'has-blavatar';
			}

			$blog_info  = '<div class="ab-site-icon">' . $blavatar . '</div>';
			$blog_info .= '<span class="ab-site-title">' . esc_html( $blog_name ) . '</span>';
			$blog_info .= '<span class="ab-site-description">' . esc_html( $this->primary_site_url ) . '</span>';

			$wp_admin_bar->add_menu(
				array(
					'parent' => 'blog',
					'id'     => 'blog-info',
					'title'  => $blog_info,
					'href'   => esc_url( trailingslashit( $this->primary_site_url ) ),
					'meta'   => array(
						'class' => $class,
					),
				)
			);
		}

		// Site Preview.
		if ( is_admin() ) {
			$wp_admin_bar->add_menu(
				array(
					'parent' => 'blog',
					'id'     => 'site-view',
					'title'  => __( 'View Site', 'jetpack' ),
					'href'   => home_url(),
					'meta'   => array(
						'class'  => 'mb-icon',
						'target' => '_blank',
					),
				)
			);
		}

		$this->add_my_home_submenu_item( $wp_admin_bar );

		// Stats.
		if ( Jetpack::is_module_active( 'stats' ) && current_user_can( 'view_stats' ) ) {
			$wp_admin_bar->add_menu(
				array(
					'parent' => 'blog',
					'id'     => 'blog-stats',
					'title'  => esc_html__( 'Stats', 'jetpack' ),
					'href'   => Redirect::get_url( 'calypso-stats' ),
					'meta'   => array(
						'class' => 'mb-icon',
					),
				)
			);
		}

		if ( current_user_can( 'manage_options' ) ) {
			$wp_admin_bar->add_menu(
				array(
					'parent' => 'blog',
					'id'     => 'activity',
					'title'  => esc_html__( 'Activity', 'jetpack' ),
					'href'   => Redirect::get_url( 'calypso-activity-log' ),
					'meta'   => array(
						'class' => 'mb-icon',
					),
				)
			);
		}

		// Add Calypso plans link and plan type indicator.
		if ( is_user_member_of_blog( $current_user->ID ) && current_user_can( 'manage_options' ) ) {
			$plans_url = Redirect::get_url( 'calypso-plans' );
			$label     = esc_html__( 'Plan', 'jetpack' );
			$plan      = Jetpack_Plan::get();

			$plan_title = $this->create_menu_item_pair(
				array(
					'url'   => $plans_url,
					'id'    => 'wp-admin-bar-plan',
					'label' => $label,
				),
				array(
					'url'   => $plans_url,
					'id'    => 'wp-admin-bar-plan-badge',
					'label' => ! empty( $plan['product_name_short'] ) ? $plan['product_name_short'] : esc_html__( 'Free', 'jetpack' ),
				)
			);

			$wp_admin_bar->add_menu(
				array(
					'parent' => 'blog',
					'id'     => 'plan',
					'title'  => $plan_title,
					'meta'   => array(
						'class' => 'inline-action',
					),
				)
			);
		}

		// Publish group.
		$wp_admin_bar->add_group(
			array(
				'parent' => 'blog',
				'id'     => 'publish',
			)
		);

		// Publish header.
		$wp_admin_bar->add_menu(
			array(
				'parent' => 'publish',
				'id'     => 'publish-header',
				'title'  => esc_html_x( 'Manage', 'admin bar menu group label', 'jetpack' ),
				'meta'   => array(
					'class' => 'ab-submenu-header',
				),
			)
		);

		// Pages.
		$pages_title = $this->create_menu_item_pair(
			array(
				'url'   => Redirect::get_url( 'calypso-edit-pages' ),
				'id'    => 'wp-admin-bar-edit-page',
				'label' => esc_html__( 'Site Pages', 'jetpack' ),
			),
			array(
				'url'   => Redirect::get_url( 'calypso-edit-page' ),
				'id'    => 'wp-admin-bar-new-page-badge',
				'label' => esc_html_x( 'Add', 'admin bar menu new item label', 'jetpack' ),
			)
		);

		if ( ! current_user_can( 'edit_pages' ) ) {
			$pages_title = $this->create_menu_item_anchor(
				'ab-item ab-primary mb-icon',
				Redirect::get_url( 'calypso-edit-pages' ),
				esc_html__( 'Site Pages', 'jetpack' ),
				'wp-admin-bar-edit-page'
			);
		}

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'publish',
				'id'     => 'new-page',
				'title'  => $pages_title,
				'meta'   => array(
					'class' => 'inline-action',
				),
			)
		);

		// Blog Posts.
		$posts_title = $this->create_menu_item_pair(
			array(
				'url'   => Redirect::get_url( 'calypso-edit-posts' ),
				'id'    => 'wp-admin-bar-edit-post',
				'label' => esc_html__( 'Blog Posts', 'jetpack' ),
			),
			array(
				'url'   => Redirect::get_url( 'calypso-edit-post' ),
				'id'    => 'wp-admin-bar-new-post-badge',
				'label' => esc_html_x( 'Add', 'admin bar menu new item label', 'jetpack' ),
			)
		);

		if ( ! current_user_can( 'edit_posts' ) ) {
			$posts_title = $this->create_menu_item_anchor(
				'ab-item ab-primary mb-icon',
				Redirect::get_url( 'calypso-edit-posts' ),
				esc_html__( 'Blog Posts', 'jetpack' ),
				'wp-admin-bar-edit-post'
			);
		}

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'publish',
				'id'     => 'new-post',
				'title'  => $posts_title,
				'meta'   => array(
					'class' => 'inline-action mb-trackable',
				),
			)
		);

		// Comments.
		if ( current_user_can( 'moderate_comments' ) ) {
			$wp_admin_bar->add_menu(
				array(
					'parent' => 'publish',
					'id'     => 'comments',
					'title'  => __( 'Comments', 'jetpack' ),
					'href'   => Redirect::get_url( 'calypso-comments' ),
					'meta'   => array(
						'class' => 'mb-icon',
					),
				)
			);
		}

		// Testimonials.
		if ( Jetpack::is_module_active( 'custom-content-types' ) && get_option( 'jetpack_testimonial' ) ) {
			$testimonials_title = $this->create_menu_item_pair(
				array(
					'url'   => Redirect::get_url( 'calypso-list-jetpack-testimonial' ),
					'id'    => 'wp-admin-bar-edit-testimonial',
					'label' => esc_html__( 'Testimonials', 'jetpack' ),
				),
				array(
					'url'   => Redirect::get_url( 'calypso-edit-jetpack-testimonial' ),
					'id'    => 'wp-admin-bar-new-testimonial',
					'label' => esc_html_x( 'Add', 'Button label for adding a new item via the toolbar menu', 'jetpack' ),
				)
			);

			if ( ! current_user_can( 'edit_pages' ) ) {
				$testimonials_title = $this->create_menu_item_anchor(
					'ab-item ab-primary mb-icon',
					Redirect::get_url( 'calypso-list-jetpack-testimonial' ),
					esc_html__( 'Testimonials', 'jetpack' ),
					'wp-admin-bar-edit-testimonial'
				);
			}

			$wp_admin_bar->add_menu(
				array(
					'parent' => 'publish',
					'id'     => 'new-jetpack-testimonial',
					'title'  => $testimonials_title,
					'meta'   => array(
						'class' => 'inline-action',
					),
				)
			);
		}

		// Portfolio.
		if ( Jetpack::is_module_active( 'custom-content-types' ) && get_option( 'jetpack_portfolio' ) ) {
			$portfolios_title = $this->create_menu_item_pair(
				array(
					'url'   => Redirect::get_url( 'calypso-list-jetpack-portfolio' ),
					'id'    => 'wp-admin-bar-edit-portfolio',
					'label' => esc_html__( 'Portfolio', 'jetpack' ),
				),
				array(
					'url'   => Redirect::get_url( 'calypso-edit-jetpack-portfolio' ),
					'id'    => 'wp-admin-bar-new-portfolio',
					'label' => esc_html_x( 'Add', 'Button label for adding a new item via the toolbar menu', 'jetpack' ),
				)
			);

			if ( ! current_user_can( 'edit_pages' ) ) {
				$portfolios_title = $this->create_menu_item_anchor(
					'ab-item ab-primary mb-icon',
					Redirect::get_url( 'calypso-list-jetpack-portfolio' ),
					esc_html__( 'Portfolio', 'jetpack' ),
					'wp-admin-bar-edit-portfolio'
				);
			}

			$wp_admin_bar->add_menu(
				array(
					'parent' => 'publish',
					'id'     => 'new-jetpack-portfolio',
					'title'  => $portfolios_title,
					'meta'   => array(
						'class' => 'inline-action',
					),
				)
			);
		}

		if ( current_user_can( 'edit_theme_options' ) ) {
			// Look and Feel group.
			$wp_admin_bar->add_group(
				array(
					'parent' => 'blog',
					'id'     => 'look-and-feel',
				)
			);

			// Look and Feel header.
			$wp_admin_bar->add_menu(
				array(
					'parent' => 'look-and-feel',
					'id'     => 'look-and-feel-header',
					'title'  => esc_html_x( 'Personalize', 'admin bar menu group label', 'jetpack' ),
					'meta'   => array(
						'class' => 'ab-submenu-header',
					),
				)
			);

			$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? filter_var( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			if ( is_admin() ) {
				// In wp-admin the `return` query arg will return to that page after closing the Customizer.
				$customizer_url = add_query_arg(
					array(
						'return' => rawurlencode( site_url( $request_uri ) ),
					),
					wp_customize_url()
				);
			} else {
				/*
				 * On the frontend the `url` query arg will load that page in the Customizer
				 * and also return to it after closing
				 * non-home URLs won't work unless we undo domain mapping
				 * since the Customizer preview is unmapped to always have HTTPS.
				 */
				$current_page   = '//' . $this->primary_site_slug . $request_uri;
				$customizer_url = add_query_arg( array( 'url' => rawurlencode( $current_page ) ), wp_customize_url() );
			}

			$theme_title = $this->create_menu_item_pair(
				array(
					'url'   => $customizer_url,
					'id'    => 'wp-admin-bar-cmz',
					'label' => esc_html_x( 'Customize', 'admin bar customize item label', 'jetpack' ),
				),
				array(
					'url'   => Redirect::get_url( 'calypso-themes' ),
					'id'    => 'wp-admin-bar-themes',
					'label' => esc_html__( 'Themes', 'jetpack' ),
				)
			);
			$meta        = array(
				'class' => 'mb-icon inline-action',
			);
			$href        = false;

			$wp_admin_bar->add_menu(
				array(
					'parent' => 'look-and-feel',
					'id'     => 'themes',
					'title'  => $theme_title,
					'href'   => $href,
					'meta'   => $meta,
				)
			);
		}

		if ( current_user_can( 'manage_options' ) ) {
			// Configuration group.
			$wp_admin_bar->add_group(
				array(
					'parent' => 'blog',
					'id'     => 'configuration',
				)
			);

			// Configuration header.
			$wp_admin_bar->add_menu(
				array(
					'parent' => 'configuration',
					'id'     => 'configuration-header',
					'title'  => esc_html_x( 'Configure', 'admin bar menu group label', 'jetpack' ),
					'meta'   => array(
						'class' => 'ab-submenu-header',
					),
				)
			);

			if ( Jetpack::is_module_active( 'publicize' ) || Jetpack::is_module_active( 'sharedaddy' ) ) {
				$wp_admin_bar->add_menu(
					array(
						'parent' => 'configuration',
						'id'     => 'sharing',
						'title'  => esc_html__( 'Sharing', 'jetpack' ),
						'href'   => Redirect::get_url( 'calypso-sharing' ),
						'meta'   => array(
							'class' => 'mb-icon',
						),
					)
				);
			}

			$people_title = $this->create_menu_item_pair(
				array(
					'url'   => Redirect::get_url( 'calypso-people-team' ),
					'id'    => 'wp-admin-bar-people',
					'label' => esc_html__( 'People', 'jetpack' ),
				),
				array(
					'url'   => admin_url( 'user-new.php' ),
					'id'    => 'wp-admin-bar-people-add',
					'label' => esc_html_x( 'Add', 'admin bar people item label', 'jetpack' ),
				)
			);

			$wp_admin_bar->add_menu(
				array(
					'parent' => 'configuration',
					'id'     => 'users-toolbar',
					'title'  => $people_title,
					'href'   => false,
					'meta'   => array(
						'class' => 'inline-action',
					),
				)
			);

			$plugins_title = $this->create_menu_item_pair(
				array(
					'url'   => Redirect::get_url( 'calypso-plugins' ),
					'id'    => 'wp-admin-bar-plugins',
					'label' => esc_html__( 'Plugins', 'jetpack' ),
				),
				array(
					'url'   => Redirect::get_url( 'calypso-plugins-manage' ),
					'id'    => 'wp-admin-bar-plugins-add',
					'label' => esc_html_x( 'Manage', 'Label for the button on the Masterbar to manage plugins', 'jetpack' ),
				)
			);

			$wp_admin_bar->add_menu(
				array(
					'parent' => 'configuration',
					'id'     => 'plugins',
					'title'  => $plugins_title,
					'href'   => false,
					'meta'   => array(
						'class' => 'inline-action',
					),
				)
			);

			if ( $this->site_woa ) {
				$domain_title = $this->create_menu_item_pair(
					array(
						'url'   => Redirect::get_url( 'calypso-domains' ),
						'id'    => 'wp-admin-bar-domains',
						'label' => esc_html__( 'Domains', 'jetpack' ),
					),
					array(
						'url'   => Redirect::get_url( 'calypso-domains-add' ),
						'id'    => 'wp-admin-bar-domains-add',
						'label' => esc_html_x( 'Add', 'Label for the button on the Masterbar to add a new domain', 'jetpack' ),
					)
				);
				$wp_admin_bar->add_menu(
					array(
						'parent' => 'configuration',
						'id'     => 'domains',
						'title'  => $domain_title,
						'href'   => false,
						'meta'   => array(
							'class' => 'inline-action',
						),
					)
				);
			}

			$wp_admin_bar->add_menu(
				array(
					'parent' => 'configuration',
					'id'     => 'blog-settings',
					'title'  => esc_html__( 'Settings', 'jetpack' ),
					'href'   => Redirect::get_url( 'calypso-settings-general' ),
					'meta'   => array(
						'class' => 'mb-icon',
					),
				)
			);

			if ( ! is_admin() ) {
				$wp_admin_bar->add_menu(
					array(
						'parent' => 'configuration',
						'id'     => 'legacy-dashboard',
						'title'  => esc_html__( 'Dashboard', 'jetpack' ),
						'href'   => admin_url(),
						'meta'   => array(
							'class' => 'mb-icon',
						),
					)
				);
			}

			// Restore dashboard menu toggle that is needed on mobile views.
			if ( is_admin() ) {
				$wp_admin_bar->add_menu(
					array(
						'id'    => 'menu-toggle',
						'title' => '<span class="ab-icon"></span><span class="screen-reader-text">' . esc_html__( 'Menu', 'jetpack' ) . '</span>',
						'href'  => '#',
					)
				);
			}

			/**
			 * Fires when menu items are added to the masterbar "My Sites" menu.
			 *
			 * @since 5.4.0
			 */
			do_action( 'jetpack_masterbar' );
		}
	}

	/**
	 * Adds "My Home" submenu item to sites that are eligible.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin Bar instance.
	 * @return void
	 */
	private function add_my_home_submenu_item( &$wp_admin_bar ) {
		if ( ! current_user_can( 'manage_options' ) || ! $this->site_woa ) {
			return;
		}

		$wp_admin_bar->add_menu(
			array(
				'parent' => 'blog',
				'id'     => 'my-home',
				'title'  => __( 'My Home', 'jetpack' ),
				'href'   => Redirect::get_url( 'calypso-home' ),
				'meta'   => array(
					'class' => 'mb-icon',
				),
			)
		);
	}
}
