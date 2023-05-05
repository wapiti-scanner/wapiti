<?php
/**
 * File: Extensions_Plugin_Admin.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: Extensions_Plugin_Admin
 */
class Extensions_Plugin_Admin {
	/**
	 * Config.
	 *
	 * @var Config
	 */
	private $_config = null; // phpcs:ignore

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin.
	 */
	public function run() {
		// Attach w3tc-bundled extensions.
		add_filter( 'w3tc_extensions', array( '\W3TC\Extension_CloudFlare_Plugin_Admin', 'w3tc_extensions' ), 10, 2 );
		add_filter( 'w3tc_extensions', array( '\W3TC\Extension_FragmentCache_Plugin_Admin', 'w3tc_extensions' ), 10, 2 );
		add_filter( 'w3tc_extensions', array( '\W3TC\Extension_Genesis_Plugin_Admin', 'w3tc_extensions' ), 10, 2 );
		add_filter( 'w3tc_extensions_hooks', array( '\W3TC\Extension_Genesis_Plugin_Admin', 'w3tc_extensions_hooks' ) );
		add_filter( 'w3tc_notes_genesis_theme', array( '\W3TC\Extension_Genesis_Plugin_Admin', 'w3tc_notes_genesis_theme' ) );
		add_filter( 'w3tc_extensions', array( '\W3TC\Extension_NewRelic_Plugin_Admin', 'w3tc_extensions' ), 10, 2 );
		add_filter( 'w3tc_extensions', array( '\W3TC\Extension_Swarmify_Plugin_Admin', 'w3tc_extensions' ), 10, 2 );
		add_filter( 'w3tc_extensions', array( '\W3TC\Extension_WordPressSeo_Plugin_Admin', 'w3tc_extensions' ), 10, 2 );
		add_filter( 'w3tc_extensions_hooks', array( '\W3TC\Extension_WordPressSeo_Plugin_Admin', 'w3tc_extensions_hooks' ) );
		add_action( 'w3tc_notes_wordpress_seo', array( '\W3TC\Extension_WordPressSeo_Plugin_Admin', 'w3tc_notes_wordpress_seo' ) );
		add_filter( 'w3tc_extensions', array( '\W3TC\Extension_Wpml_Plugin_Admin', 'w3tc_extensions' ), 10, 2 );
		add_filter( 'w3tc_extensions', array( '\W3TC\Extension_Amp_Plugin_Admin', 'w3tc_extensions' ), 10, 2 );
		add_filter( 'w3tc_extensions_hooks', array( '\W3TC\Extension_Wpml_Plugin_Admin', 'w3tc_extensions_hooks' ) );
		add_action( 'w3tc_notes_wpml', array( '\W3TC\Extension_Wpml_Plugin_Admin', 'w3tc_notes_wpml' ) );
		add_filter( 'w3tc_extensions', array( '\W3TC\Extension_ImageService_Plugin_Admin', 'w3tc_extensions' ), 10, 2 );
		add_action( 'admin_init', array( $this, 'admin_init' ), 1 );
		add_filter( 'pre_update_option_active_plugins', array( $this, 'pre_update_option_active_plugins' ) );
		add_filter( 'w3tc_admin_menu', array( $this, 'w3tc_admin_menu' ), 10000 );
		add_action( 'w3tc_settings_page-w3tc_extensions', array( $this, 'w3tc_settings_page_w3tc_extensions' ) );

		if ( Util_Admin::is_w3tc_admin_page() ) {
			add_action( 'admin_notices', array( $this, 'admin_notices' ) );

			$action_val = Util_Request::get_string( 'action' );
			if ( ! empty( Util_Request::get_string( 'extension' ) ) && ! empty( $action_val ) ) {
				if ( in_array( $action_val, array( 'activate', 'deactivate' ), true ) ) {
					add_action( 'init', array( $this, 'change_extension_status' ) );
				}
			} elseif ( ! empty( Util_Request::get_array( 'checked' ) ) ) {
				add_action( 'admin_init', array( $this, 'change_extensions_status' ) );
			}
		}
	}

	/**
	 * Adds menu.
	 *
	 * @param array $menu Menu.
	 * @return array
	 */
	public function w3tc_admin_menu( $menu ) {
		$menu['w3tc_extensions'] = array(
			'page_title'     => __( 'Extensions', 'w3-total-cache' ),
			'menu_text'      => __( 'Extensions', 'w3-total-cache' ),
			'visible_always' => false,
			'order'          => 1900,
		);

		return $menu;
	}

	/**
	 * Loads options page and corresponding view.
	 */
	public function w3tc_settings_page_w3tc_extensions() {
		$o = new Extensions_Page();
		$o->render_content();
	}

	/**
	 * Delete hooks option before updating active plugins option.
	 *
	 * @param mixed $o Option value.
	 * @return mixed
	 */
	public function pre_update_option_active_plugins( $o ) {
		delete_option( 'w3tc_extensions_hooks' );

		return $o;
	}

	/**
	 * Admin init.
	 */
	public function admin_init() {
		// Used to load even inactive extensions if they want to.
		$s     = get_option( 'w3tc_extensions_hooks' );
		$hooks = @json_decode( $s, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( ! isset( $hooks['next_check_date'] ) ||
			$hooks['next_check_date'] < time() ) {
			$hooks = array(
				'actions'         => array(),
				'filters'         => array(),
				'next_check_date' => time() + 24 * 60 * 60,
			);

			$hooks = apply_filters( 'w3tc_extensions_hooks', $hooks );

			update_option( 'w3tc_extensions_hooks', wp_json_encode( $hooks ) );
		}

		if ( isset( $hooks['actions'] ) ) {
			foreach ( $hooks['actions'] as $hook => $actions_to_call ) {
				if ( is_array( $actions_to_call ) ) {
					add_action(
						$hook,
						function() use ( $actions_to_call ) {
							foreach ( $actions_to_call as $action ) {
								do_action( $action );
							}
						}
					);
				}
			}
		}

		if ( isset( $hooks['filters'] ) ) {
			foreach ( $hooks['filters'] as $hook => $filters_to_call ) {
				if ( is_array( $filters_to_call ) ) {
					add_filter(
						$hook,
						function( $v ) use ( $filters_to_call ) {
							foreach ( $filters_to_call as $filter ) {
								$v = apply_filters( $filter, $v );
							}

							return $v;
						}
					);
				}
			}
		}
	}

	/**
	 * Alters the active state of multiple extensions.
	 */
	public function change_extensions_status() {
		$message    = '';
		$extensions = Util_Request::get_array( 'checked' );
		$action     = Util_Request::get( 'action' );

		if ( '-1' === $action ) {
			$action = Util_Request::get( 'action2' );   // Dropdown at bottom.
		}

		if ( 'activate-selected' === $action ) {
			foreach ( $extensions as $extension ) {
				if ( Extensions_Util::activate_extension( $extension, $this->_config ) ) {
					$message .= '&activated=' . $extension;
				}
			}
			wp_safe_redirect( Util_Ui::admin_url( sprintf( 'admin.php?page=w3tc_extensions%s', $message ) ) );
			exit;
		} elseif ( 'deactivate-selected' === $action ) {
			foreach ( $extensions as $extension ) {
				if ( Extensions_Util::deactivate_extension( $extension, $this->_config ) ) {
					$message .= '&deactivated=' . $extension;
				}
			}
			wp_safe_redirect( Util_Ui::admin_url( sprintf( 'admin.php?page=w3tc_extensions%s', $message ) ) );
			exit;
		} else {
			wp_safe_redirect( Util_Ui::admin_url( 'admin.php?page=w3tc_extensions' ) );
			exit;
		}
	}

	/**
	 * Alters the active state of an extension.
	 */
	public function change_extension_status() {
		$action = Util_Request::get_string( 'action' );

		if ( in_array( $action, array( 'activate', 'deactivate' ), true ) ) {
			$extension = Util_Request::get_string( 'extension' );

			if ( 'activate' === $action ) {
				Extensions_Util::activate_extension( $extension, $this->_config );
				wp_safe_redirect( Util_Ui::admin_url( sprintf( 'admin.php?page=w3tc_extensions&activated=%s', $extension ) ) );
				exit;
			} elseif ( 'deactivate' === $action ) {
				Extensions_Util::deactivate_extension( $extension, $this->_config );
				wp_safe_redirect( Util_Ui::admin_url( sprintf( 'admin.php?page=w3tc_extensions&deactivated=%s', $extension ) ) );
				exit;
			}
		}
	}

	/**
	 * Display admin notices.
	 *
	 * @since 2.2.0
	 *
	 * @see Extensions_Util::get_active_extensions()
	 */
	public function admin_notices() {
		$extensions_active = Extensions_Util::get_active_extensions( $this->_config );

		foreach ( $extensions_active as $id => $info ) {
			$transient_name = 'w3tc_activation_' . $id;
			$action_name    = 'w3tc_' . $id . '_action';
			$action_val     = Util_Request::get_string( $action_name );

			if ( ! empty( $action_val ) && 'dismiss_activation_notice' === $action_val ) {
				delete_transient( $transient_name );
			}

			if ( isset( $info['notice'] ) && get_transient( $transient_name ) ) {
				?>
				<div class="notice notice-warning is-dismissible">
					<p>
				<?php
				echo wp_kses(
					$info['notice'],
					array(
						'a' => array(
							'class'  => array(),
							'href'   => array(),
							'target' => array(),
						),
					)
				);
				?>
						</p>
				</div>
				<?php
			}
		}
	}
}
