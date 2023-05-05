<?php
namespace W3TC;

class Licensing_Plugin_Admin {
	private $site_inactivated = false;
	private $site_activated   = false;
	/**
	 * Config
	 */
	private $_config = null;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin
	 */
	function run() {
		add_action( 'admin_init', array( $this, 'admin_init' ) );
		add_action( 'wp_ajax_w3tc_verify_plugin_license_key', array( $this, 'action_verify_plugin_license_key' ) );
		add_action( 'w3tc_config_ui_save-w3tc_general', array( $this, 'possible_state_change' ), 2, 10 );

		add_action( 'w3tc_message_action_licensing_upgrade', array( $this, 'w3tc_message_action_licensing_upgrade' ) );

		add_filter( 'w3tc_admin_bar_menu', array( $this, 'w3tc_admin_bar_menu' ) );
	}

	public function w3tc_admin_bar_menu( $menu_items ) {
		if ( ! Util_Environment::is_w3tc_pro( $this->_config ) ) {
			$menu_items['00020.licensing'] = array(
				'id'     => 'w3tc_overlay_upgrade',
				'parent' => 'w3tc',
				'title'  => wp_kses(
					sprintf(
						// translators: 1 opening HTML span tag, 2 closing HTML span tag.
						__(
							'%1$sUpgrade Performance%2$s',
							'w3-total-cache'
						),
						'<span style="color: red; background: none;">',
						'</span>'
					),
					array(
						'span' => array(
							'style' => array(),
						),
					)
				),
				'href'   => wp_nonce_url(
					network_admin_url( 'admin.php?page=w3tc_dashboard&amp;w3tc_message_action=licensing_upgrade' ),
					'w3tc'
				),
			);
		}

		if ( defined( 'W3TC_DEBUG' ) && W3TC_DEBUG ) {
			$menu_items['90040.licensing'] = array(
				'id'     => 'w3tc_debug_overlay_upgrade',
				'parent' => 'w3tc_debug_overlays',
				'title'  => esc_html__( 'Upgrade', 'w3-total-cache' ),
				'href'   => wp_nonce_url( network_admin_url( 'admin.php?page=w3tc_dashboard&amp;w3tc_message_action=licensing_upgrade' ), 'w3tc' )
			);
		}

		return $menu_items;
	}

	public function w3tc_message_action_licensing_upgrade() {
		add_action( 'admin_head', array( $this, 'admin_head_licensing_upgrade' ) );
	}

	public function admin_head_licensing_upgrade() {
		?>
		<script type="text/javascript">
			jQuery(function() {
				w3tc_lightbox_upgrade(w3tc_nonce, 'topbar_performance');
				jQuery('#w3tc-license-instruction').show();
			});
		</script>
		<?php
	}

	/**
	 *
	 *
	 * @param Config  $config
	 * @param Config  $old_config
	 */
	function possible_state_change( $config, $old_config ) {
		$changed = false;

		if ( $old_config->get_string( 'plugin.license_key' ) !== '' && $config->get_string( 'plugin.license_key' ) === '' ) {
			$result = Licensing_Core::deactivate_license( $old_config->get_string( 'plugin.license_key' ) );
			if ( $result ) {
				$this->site_inactivated = true;
			}
			$changed = true;
		} elseif ( $old_config->get_string( 'plugin.license_key' ) === '' && $config->get_string( 'plugin.license_key' ) !== '' ) {
			$result = Licensing_Core::activate_license( $config->get_string( 'plugin.license_key' ), W3TC_VERSION );
			if ( $result ) {
				$this->site_activated = true;
				$config->set( 'common.track_usage', true );
			}
			$changed = true;
		} elseif ( $old_config->get_string( 'plugin.license_key' ) !== $config->get_string( 'plugin.license_key' ) ) {
			$result = Licensing_Core::activate_license( $config->get_string( 'plugin.license_key' ), W3TC_VERSION );
			if ( $result ) {
				$this->site_activated = true;
			}
			$changed = true;
		}

		if ( $changed ) {
			$state = Dispatcher::config_state();
			$state->set( 'license.next_check', 0 );
			$state->save();

			delete_transient( 'w3tc_imageservice_limited' );
		}
	}

	/**
	 * Setup notices actions
	 */
	function admin_init() {
		$capability = apply_filters( 'w3tc_capability_admin_notices', 'manage_options' );

		$this->maybe_update_license_status();

		if ( current_user_can( $capability ) ) {
			if ( is_admin() ) {
				/**
				 * Only admin can see W3TC notices and errors
				 */
				if ( ! Util_Environment::is_wpmu() ) {
					add_action( 'admin_notices', array( $this, 'admin_notices' ), 1, 1 );
				}
				add_action( 'network_admin_notices', array( $this, 'admin_notices' ), 1, 1 );

				if ( Util_Admin::is_w3tc_admin_page() ) {
					add_filter( 'w3tc_notes', array( $this, 'w3tc_notes' ) );
				}
			}
		}
	}

	private function _status_is( $s, $starts_with ) {
		$s           .= '.';
		$starts_with .= '.';
		return substr( $s, 0, strlen( $starts_with ) ) === $starts_with;
	}

	/**
	 * Run license status check and display messages
	 */
	function admin_notices() {
		$message = '';

		$state  = Dispatcher::config_state();
		$status = $state->get_string( 'license.status' );

		if ( defined( 'W3TC_PRO' ) ) {
		} elseif ( 'no_key' === $status ) {
		} elseif ( $this->_status_is( $status, 'inactive.expired' ) ) {
			$message = wp_kses(
				sprintf(
					// translators: 1 HTML input button for renewing licence.
					__(
						'It looks like your W3 Total Cache Pro License has expired. %1$s to continue using the Pro Features',
						'w3-total-cache'
					),
					'<input type="button" class="button-primary button-buy-plugin" data-nonce="' .
						esc_url( wp_create_nonce( 'w3tc' ) ) . '" data-renew-key="' . esc_attr( $this->get_license_key() ) .
						'" data-src="licensing_expired" value="' . __( 'Renew Now', 'w3-total-cache' ) . '" />'
				),
				array(
					'input' => array(
						'type'           => array(),
						'class'          => array(),
						'data-nonce'     => array(),
						'data-renew-key' => array(),
						'data-src'       => array(),
						'value'          => array(),
					),
				)
			);
		} elseif ( $this->_status_is( $status, 'invalid' ) ) {
			$message = __( 'The W3 Total Cache license key you entered is not valid.', 'w3-total-cache' ) .
				'<a href="' . ( is_network_admin() ? network_admin_url( 'admin.php?page=w3tc_general#licensing' ) :
				admin_url( 'admin.php?page=w3tc_general#licensing' ) ) . '"> ' . __( 'Please enter it again.', 'w3-total-cache' ) . '</a>';
		} elseif ( $this->_status_is( $status, 'inactive.by_rooturi.activations_limit_not_reached' ) ) {
			$message = __( 'The W3 Total Cache license key is not active for this site.', 'w3-total-cache' );
		} elseif ( $this->_status_is( $status, 'inactive.by_rooturi' ) ) {
			$message = wp_kses(
				sprintf(
					// translators: HTML a tag to W3TC Licence Reset.
					__(
						'The W3 Total Cache license key is not active for this site. You can switch your license to this website following %1$sthis link%2$s',
						'w3-total-cache'
					),
					'<a class="w3tc_licensing_reset_rooturi" href="' . Util_Ui::url(
						array(
							'page'                         => 'w3tc_general',
							'w3tc_licensing_reset_rooturi' => 'y',
						)
					) . '">',
					'</a>'
				),
				array(
					'a' => array(
						'class' => array(),
						'href'  => array(),
					),
				)
			);
		} elseif ( $this->_status_is( $status, 'inactive' ) ) {
			$message = __( 'The W3 Total Cache license key is not active.', 'w3-total-cache' );
		} elseif ( $this->_status_is( $status, 'active' ) ) {
		} else {
			$message = __( 'The W3 Total Cache license key can\'t be verified.', 'w3-total-cache' );
		}

		if ( $message ) {
			if ( ! Util_Admin::is_w3tc_admin_page() ) {
				echo '<script src="' . esc_url( plugins_url( 'pub/js/lightbox.js', W3TC_FILE ) ) . '"></script>';
				echo '<link rel="stylesheet" id="w3tc-lightbox-css"  href="' . esc_url( plugins_url( 'pub/css/lightbox.css', W3TC_FILE ) ) . '" type="text/css" media="all" />';
			}

			Util_Ui::error_box(
				sprintf(
					'%1$s%2$s. %3$scheck license status again</a></p>',
					'<p>',
					$message,
					'<a class="w3tc_licensing_check" href="' . Util_Ui::url(
						array(
							'page'                     => 'w3tc_general',
							'w3tc_licensing_check_key' => 'y',
						)
					) . '">',
					'</a>',
					'</p>'
				)
			);
		}

		if ( $this->site_inactivated ) {
			Util_Ui::error_box( '<p>' . __( 'The W3 Total Cache license key is deactivated for this site.', 'w3-total-cache' ) . '</p>' );
		}

		if ( $this->site_activated ) {
			Util_Ui::error_box( '<p>' . __( 'The W3 Total Cache license key is activated for this site.', 'w3-total-cache' ) . '</p>' );
		}
	}

	function w3tc_notes( $notes ) {
		$terms        = '';
		$state_master = Dispatcher::config_state_master();

		if ( defined( 'W3TC_PRO' ) ) {
			$terms = 'accept';
		} elseif ( ! Util_Environment::is_w3tc_pro( $this->_config ) ) {
			$terms = $state_master->get_string( 'license.community_terms' );

			$buttons = sprintf(
				'<br /><br />%s&nbsp;%s',
				Util_Ui::button_link(
					__( 'Accept', 'w3-total-cache' ),
					Util_Ui::url( array( 'w3tc_licensing_terms_accept' => 'y' ) )
				),
				Util_Ui::button_link(
					__( 'Decline', 'w3-total-cache' ),
					Util_Ui::url( array( 'w3tc_licensing_terms_decline' => 'y' ) )
				)
			);
		} else {
			$state = Dispatcher::config_state();
			$terms = $state->get_string( 'license.terms' );

			$return_url = self_admin_url( Util_Ui::url( array( 'w3tc_licensing_terms_refresh' => 'y' ) ) );

			$buttons =
				sprintf( '<form method="post" action="%s">', W3TC_TERMS_ACCEPT_URL ) .
				Util_Ui::r_hidden( 'return_url', 'return_url', $return_url ) .
				Util_Ui::r_hidden( 'license_key', 'license_key', $this->get_license_key() ) .
				Util_Ui::r_hidden( 'home_url', 'home_url', home_url() ) .
				'<input type="submit" class="button" name="answer" value="Accept" />&nbsp;' .
				'<input type="submit" class="button" name="answer" value="Decline" />' .
				'</form>';
		}

		if ( 'accept' !== $terms && 'decline' !== $terms && 'postpone' !== $terms ) {
			if ( $state_master->get_integer( 'common.install' ) < 1542029724 ) {
				/* installed before 2018-11-12 */
				$notes['licensing_terms'] = sprintf(
					// translators: 1 opening HTML a tag to W3TC Terms page, 2 closing HTML a tag.
					esc_html__(
						'Our terms of use and privacy policies have been updated. Please %1$sreview%2$s and accept them.',
						'w3-total-cache'
					),
					'<a target="_blank" href="' . esc_url( W3TC_TERMS_URL ) . '">',
					'</a>'
				) . $buttons;
			} else {
				$notes['licensing_terms'] = sprintf(
					// translators: 1: HTML break tag, 2: Anchor/link open tag, 3: Anchor/link close tag.
					esc_html__(
						'By allowing us to collect data about how W3 Total Cache is used, we can improve our features and experience for everyone. This data will not include any personally identifiable information.%1$sFeel free to review our %2$sterms of use and privacy policy%3$s.',
						'w3-total-cache'
					),
					'<br />',
					'<a target="_blank" href="' . esc_url( W3TC_TERMS_URL ) . '">',
					'</a>'
				) .
					$buttons;
			}
		}

		return $notes;
	}

	/**
	 *
	 *
	 * @return string
	 */
	private function maybe_update_license_status() {
		$state = Dispatcher::config_state();
		if ( time() < $state->get_integer( 'license.next_check' ) ) {
			return;
		}

		$check_timeout = 3600 * 24 * 5;
		$status        = '';
		$terms         = '';
		$license_key   = $this->get_license_key();

		$old_plugin_type = $this->_config->get_string( 'plugin.type' );
		$plugin_type     = '';

		if ( ! empty( $license_key ) || defined( 'W3TC_LICENSE_CHECK' ) ) {
			$license = Licensing_Core::check_license( $license_key, W3TC_VERSION );

			if ( $license ) {
				$status = $license->license_status;
				$terms  = $license->license_terms;
				if ( $this->_status_is( $status, 'active' ) ) {
					$plugin_type = 'pro';
				} elseif ( $this->_status_is( $status, 'inactive.by_rooturi' ) &&
					Util_Environment::is_w3tc_pro_dev() ) {
					$status      = 'valid';
					$plugin_type = 'pro_dev';
				}
			}

			$this->_config->set( 'plugin.type', $plugin_type );
		} else {
			$status = 'no_key';
		}

		if ( 'no_key' === $status ) {
		} elseif ( $this->_status_is( $status, 'invalid' ) ) {
		} elseif ( $this->_status_is( $status, 'inactive' ) ) {
		} elseif ( $this->_status_is( $status, 'active' ) ) {
		} else {
			$check_timeout = 60;
		}

		$state->set( 'license.status', $status );
		$state->set( 'license.next_check', time() + $check_timeout );
		$state->set( 'license.terms', $terms );
		$state->save();

		if ( $old_plugin_type !== $plugin_type ) {
			try {
				$this->_config->set( 'plugin.type', $plugin_type );
				$this->_config->save();
			} catch ( \Exception $ex ) {
				// missing exception handle?
			}
		}
		return $status;
	}

	function get_license_key() {
		$license_key = $this->_config->get_string( 'plugin.license_key', '' );
		if ( '' === $license_key ) {
			$license_key = ini_get( 'w3tc.license_key' );
		}
		return $license_key;
	}

	function action_verify_plugin_license_key() {
		$license = Util_Request::get_string( 'license_key', '' );

		if ( $license ) {
			$status = Licensing_Core::check_license( $license, W3TC_VERSION );
			echo esc_html( $status->license_status );
		} else {
			echo 'invalid';
		}
		exit();
	}
}
