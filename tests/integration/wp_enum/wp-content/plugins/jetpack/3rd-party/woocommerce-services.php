<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Plugins_Installer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Installs and activates the WooCommerce Services plugin.
 */
class WC_Services_Installer {

	/**
	 * The instance of the Jetpack class.
	 *
	 * @var Jetpack
	 */
	private $jetpack;

	/**
	 * The singleton instance of this class.
	 *
	 * @var WC_Services_Installer
	 */
	private static $instance = null;

	/**
	 * Returns the singleton instance of this class.
	 *
	 * @return object The WC_Services_Installer object.
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new WC_Services_Installer();
		}
		return self::$instance;
	}

	/**
	 * Constructor
	 */
	public function __construct() {
		add_action( 'jetpack_loaded', array( $this, 'on_jetpack_loaded' ) );
		if ( ! empty( $_GET['wc-services-install-error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			add_action( 'admin_notices', array( $this, 'error_notice' ) );
		}

		if ( isset( $_GET['wc-services-action'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			add_action( 'admin_init', array( $this, 'try_install' ) );
		}
	}

	/**
	 * Runs on Jetpack being ready to load its packages.
	 *
	 * @param Jetpack $jetpack object.
	 */
	public function on_jetpack_loaded( $jetpack ) {
		$this->jetpack = $jetpack;
	}

	/**
	 * Verify the intent to install WooCommerce Services, and kick off installation.
	 */
	public function try_install() {
		if ( ! isset( $_GET['wc-services-action'] ) ) {
			return;
		}
		check_admin_referer( 'wc-services-install' );

		$result = false;

		switch ( $_GET['wc-services-action'] ) {
			case 'install':
				if ( current_user_can( 'install_plugins' ) ) {
					$this->jetpack->stat( 'jitm', 'wooservices-install-' . JETPACK__VERSION );
					$result = $this->install();
					if ( $result ) {
						$result = $this->activate();
					}
				}
				break;

			case 'activate':
				if ( current_user_can( 'activate_plugins' ) ) {
					$this->jetpack->stat( 'jitm', 'wooservices-activate-' . JETPACK__VERSION );
					$result = $this->activate();
				}
				break;
		}

		if ( isset( $_GET['redirect'] ) ) {
			$redirect = home_url( esc_url_raw( wp_unslash( $_GET['redirect'] ) ) );
		} else {
			$redirect = admin_url();
		}

		if ( $result ) {
			$this->jetpack->stat( 'jitm', 'wooservices-activated-' . JETPACK__VERSION );
		} else {
			$redirect = add_query_arg( 'wc-services-install-error', true, $redirect );
		}

		wp_safe_redirect( $redirect );

		exit;
	}

	/**
	 * Notify the user that the installation of WooCommerce Services failed.
	 */
	public function error_notice() {
		?>
		<div class="notice notice-error is-dismissible">
			<p><?php esc_html_e( 'There was an error installing WooCommerce Services.', 'jetpack' ); ?></p>
		</div>
		<?php
	}

	/**
	 * Download and install the WooCommerce Services plugin.
	 *
	 * @return bool result of installation
	 */
	private function install() {
		$result = Plugins_Installer::install_plugin( 'woocommerce-services' );

		if ( is_wp_error( $result ) ) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * Activate the WooCommerce Services plugin.
	 *
	 * @return bool result of activation
	 */
	private function activate() {
		$result = activate_plugin( 'woocommerce-services/woocommerce-services.php' );

		// Activate_plugin() returns null on success.
		return $result === null;
	}
}

WC_Services_Installer::init();
