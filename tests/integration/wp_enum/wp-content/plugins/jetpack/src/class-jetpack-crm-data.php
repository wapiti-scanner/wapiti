<?php
/**
 * Compatibility functions for the Jetpack CRM plugin.
 *
 * @since 9.0.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack;

/**
 * Provides Jetpack CRM plugin data.
 */
class Jetpack_CRM_Data {

	const JETPACK_CRM_PLUGIN_SLUG = 'zero-bs-crm/ZeroBSCRM.php';

	/**
	 * Provides Jetpack CRM plugin data for use in the Contact Form block sidebar menu.
	 *
	 * @return array An array containing the Jetpack CRM plugin data.
	 */
	public function get_crm_data() {
		$plugins = Plugins_Installer::get_plugins();

		// Set default values.
		$response = array(
			'crm_installed'          => false,
			'crm_active'             => false,
			'crm_version'            => null,
			'jp_form_ext_enabled'    => null,
			'can_install_crm'        => false,
			'can_activate_crm'       => false,
			'can_activate_extension' => false,
		);

		if ( isset( $plugins[ self::JETPACK_CRM_PLUGIN_SLUG ] ) ) {
			$response['crm_installed'] = true;

			$crm_data = $plugins[ self::JETPACK_CRM_PLUGIN_SLUG ];

			$response['crm_active']  = $crm_data['active'];
			$response['crm_version'] = $crm_data['Version'];

			if ( $response['crm_active'] ) {
				if ( function_exists( 'zeroBSCRM_isExtensionInstalled' ) ) {
					$response['jp_form_ext_enabled'] = zeroBSCRM_isExtensionInstalled( 'jetpackforms' );
				}
			}
		}

		$response['can_install_crm']  = $response['crm_installed'] ? false : current_user_can( 'install_plugins' );
		$response['can_activate_crm'] = $response['crm_active'] ? false : current_user_can( 'activate_plugins' );

		if ( $response['crm_active'] && function_exists( 'zeroBSCRM_extension_install_jetpackforms' ) ) {
			// phpcs:ignore WordPress.WP.Capabilities.Unknown
			$response['can_activate_extension'] = current_user_can( 'admin_zerobs_manage_options' );
		}

		return $response;
	}

	/**
	 * Activates Jetpack CRM's Jetpack Forms extension. This is used by a button in the Jetpack Contact Form
	 * sidebar menu.
	 *
	 * @return true|WP_Error Returns true if activation is success, else returns a WP_Error object.
	 */
	public function activate_crm_jetpackforms_extension() {
		if ( function_exists( 'zeroBSCRM_extension_install_jetpackforms' ) ) {
			return zeroBSCRM_extension_install_jetpackforms();
		}

		return new WP_Error( 'jp_forms_extension_activation_failed', esc_html__( 'The Jetpack Forms extension could not be activated.', 'jetpack' ) );
	}
}
