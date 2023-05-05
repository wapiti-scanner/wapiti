<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
require_once ABSPATH . 'wp-admin/includes/file.php';

use Automattic\Jetpack\Automatic_Install_Skin;

/**
 * Themes new endpoint class.
 *
 * /sites/%s/themes/%s/install
 */
class Jetpack_JSON_API_Themes_New_Endpoint extends Jetpack_JSON_API_Themes_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'install_themes';

	/**
	 * Action.
	 *
	 * @var string
	 */
	protected $action = 'install';

	/**
	 * Download links.
	 *
	 * @var array
	 */
	protected $download_links = array();

	/**
	 * Validate the call.
	 *
	 * @param int    $_blog_id - the blod ID.
	 * @param string $capability - the capability we're checking.
	 * @param bool   $check_manage_active - if managing capabilities is active.
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_call( $_blog_id, $capability, $check_manage_active = true ) {
		$validate = parent::validate_call( $_blog_id, $capability, $check_manage_active );
		if ( is_wp_error( $validate ) ) {
			// Lets delete the attachment... if the user doesn't have the right permissions to do things.
			$args = $this->input();
			if ( isset( $args['zip'][0]['id'] ) ) {
				wp_delete_attachment( $args['zip'][0]['id'], true );
			}
		}

		return $validate;
	}

	/**
	 * Validate the input.
	 *
	 * @param string $theme - the theme.
	 */
	protected function validate_input( $theme ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$this->bulk   = false;
		$this->themes = array();
	}

	/**
	 * Install the theme.
	 *
	 * @return bool
	 */
	public function install() {
		$args = $this->input();

		if ( isset( $args['zip'][0]['id'] ) ) {
			$attachment_id = $args['zip'][0]['id'];
			$local_file    = get_attached_file( $attachment_id );
			if ( ! $local_file ) {
				return new WP_Error( 'local-file-does-not-exist' );
			}
			$skin     = new Automatic_Install_Skin();
			$upgrader = new Theme_Upgrader( $skin );

			$pre_install_list = wp_get_themes();
			$result           = $upgrader->install( $local_file );

			// clean up.
			wp_delete_attachment( $attachment_id, true );

			if ( is_wp_error( $result ) ) {
				return $result;
			}

			$after_install_list = wp_get_themes();
			$plugin             = array_values( array_diff( array_keys( $after_install_list ), array_keys( $pre_install_list ) ) );

			if ( ! $result ) {
				$error_code = $upgrader->skin->get_main_error_code();
				$message    = $upgrader->skin->get_main_error_message();
				if ( empty( $message ) ) {
					$message = __( 'An unknown error occurred during installation', 'jetpack' );
				}

				if ( 'download_failed' === $error_code ) {
					$error_code = 'no_package';
				}

				return new WP_Error( $error_code, $message, 400 );
			}

			if ( empty( $plugin ) ) {
				return new WP_Error( 'theme_already_installed' );
			}

			$this->themes            = $plugin;
			$this->log[ $plugin[0] ] = $upgrader->skin->get_upgrade_messages();

			return true;
		}

		return new WP_Error( 'no_theme_installed' );
	}
}
