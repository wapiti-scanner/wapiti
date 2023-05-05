<?php
/**
 * Automatic_Upgrader_Skin extension for Jetpack
 *
 * @package jetpack-plugins-installer
 */

namespace Automattic\Jetpack;

use Automatic_Upgrader_Skin;

/**
 * Include required files from wp-admin.
 */
require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
require_once ABSPATH . 'wp-admin/includes/file.php';

/**
 * Allows us to capture that the site doesn't have proper file system access.
 * In order to update the plugin.
 */
class Automatic_Install_Skin extends Automatic_Upgrader_Skin {
	/**
	 * Stores the last error key;
	 *
	 * @var string
	 **/
	protected $main_error_code = 'install_error';

	/**
	 * Stores the last error message.
	 *
	 * @var string
	 **/
	protected $main_error_message = 'An unknown error occurred during installation';

	/**
	 * Overwrites the set_upgrader to be able to tell if we e ven have the ability to write to the files.
	 *
	 * @param WP_Upgrader $upgrader The upgrader object.
	 */
	public function set_upgrader( &$upgrader ) {
		parent::set_upgrader( $upgrader );

		// Check if we even have permission to.
		$result = $upgrader->fs_connect( array( WP_CONTENT_DIR, WP_PLUGIN_DIR ) );
		if ( ! $result ) {
			// set the string here since they are not available just yet.
			$upgrader->generic_strings();
			$this->feedback( 'fs_unavailable' );
		}
	}

	/**
	 * Overwrites the error function
	 *
	 * @param \WP_Error|mixed $error The error object.
	 */
	public function error( $error ) {
		if ( is_wp_error( $error ) ) {
			$this->feedback( $error );
		}
	}

	/**
	 * Set the main error code.
	 *
	 * Don't set the process_failed as code since it is not that helpful unless we don't have one already set
	 *
	 * @param string $code The error code.
	 * @return void
	 */
	private function set_main_error_code( $code ) {
		$this->main_error_code = ( 'process_failed' === $code && $this->main_error_code ? $this->main_error_code : $code );
	}

	/**
	 * Set the main error message.
	 *
	 * Don't set the process_failed as message since it is not that helpful unless we don't have one already set
	 *
	 * @param string $message The error message.
	 * @param string $code The error code.
	 * @return void
	 */
	private function set_main_error_message( $message, $code ) {
		$this->main_error_message = ( 'process_failed' === $code && $this->main_error_message ? $this->main_error_message : $message );
	}

	/**
	 * Get the main error code
	 *
	 * @return string
	 */
	public function get_main_error_code() {
		return $this->main_error_code;
	}

	/**
	 * Get the main error message
	 *
	 * @return string
	 */
	public function get_main_error_message() {
		return $this->main_error_message;
	}

	/**
	 * Overwrites the feedback function
	 *
	 * @param string|array|WP_Error $data    Data.
	 * @param mixed                 ...$args Optional text replacements.
	 */
	public function feedback( $data, ...$args ) {

		$current_error = null;
		if ( is_wp_error( $data ) ) {
			$this->set_main_error_code( $data->get_error_code() );
			$string = $data->get_error_message();
		} elseif ( is_array( $data ) ) {
			return;
		} else {
			$string = $data;
		}

		if ( ! empty( $this->upgrader->strings[ $string ] ) ) {
			$this->set_main_error_code( $string );

			$current_error = $string;
			$string        = $this->upgrader->strings[ $string ];
		}

		if ( strpos( $string, '%' ) !== false ) {
			if ( ! empty( $args ) ) {
				$string = vsprintf( $string, $args );
			}
		}

		$string = trim( $string );
		$string = wp_kses(
			$string,
			array(
				'a'      => array(
					'href' => true,
				),
				'br'     => true,
				'em'     => true,
				'strong' => true,
			)
		);

		$this->set_main_error_message( $string, $current_error );
		$this->messages[] = $string;
	}
}
