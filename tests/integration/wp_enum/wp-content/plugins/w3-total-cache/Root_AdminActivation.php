<?php
namespace W3TC;

/**
 * W3 Total Cache plugin
 */

/**
 * Class Root_AdminActivation
 */
class Root_AdminActivation {
	/**
	 * Activate plugin action
	 *
	 * @param bool $network_wide
	 * @return void
	 */
	public static function activate( $network_wide ) {
		// Decline non-network activation at WPMU.
		if ( Util_Environment::is_wpmu() ) {
			if ( $network_wide ) {
				// We are in network activation.
			} else if ( Util_Request::get_string( 'action' ) == 'error_scrape' &&
					strpos( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '', '/network/' ) !== false ) {
				// Workaround for error_scrape page called after error really we are in network activation and going to throw some error.
			} else {
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML a tag to plugin admin page, 2 closing HTML a tag.
						__(
							'Please %1$snetwork activate%2$s W3 Total Cache when using WordPress Multisite.',
							'w3-total-cache'
						),
						'<a href="' . esc_url( network_admin_url( 'plugins.php' ) ) . '">',
						'</a>'
					),
					array(
						'a' => array(
							'href' => array(),
						),
					)
				);

				die;
			}
		}

		try {
			$e      = Dispatcher::component( 'Root_Environment' );
			$config = Dispatcher::config();
			$e->fix_in_wpadmin( $config, true );
			$e->fix_on_event( $config, 'activate' );

			// try to save config file if needed, optional thing so exceptions hidden.
			if ( ! ConfigUtil::is_item_exists( 0, false ) ) {
				try {
					// create folders.
					$e->fix_in_wpadmin( $config );
				} catch ( \Exception $ex ) {
					// missing exception handle?
				}

				try {
					Util_Admin::config_save( Dispatcher::config(), $config );
				} catch ( \Exception $ex ) {
					// missing exception handle?
				}
			}
		} catch ( Util_Environment_Exceptions $e ) {
			// missing exception handle?
		} catch ( \Exception $e ) {
			Util_Activation::error_on_exception( $e );
		}
	}

	/**
	 * Deactivate plugin action
	 *
	 * @return void
	 */
	public static function deactivate() {
		try {
			Util_Activation::enable_maintenance_mode();
		} catch ( \Exception $ex ) {
			// missing exception handle?
		}

		try {
			$e = Dispatcher::component( 'Root_Environment' );
			$e->fix_after_deactivation();
		} catch ( Util_Environment_Exceptions $exs ) {
			$r = Util_Activation::parse_environment_exceptions( $exs );

			if ( strlen( $r['required_changes'] ) > 0 ) {
				$changes_style = 'border: 1px solid black; background: white; margin: 10px 30px 10px 30px; padding: 10px;';

				// this is not shown since wp redirects from that page not solved now.
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML div tag followed by opening HTML p tag, 2 opening HTML strong tag,
						// translators: 3 closing HTML strong tag, 4 html line break tags (x2), 5 opening HTML div tag,
						// translators: 6 list of required changes, 7 closing HTML div tag,
						// translators: 8 closing HTML p tag followed by closing HTML div tag.
						__(
							'%1$s%2$sW3 Total Cache Error:%3$s Files and directories could not be automatically removed to complete the deactivation. %4$sPlease execute commands manually:%5$s%6$s%7$s%8$s',
							'w3-total-cache'
						),
						'<div class="' . esc_attr__( 'error', 'w3-total-cache' ) . '"><p>',
						'<strong>',
						'</strong>',
						'<br /><br />',
						'<div style="' . esc_attr( $changes_style ) . '">',
						esc_html( $r['required_changes'] ),
						'</div>',
						'</p></div>'
					),
					array(
						'div'    => array(
							'class' => array(),
							'style' => array(),
						),
						'strong' => array(),
						'br'     => array(),
						'p'      => array(),
					)
				);
			}
		}

		try {
			Util_Activation::disable_maintenance_mode();
		} catch ( \Exception $ex ) {
			// missing exception handle?
		}

		// Delete cron events.
		require_once __DIR__ . '/Extension_ImageService_Cron.php';
		Extension_ImageService_Cron::delete_cron();
	}
}
