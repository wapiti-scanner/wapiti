<?php

namespace WPForms\Lite\Admin;

use WPForms\Helpers\PluginSilentUpgraderSkin;

/**
 * WPForms Connect Skin.
 *
 * WPForms Connect is our service that makes it easy for non-techy users to
 * upgrade to WPForms Pro without having to manually install WPForms Pro plugin.
 *
 * @since 1.5.5
 * @since 1.5.6.1 Extend PluginSilentUpgraderSkin and clean up the class.
 */
class ConnectSkin extends PluginSilentUpgraderSkin {

	/**
	 * Instead of outputting HTML for errors, json_encode the errors and send them
	 * back to the Ajax script for processing.
	 *
	 * @since 1.5.5
	 *
	 * @param array $errors Array of errors with the install process.
	 */
	public function error( $errors ) {

		if ( ! empty( $errors ) ) {
			echo \wp_json_encode(
				[
					'error' => \esc_html__( 'There was an error installing WPForms Pro. Please try again.', 'wpforms-lite' ),
				]
			);
			die;
		}
	}
}
