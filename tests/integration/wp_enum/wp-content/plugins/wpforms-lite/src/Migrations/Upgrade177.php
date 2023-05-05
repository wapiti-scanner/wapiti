<?php

namespace WPForms\Migrations;

/**
 * Class v1.7.7 upgrade.
 *
 * @since 1.7.7
 */
class Upgrade177 extends UpgradeBase {

	/**
	 * Run upgrade.
	 *
	 * @since 1.7.7
	 *
	 * @return bool|null Upgrade result:
	 *                   true  - the upgrade completed successfully,
	 *                   false - in the case of failure,
	 *                   null  - upgrade started but not yet finished (background task).
	 */
	public function run() {

		$settings          = (array) get_option( 'wpforms_settings', [] );
		$new_inputmask_key = 'validation-inputmask-incomplete';
		$old_inputmask_key = 'validation-input-mask-incomplete';
		$is_updated        = false;

		if ( isset( $settings[ $new_inputmask_key ] ) && in_array( $settings[ $new_inputmask_key ], [ 'Please fill out all blanks.', esc_html__( 'Please fill out all blanks.', 'wpforms-lite' ) ], true ) ) {
			unset( $settings[ $new_inputmask_key ] );

			$is_updated = true;
		}

		if ( empty( $settings[ $new_inputmask_key ] ) && ! empty( $settings[ $old_inputmask_key ] ) ) {
			$settings[ $new_inputmask_key ] = $settings[ $old_inputmask_key ];

			$is_updated = true;
		}

		if ( $is_updated ) {
			update_option( 'wpforms_settings', $settings );
		}

		return true;
	}
}
