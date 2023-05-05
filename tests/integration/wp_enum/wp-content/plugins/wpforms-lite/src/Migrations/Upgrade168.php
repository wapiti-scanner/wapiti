<?php

namespace WPForms\Migrations;

/**
 * Class v1.6.8 upgrade.
 *
 * @since 1.7.5
 *
 * @noinspection PhpUnused
 */
class Upgrade168 extends UpgradeBase {

	/**
	 * Run upgrade.
	 *
	 * @since 1.7.5
	 *
	 * @return bool|null Upgrade result:
	 *                   true  - the upgrade completed successfully,
	 *                   false - in the case of failure,
	 *                   null  - upgrade started but not yet finished (background task).
	 */
	public function run() {

		$current_opened_date = get_option( 'wpforms_builder_opened_date', null );

		// Do not run migration twice as 0 is a default value for all old users.
		if ( $current_opened_date === '0' ) {
			return true;
		}

		// We don't want users to report to us if they already previously used the builder by creating a form.
		$form_handler = wpforms()->get( 'form' );

		if ( ! $form_handler ) {
			return false;
		}

		$forms = $form_handler->get(
			'',
			[
				'posts_per_page'         => 1,
				'nopaging'               => false,
				'fields'                 => 'ids',
				'update_post_meta_cache' => false,
			]
		);

		// At least 1 form exists - set the default value.
		if ( ! empty( $forms ) ) {
			add_option( 'wpforms_builder_opened_date', 0, '', 'no' );
		}

		return true;
	}
}
