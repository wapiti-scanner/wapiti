<?php

namespace WPForms\Migrations;

/**
 * Class v1.6.7.2 upgrade.
 *
 * @since 1.7.5
 *
 * @noinspection PhpUnused
 */
class Upgrade1672 extends UpgradeBase {

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

		$review = get_option( 'wpforms_review' );

		if ( empty( $review ) ) {
			return true;
		}

		$notices = get_option( 'wpforms_admin_notices', [] );

		if ( isset( $notices['review_request'] ) ) {
			return true;
		}

		$notices['review_request'] = $review;

		update_option( 'wpforms_admin_notices', $notices, true );
		delete_option( 'wpforms_review' );

		return true;
	}
}
