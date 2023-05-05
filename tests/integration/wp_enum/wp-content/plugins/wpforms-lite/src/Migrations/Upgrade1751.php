<?php

namespace WPForms\Migrations;

/**
 * Class v1.7.5.1 upgrade.
 *
 * @since 1.7.5.1
 *
 * @noinspection PhpUnused
 */
class Upgrade1751 extends UpgradeBase {

	/**
	 * Repeat 1.7.5 migration.
	 *
	 * @since 1.7.5.1
	 *
	 * @return bool|null Upgrade result:
	 *                   true  - the upgrade completed successfully,
	 *                   false - in the case of failure,
	 *                   null  - upgrade started but not yet finished (background task).
	 */
	public function run() {

		return ( new Upgrade175( $this->migrations ) )->run();
	}
}
