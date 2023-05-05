<?php

namespace WPForms\Migrations;

/**
 * Class v1.5.9 upgrade.
 *
 * @since 1.7.5
 *
 * @noinspection PhpUnused
 */
class Upgrade159 extends UpgradeBase {

	/**
	 * Create tasks_meta table.
	 *
	 * @since 1.7.5
	 *
	 * @return bool|null Upgrade result:
	 *                   true  - the upgrade completed successfully,
	 *                   false - in the case of failure,
	 *                   null  - upgrade started but not yet finished (background task).
	 */
	public function run() {

		$meta = wpforms()->get( 'tasks_meta' );

		if ( ! $meta ) {
			return false;
		}

		// Create the table if it doesn't exist.
		if ( ! $meta->table_exists() ) {
			$meta->create_table();
		}

		return true;
	}
}
