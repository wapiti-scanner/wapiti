<?php

namespace WPForms\Migrations;

use WPForms\Tasks\Meta;
use WPForms\Tasks\Tasks;

/**
 * Class v1.7.5 upgrade.
 *
 * @since 1.7.5
 *
 * @noinspection PhpUnused
 */
class Upgrade175 extends UpgradeBase {

	/**
	 * Delete all task meta of not active tasks.
	 *
	 * @since 1.7.5
	 *
	 * @noinspection ElvisOperatorCanBeUsedInspection
	 *
	 * @return bool|null Upgrade result:
	 *                   true  - the upgrade completed successfully,
	 *                   false - in the case of failure,
	 *                   null  - upgrade started but not yet finished (background task).
	 */
	public function run() {

		global $wpdb;

		if ( ! $this->as_tables_exist() ) {
			return true;
		}

		$group = Tasks::GROUP;
		$sql   = "SELECT DISTINCT a.args FROM {$wpdb->prefix}actionscheduler_actions a
					JOIN {$wpdb->prefix}actionscheduler_groups g ON g.group_id = a.group_id
					WHERE g.slug = '$group' AND a.status IN ('pending', 'in-progress')";

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
		$results = $wpdb->get_results( $sql, 'ARRAY_A' );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared

		$results  = $results ? $results : [];
		$meta_ids = [];

		foreach ( $results as $result ) {
			$args = isset( $result['args'] ) ? json_decode( $result['args'], true ) : null;

			if ( $args && ! empty( $args['tasks_meta_id'] ) ) {
				$meta_ids[] = $args['tasks_meta_id'];
			}
		}

		$table_name = Meta::get_table_name();
		$not_in     = $meta_ids ? wpforms_wpdb_prepare_in( $meta_ids ) : '0';

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			"DELETE FROM {$table_name} WHERE id NOT IN ( {$not_in} )"
		);

		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching

		return true;
	}

	/**
	 * Check whether AS tables exist.
	 *
	 * @since 1.7.6
	 *
	 * @return bool
	 */
	private function as_tables_exist() {

		global $wpdb;

		$required_tables = [
			$wpdb->prefix . 'actionscheduler_actions',
			$wpdb->prefix . 'actionscheduler_groups',
		];

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		$tables    = $wpdb->get_col( "SHOW TABLES LIKE '" . $wpdb->prefix . "actionscheduler%'" );
		$intersect = array_values( array_intersect( $tables, $required_tables ) );

		sort( $intersect );
		sort( $required_tables );

		return $intersect === $required_tables;
	}
}
