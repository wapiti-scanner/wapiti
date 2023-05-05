<?php

namespace WPForms\Logger;

/**
 * Class RecordQuery.
 *
 * @since 1.6.3
 */
class RecordQuery {

	/**
	 * Build query.
	 *
	 * @since 1.6.3
	 *
	 * @param int    $limit  Query limit of records.
	 * @param int    $offset Offset of records.
	 * @param string $search Search.
	 * @param string $type   Type of records.
	 *
	 * @return array
	 */
	public function get( $limit, $offset = 0, $search = '', $type = '' ) {

		global $wpdb;
		//phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
		//phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
		return (array) $wpdb->get_results(
			$this->build_query( $limit, $offset, $search, $type )
		);
		//phpcs:enable WordPress.DB.DirectDatabaseQuery.NoCaching
		//phpcs:enable WordPress.DB.PreparedSQL.NotPrepared
	}

	/**
	 * Build query.
	 *
	 * @since 1.6.3
	 *
	 * @param int    $limit  Query limit of records.
	 * @param int    $offset Offset of records.
	 * @param string $search Search.
	 * @param string $type   Type of records.
	 *
	 * @return string
	 */
	private function build_query( $limit, $offset = 0, $search = '', $type = '' ) {

		global $wpdb;

		$sql   = 'SELECT SQL_CALC_FOUND_ROWS * FROM ' . Repository::get_table_name();
		$where = [];
		if ( ! empty( $search ) ) {
			$where[] = $wpdb->prepare(
				'`title` REGEXP %s OR `message` REGEXP %s',
				$search,
				$search
			);
		}
		if ( ! empty( $type ) ) {
			$where[] = $wpdb->prepare(
				'`types` REGEXP %s',
				$type
			);
		}
		if ( $where ) {
			$sql .= ' WHERE ' . implode( ' AND ', $where );
		}
		$sql .= ' ORDER BY `create_at` DESC, `id` DESC';
		$sql .= $wpdb->prepare( ' LIMIT %d, %d', absint( $offset ), absint( $limit ) );

		return $sql;
	}
}
