<?php

namespace WPForms\Lite\Reports;

/**
 * Generate form submissions reports.
 *
 * @since 1.5.4
 */
class EntriesCount {

	/**
	 * Constructor.
	 *
	 * @since 1.5.4
	 */
	public function __construct() {}

	/**
	 * Get entries count grouped by form.
	 * Main point of entry to fetch form entry count data from DB.
	 * Cache the result.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	public function get_by_form() {

		$forms = wpforms()->form->get( '', [ 'fields' => 'ids' ] );

		if ( empty( $forms ) || ! \is_array( $forms ) ) {
			return [];
		}

		$result = [];

		foreach ( $forms as $form_id ) {
			$count = \absint( \get_post_meta( $form_id, 'wpforms_entries_count', true ) );
			if ( empty( $count ) ) {
				continue;
			}
			$result[ $form_id ] = [
				'form_id' => $form_id,
				'count'   => $count,
				'title'   => \get_the_title( $form_id ),
			];
		}

		if ( ! empty( $result ) ) {
			// Sort forms by entries count (desc).
			\uasort(
				$result,
				function ( $a, $b ) {
					return ( $a['count'] > $b['count'] ) ? -1 : 1;
				}
			);
		}

		return $result;
	}
}
