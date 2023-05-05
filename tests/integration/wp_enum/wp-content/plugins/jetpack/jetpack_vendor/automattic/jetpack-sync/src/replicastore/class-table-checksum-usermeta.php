<?php
/**
 * Table Checksums Class.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Replicastore;

use Automattic\Jetpack\Connection\Manager;
use Automattic\Jetpack\Sync;
use Automattic\Jetpack\Sync\Modules;
use WP_Error;
use WP_User_Query;

/**
 * Class to handle Table Checksums for the User Meta table.
 */
class Table_Checksum_Usermeta extends Table_Checksum_Users {
	/**
	 * Calculate the checksum based on provided range and filters.
	 *
	 * @param int|null   $range_from          The start of the range.
	 * @param int|null   $range_to            The end of the range.
	 * @param array|null $filter_values       Additional filter values. Not used at the moment.
	 * @param bool       $granular_result     If the returned result should be granular or only the checksum.
	 * @param bool       $simple_return_value If we want to use a simple return value for non-granular results (return only the checksum, without wrappers).
	 *
	 * @return array|mixed|object|WP_Error|null
	 */
	public function calculate_checksum( $range_from = null, $range_to = null, $filter_values = null, $granular_result = false, $simple_return_value = true ) {

		if ( ! Sync\Settings::is_checksum_enabled() ) {
			return new WP_Error( 'checksum_disabled', 'Checksums are currently disabled.' );
		}

		/**
		 * First we need to fetch the user IDs for the users that we want to include in the range.
		 *
		 * To keep things a bit simple and avoid filtering issues, let's reuse the `build_filter_statement` that already
		 * exists. Unfortunately we don't
		 */
		global $wpdb;

		// This call depends on the `range_field` pointing to the `ID` field of the `users` table. Currently, "ID".
		$range_filter_statement = $this->build_filter_statement( $range_from, $range_to );

		$query = "
			SELECT
				DISTINCT {$this->table}.{$this->range_field}
			FROM
				{$this->table}
			JOIN {$wpdb->usermeta} as um_table ON um_table.user_id = {$this->table}.ID
			WHERE
				{$range_filter_statement}
				AND um_table.meta_key = '{$wpdb->prefix}user_level'
			  	AND um_table.meta_value > 0
		";

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$user_ids = $wpdb->get_col( $query );

		// Chunk the array down to make sure we don't overload the database with queries that are too large.
		$chunked_user_ids = array_chunk( $user_ids, 500 );

		$checksum_entries = array();

		foreach ( $chunked_user_ids as $user_ids_chunk ) {
			$user_objects = $this->get_user_objects_by_ids( $user_ids_chunk );

			foreach ( $user_objects as $user_object ) {
				// expand and sanitize desired meta based on WP.com logic.
				$user_object = $this->expand_and_sanitize_user_meta( $user_object );

				// Generate checksum entry based on the serialized value if not empty.
				$checksum_entry = 0;
				if ( ! empty( $user_object->roles ) ) {
					$checksum_entry = crc32( implode( '#', array( $this->salt, 'roles', maybe_serialize( $user_object->roles ) ) ) );
				}

				// Meta only persisted if user is connected to WP.com.
				if ( ( new Manager( 'jetpack' ) )->is_user_connected( $user_object->ID ) ) {
					if ( ! empty( $user_object->allcaps ) ) {
						$checksum_entry += crc32(
							implode(
								'#',
								array(
									$this->salt,
									'capabilities',
									maybe_serialize( $user_object->allcaps ),
								)
							)
						);
					}
					// Explicitly check that locale is not same as site locale.
					if ( ! empty( $user_object->locale ) && get_locale() !== $user_object->locale ) {
						$checksum_entry += crc32(
							implode(
								'#',
								array(
									$this->salt,
									'locale',
									maybe_serialize( $user_object->locale ),
								)
							)
						);
					}
					if ( ! empty( $user_object->allowed_mime_types ) ) {
						$checksum_entry += crc32(
							implode(
								'#',
								array(
									$this->salt,
									'allowed_mime_types',
									maybe_serialize( $user_object->allowed_mime_types ),
								)
							)
						);
					}
				}

				$checksum_entries[ $user_object->ID ] = '' . $checksum_entry;
			}
		}

		// Non-granular results need only to sum the different entries.
		if ( ! $granular_result ) {
			$checksum_sum = 0;
			foreach ( $checksum_entries as $entry ) {
				$checksum_sum += intval( $entry );
			}

			if ( $simple_return_value ) {
				return '' . $checksum_sum;
			}

			return array(
				'range'    => $range_from . '-' . $range_to,
				'checksum' => '' . $checksum_sum,
			);

		}

		// Granular results.
		$response = $checksum_entries;

		// Sort the return value for easier comparisons and code flows further down the line.
		ksort( $response );

		return $response;
	}

	/**
	 * Expand the User Object with additional meta santized by WP.com logic.
	 *
	 * @param mixed $user_object User Object from WP_User_Query.
	 *
	 * @return mixed $user_object expanded User Object.
	 */
	protected function expand_and_sanitize_user_meta( $user_object ) {
		$user_module = Modules::get_module( 'users' );
		// Expand User Objects based on Sync logic.
		$user_object = $user_module->expand_user( $user_object );

		// Sanitize location.
		if ( ! empty( $user_object->locale ) ) {
			$user_object->locale = wp_strip_all_tags( $user_object->locale, true );
		}

		// Sanitize allcaps.
		if ( ! empty( $user_object->allcaps ) ) {
			$user_object->allcaps = array_map(
				function ( $cap ) {
					return (bool) $cap;
				},
				$user_object->allcaps
			);
		}

		// Sanitize allowed_mime_types.
		$allowed_mime_types = $user_object->allowed_mime_types;
		foreach ( $allowed_mime_types as $allowed_mime_type_short => $allowed_mime_type_long ) {
			$allowed_mime_type_short                        = wp_strip_all_tags( (string) $allowed_mime_type_short, true );
			$allowed_mime_type_long                         = wp_strip_all_tags( (string) $allowed_mime_type_long, true );
			$allowed_mime_types[ $allowed_mime_type_short ] = $allowed_mime_type_long;
		}
		$user_object->allowed_mime_types = $allowed_mime_types;

		// Sanitize roles.
		if ( is_array( $user_object->roles ) ) {
			$user_object->roles = array_map( 'sanitize_text_field', $user_object->roles );
		}
		return $user_object;
	}

	/**
	 * Gets a list of `WP_User` objects by their IDs
	 *
	 * @param array $ids List of IDs to fetch.
	 *
	 * @return array
	 */
	protected function get_user_objects_by_ids( $ids ) {
		$user_query = new WP_User_Query( array( 'include' => $ids ) );

		return $user_query->get_results();
	}
}
