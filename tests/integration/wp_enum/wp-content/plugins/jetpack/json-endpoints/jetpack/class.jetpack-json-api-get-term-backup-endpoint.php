<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Get Term backup endpoint class.
 *
 * /sites/%s/terms/%d/backup      -> $blog_id, $term_id
 */
class Jetpack_JSON_API_Get_Term_Backup_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var array
	 */
	protected $needed_capabilities = array(); // This endpoint is only accessible using a site token

	/**
	 * The term ID.
	 *
	 * @var int
	 */
	protected $term_id;

	/**
	 * Validate input.
	 *
	 * @param int $term_id - the term ID.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_input( $term_id ) {
		if ( empty( $term_id ) || ! is_numeric( $term_id ) ) {
			return new WP_Error( 'term_id_not_specified', __( 'You must specify a Term ID', 'jetpack' ), 400 );
		}

		$this->term_id = (int) $term_id;

		return true;
	}

	/**
	 * Return the result.
	 *
	 * @return array|WP_Error
	 */
	protected function result() {
		// Disable Sync as this is a read-only operation and triggered by sync activity.
		\Automattic\Jetpack\Sync\Actions::mark_sync_read_only();

		$term = get_term( $this->term_id );
		if ( empty( $term ) ) {
			return new WP_Error( 'term_not_found', __( 'Term not found', 'jetpack' ), 404 );
		}

		return array(
			'term' => (array) $term,
			'meta' => get_term_meta( $this->term_id ),
		);
	}

}

