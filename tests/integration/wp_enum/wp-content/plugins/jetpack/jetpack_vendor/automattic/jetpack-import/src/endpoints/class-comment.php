<?php
/**
 * Comments REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

/**
 * Class Comment
 */
class Comment extends \WP_REST_Comments_Controller {

	/**
	 * Base class
	 */
	use Import;

	/**
	 * The Import ID add a new item to the schema.
	 */
	use Import_ID;

	/**
	 * Whether the controller supports batching.
	 *
	 * @var array
	 */
	protected $allow_batch = array( 'v1' => true );

	/**
	 * Constructor.
	 */
	public function __construct() {
		parent::__construct();

		// @see add_comment_meta
		$this->import_id_meta_type = 'comment';
	}

	/**
	 * Creates a comment.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or error object on failure.
	 */
	public function create_item( $request ) {
		// Resolve comment post ID.
		if ( ! empty( $request['post'] ) ) {
			$posts = \get_posts( $this->get_import_db_query( $request['post'] ) );

			// Overwrite the comment parent post ID.
			$request['post'] = is_array( $posts ) && count( $posts ) ? $posts[0] : 0;
		}

		// Resolve comment parent ID.
		if ( ! empty( $request['parent'] ) ) {
			$comments = \get_comments( $this->get_import_db_query( $request['parent'] ) );

			// Overwrite the comment parent post ID.
			$request['parent'] = is_array( $comments ) && count( $comments ) ? $comments[0] : 0;
		}

		$duplicated_id = null;

		/**
		 * Core comment creation function doesn't return the duplicated comment ID.
		 * Add a filter to get the ID.
		 *
		 * phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		 */
		$get_id_func = function ( $dupe_id, $commentdata ) use ( &$duplicated_id ) {
			if ( $dupe_id !== null ) {
				$duplicated_id = $dupe_id;
			}

			return $dupe_id;
		};

		// Add the filter.
		\add_filter( 'duplicate_comment_id', $get_id_func, 10, 2 );

		$response = parent::create_item( $request );

		// Check if the comment is duplicated.
		if (
			$duplicated_id !== null &&
			is_wp_error( $response ) &&
			$response->get_error_code() === 'comment_duplicate' ) {
			$data = $response->get_error_data( 'comment_duplicate' );

			// Add the comment ID.
			$data['comment_id'] = $duplicated_id;

			$response->add_data( $data );
		}

		// Remove the filter.
		\remove_filter( 'duplicate_comment_id', $get_id_func );

		return $this->add_import_id_metadata( $request, $response );
	}
}
