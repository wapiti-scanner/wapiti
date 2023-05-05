<?php
/**
 * Attachments REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

/**
 * Class Attachment
 */
class Attachment extends \WP_REST_Attachments_Controller {

	/**
	 * Base class
	 */
	use Import;

	/**
	 * The Import ID add a new item to the schema.
	 */
	use Import_ID;

	/**
	 * Whether the controller supports batching. Default false.
	 *
	 * @var false
	 */
	protected $allow_batch = false;

	/**
	 * Constructor.
	 */
	public function __construct() {
		parent::__construct( 'attachment' );

		// @see add_term_meta
		$this->import_id_meta_type = 'post';
	}

	/**
	 * Registers the routes for the objects of the controller.
	 *
	 * @see WP_REST_Terms_Controller::register_rest_route()
	 */
	public function register_routes() {
		register_rest_route(
			self::$rest_namespace,
			'/' . $this->rest_base,
			$this->get_route_options()
		);

		register_rest_route(
			self::$rest_namespace,
			'/' . $this->rest_base . '/(?P<id>[\d]+)',
			array(
				'args'        => array(
					'id' => array(
						'description' => __( 'Unique identifier for the attachment.', 'jetpack-import' ),
						'type'        => 'integer',
					),
				),
				array(
					'methods'             => \WP_REST_Server::EDITABLE,
					'callback'            => array( $this, 'update_item' ),
					'permission_callback' => array( $this, 'update_item_permissions_check' ),
					'args'                => $this->get_endpoint_args_for_item_schema( \WP_REST_Server::EDITABLE ),
				),
				'allow_batch' => array( 'v1' => true ),
				'schema'      => array( $this, 'get_public_item_schema' ),
			)
		);

		register_rest_route(
			self::$rest_namespace,
			'/' . $this->rest_base . '/(?P<id>[\d]+)/post-process',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'post_process_item' ),
				'permission_callback' => array( $this, 'import_permissions_callback' ),
				'args'                => array(
					'id'     => array(
						'description' => __( 'Unique identifier for the attachment.', 'jetpack-import' ),
						'type'        => 'integer',
					),
					'action' => array(
						'type'     => 'string',
						'enum'     => array( 'create-image-subsizes' ),
						'required' => true,
					),
				),
			)
		);
	}

	/**
	 * Create a single attachment.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, WP_Error object on failure.
	 */
	public function create_item( $request ) {
		$file_info  = $this->get_file_info( $request );
		$attachment = $this->get_attachment_by_file_info( $file_info );
		if ( $attachment ) {
			$response = $this->prepare_attachment_for_response( $attachment, $request );

			if ( \is_wp_error( $response ) ) {
				return $response;
			}

			return new \WP_Error(
				'attachment_exists',
				__( 'The attachment already exists.', 'jetpack-import' ),
				array(
					'status'        => 409,
					'attachment'    => $response,
					'attachment_id' => $attachment->ID,
				)
			);
		}

		$this->set_upload_dir( $request );
		return parent::create_item( $request );
	}

	/**
	 * Updates a single attachment.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
	 */
	public function update_item( $request ) {
		$response = parent::update_item( $request );

		return $this->add_import_id_metadata( $request, $response );
	}

	/**
	 * Adds the schema from additional fields to a schema array.
	 *
	 * The type of object is inferred from the passed schema.
	 *
	 * @param array $schema Schema array.
	 * @return array Modified Schema array.
	 */
	public function add_additional_fields_schema( $schema ) {
		// Validate the upload_date, used for placing the uploaded file in the correct upload directory.
		$schema['properties']['upload_date'] = array(
			'description' => __( 'The date for the upload directory of the attachment.', 'jetpack-import' ),
			'type'        => array( 'string', 'null' ),
			'pattern'     => '^\d{4}\/\d{2}$',
			'required'    => false,
		);

		// The unique identifier is only required for PUT requests.
		return $this->add_unique_identifier_to_schema( $schema, isset( $_SERVER['REQUEST_METHOD'] ) && $_SERVER['REQUEST_METHOD'] === 'PUT' );
	}

	/**
	 * Performs post-processing on an attachment.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, WP_Error object on failure.
	 */
	public function post_process_item( $request ) {
		require_once ABSPATH . 'wp-admin/includes/image.php';

		\wp_update_image_subsizes( $request['id'] );
		$request['context'] = 'edit';

		return $this->prepare_item_for_response( \get_post( $request['id'] ), $request );
	}

	/**
	 * Add a filter that rewrites the upload path.
	 *
	 * @param \WP_REST_Request $request Full details about the request.
	 *
	 * @return void
	 * @throws \Exception If the date is invalid.
	 */
	protected function set_upload_dir( $request ) {

		if ( ! $request->get_param( 'upload_date' ) ) {
			return;
		}

		add_filter(
			'upload_dir',
			static function ( $data ) use ( $request ) {
				$date              = $request->get_param( 'upload_date' );
				$fields_to_rewrite = array( 'path', 'url', 'subdir' );
				foreach ( $fields_to_rewrite as $field ) {
					$data[ $field ] = preg_replace( '/\d{4}\/\d{2}$/', $date, $data[ $field ] );
				}

				return $data;
			}
		);
	}

	/**
	 * Prepares a single attachment for create or update. This function overrides the parent function
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return stdClass|WP_Error Post object.
	 */
	protected function prepare_item_for_database( $request ) {
		$prepared_attachment = parent::prepare_item_for_database( $request );
		// date_gmt is equal to the date by default, so we need to override it.
		if ( $request->get_param( 'date_gmt' ) ) {
			$prepared_attachment->post_date_gmt = $request->get_param( 'date_gmt' );
		}
		return $prepared_attachment;
	}

	/**
	 * Retrieve the filename and MIME type from the request headers.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 *
	 * @return array An associative array containing the filename and MIME type.
	 */
	protected function get_file_info( $request ) {
		// Get the filename from the Content-Disposition header.
		$filename_header = $request->get_header( 'content_disposition' );
		$filename        = self::get_filename_from_disposition( (array) $filename_header );
		$post_date_gmt   = $request->get_param( 'date_gmt' );

		// Get the MIME type from the Content-Type header.
		$mime_type = $request->get_header( 'content_type' );

		return array(
			'filename'      => $filename,
			'mime_type'     => $mime_type,
			'post_date_gmt' => $post_date_gmt,
		);
	}

	/**
	 * Retrieve attachment metadata by file information.
	 *
	 * This function retrieves attachment metadata for a given file based on its filename, MIME type, and creation date.
	 *
	 * @param array $fileinfo An associative array containing information about the file. The array must contain the following keys:
	 *   - 'filename': The name of the file.
	 *   - 'mime_type': The MIME type of the file (e.g. 'image/jpeg').
	 *   - 'date': The creation date of the file (e.g. '2022-01-01 12:00:00').
	 *
	 * @return mixed An associative array containing metadata for the attachment, or false if no attachment was found.
	 */
	protected function get_attachment_by_file_info( $fileinfo ) {
		// Make sure all required variables are set and not empty
		if ( empty( $fileinfo['filename'] ) || empty( $fileinfo['mime_type'] ) || empty( $fileinfo['post_date_gmt'] ) ) {
			return false;
		}

		$filename      = $fileinfo['filename'];
		$mime_type     = $fileinfo['mime_type'];
		$post_date_gmt = $fileinfo['post_date_gmt'];

		$args = array(
			'post_type'      => 'attachment',
			'post_mime_type' => $mime_type,
			'date_query'     => array(
				array(
					'after'     => $post_date_gmt,
					'before'    => $post_date_gmt,
					'inclusive' => true,
					'column'    => 'post_date_gmt',
				),
			),
			'meta_query'     => array(
				array(
					'key'     => '_wp_attached_file',
					'value'   => preg_quote( $filename, '/' ),
					'compare' => 'REGEXP',
				),
			),
			'posts_per_page' => 1,
		);

		$attachments = \get_posts( $args );

		if ( ! empty( $attachments ) ) {
			// Return the first attachment data found
			return $attachments[0];
		}

		return false;
	}

	/**
	 * Prepares an attachment object for REST API response and returns the resulting data as an array.
	 *
	 * @param object $attachment The attachment object to be prepared for response.
	 * @param object $request The REST API request object.
	 *
	 * @return array|WP_Error The prepared data as an array, or a WP_Error object if there was an error preparing the data.
	 */
	private function prepare_attachment_for_response( $attachment, $request ) {
		// Prepare attachment data for response
		$response = $this->prepare_item_for_response( $attachment, $request );

		// Check if there was an error preparing the data
		if ( \is_wp_error( $response ) ) {
			return $response;
		}

		return (array) $response->get_data();
	}

}
