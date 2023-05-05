<?php
/**
 * Template parts REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

/**
 * Class Template_Part
 */
class Template_Part extends \WP_REST_Templates_Controller {

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
		parent::__construct( 'wp_template_part' );
	}
}
