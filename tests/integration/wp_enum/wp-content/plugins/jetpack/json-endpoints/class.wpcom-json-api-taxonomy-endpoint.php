<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Taxonomy endpoint.
 */
abstract class WPCOM_JSON_API_Taxonomy_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * Category object format.
	 *
	 * @var array
	 */
	public $category_object_format = array(
		'ID'          => '(int) The category ID.',
		'name'        => '(string) The name of the category.',
		'slug'        => '(string) The slug of the category.',
		'description' => '(string) The description of the category.',
		'post_count'  => '(int) The number of posts using this category.',
		'feed_url'    => '(string) The URL of the feed for this category.',
		'parent'      => '(int) The parent ID for the category.',
		'meta'        => '(object) Meta data',
	);

	/**
	 * Tag object format.
	 *
	 * @var array
	 */
	public $tag_object_format = array(
		'ID'          => '(int) The tag ID.',
		'name'        => '(string) The name of the tag.',
		'slug'        => '(string) The slug of the tag.',
		'description' => '(string) The description of the tag.',
		'post_count'  => '(int) The number of posts using this t.',
		'meta'        => '(object) Meta data',
	);

	/**
	 * Constructor function.
	 *
	 * @param string|array|object $args - the arguments.
	 */
	public function __construct( $args ) {
		parent::__construct( $args );
		if ( preg_match( '#/tags/#i', $this->path ) ) {
			$this->response_format =& $this->tag_object_format;
		} else {
			$this->response_format =& $this->category_object_format;
		}
	}
}
