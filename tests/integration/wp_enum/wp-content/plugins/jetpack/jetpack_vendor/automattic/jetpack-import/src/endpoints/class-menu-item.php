<?php
/**
 * Menu items REST route
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

/**
 * Class Menu_Item
 */
class Menu_Item extends \WP_REST_Menu_Items_Controller {

	/**
	 * Base class
	 */
	use Import;

	/**
	 * The Import ID add a new item to the schema.
	 */
	use Import_ID;

	/**
	 * Whether the controller supports batching. Default true.
	 *
	 * @var array
	 */
	protected $allow_batch = array( 'v1' => true );

	/**
	 * Constructor.
	 */
	public function __construct() {
		parent::__construct( 'nav_menu_item' );

		// @see add_term_meta
		$this->import_id_meta_type = 'post';
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
		// WXR saves menu parent as slug, so we need to overwrite the schema.
		$schema['properties']['menus']['description'] = __( 'The parent menu slug.', 'jetpack-import' );
		$schema['properties']['menus']['type']        = 'string';

		// Add the import unique ID to the schema.
		return $this->add_unique_identifier_to_schema( $schema );
	}

	/**
	 * Creates a single menu item.
	 *
	 * @param WP_REST_Request $request Full details about the request.
	 * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
	 */
	public function create_item( $request ) {
		if ( ! empty( $request['menus'] ) ) {
			$menu_id = \term_exists( $request['menus'], 'nav_menu' );

			if ( $menu_id ) {
				// Overwrite the menu item parent menu ID.
				$request['menus'] = is_array( $menu_id ) ? $menu_id['term_id'] : $menu_id;
			}
		}

		if ( ! empty( $request['parent'] ) ) {
			$query              = $this->get_import_db_query( $request['parent'] );
			$query['post_type'] = 'nav_menu_item';
			$parent             = \get_posts( $query );

			// Overwrite the parent ID.
			$request['parent'] = is_array( $parent ) && count( $parent ) ? $parent[0] : 0;
		}

		// A menu item can be a custom link or a post, page, category or attachment.
		if ( ! empty( $request['object_id'] ) ) {
			$id = null;

			if ( $request['object'] === 'category' ) {
				if ( $request['object_id'] === 1 ) {
					// The default category is always ID 1, no need to search.
					$id = 1;
				} else {
					$query      = $this->get_import_db_query( $request['object_id'] );
					$categories = \get_categories( $this->get_import_db_query( $request['object_id'] ) );

					// Overwrite the category ID.
					$id = is_array( $categories ) && count( $categories ) ? $categories[0] : null;
				}
			} elseif ( $request['object'] === 'page' ) {
				$pages = \get_pages( $this->get_import_db_query( $request['object_id'] ) );

				// Overwrite the page ID.
				$id = is_array( $pages ) && count( $pages ) ? $pages[0]->ID : null;
			} elseif ( $request['object'] === 'post' || $request['object'] === 'attachment' ) {
				$posts = \get_posts( $this->get_import_db_query( $request['object_id'] ) );

				// Overwrite the post ID.
				$id = is_array( $posts ) && count( $posts ) ? $posts[0] : null;
			}

			if ( empty( $id ) ) {
				// Not found the object or a custom menu item, remove the fields.
				unset( $request['object_id'] );
				unset( $request['object'] );
			} else {
				$request['object_id'] = $id;
			}
		}

		$response = parent::create_item( $request );

		return $this->add_import_id_metadata( $request, $response );
	}
}
