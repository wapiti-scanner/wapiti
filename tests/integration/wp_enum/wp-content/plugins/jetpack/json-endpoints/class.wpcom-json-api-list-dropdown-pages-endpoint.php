<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * List dropdown pages endpoint.
 */
new WPCOM_JSON_API_List_Dropdown_Pages_Endpoint(
	array(

		'description'                          => 'Get a list of pages to be displayed as options in a select-a-page-dropdown.',
		'min_version'                          => '1.1',
		'max_version'                          => '1.1',

		'group'                                => 'posts',
		'stat'                                 => 'posts:dropdown-pages',

		'method'                               => 'GET',
		'path'                                 => '/sites/%s/dropdown-pages/',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1.1/sites/en.blog.wordpress.com/dropdown-pages/',
	)
);

/**
 * Endpoint class responsible for listing pages to be displayed as options in a select-a-page-dropdown.
 *
 * /sites/%s/dropdown-pages/ -> $blog_id
 */
class WPCOM_JSON_API_List_Dropdown_Pages_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * Page object format.
	 *
	 * @var array
	 */
	public $dropdown_page_object_format = array(
		'ID'       => '(int) The page ID.',
		'title'    => '(string) The page title.',
		'children' => '(array:dropdown_page) An array of child pages.',
	);

	/**
	 * The response format.
	 *
	 * @var array
	 */
	public $response_format = array(
		'found'          => '(int) The number of pages found.',
		'dropdown_pages' => '(array:dropdown_page) An array of dropdown_page objects.',
	);

	/**
	 * List of pages indexed by their page ID.
	 *
	 * @var array<int,WP_Post>
	 */
	private $pages_by_id = array();

	/**
	 * List of pages indexed by their parent page ID.
	 *
	 * @var array<int,WP_Post>
	 */
	private $pages_by_parent = array();

	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @return stdClass[] $pages - An array of page objects. Each page object includes ID and title properties and may include children property. This makes each page object a tree-like data structure.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$pages = get_pages();

		if ( empty( $pages ) ) {
			return array(
				'found'          => 0,
				'dropdown_pages' => array(),
			);
		}

		$this->pages_by_id     = self::to_pages_by_id( $pages );
		$this->pages_by_parent = self::to_pages_by_parent( $pages );
		$dropdown_pages        = $this->create_dropdown_pages();
		return array(
			'found'          => count( $dropdown_pages ),
			'dropdown_pages' => $dropdown_pages,
		);
	}

	/**
	 * Convert a list of pages to a list of pages by page ID.
	 *
	 * @param array<WP_Post> $pages - array of pages.
	 * @return array<int,WP_Post> $pages_by_page_id - indexed array of pages by page ID where index is page ID.
	 */
	private static function to_pages_by_id( $pages ) {
		$pages_by_page_id = array();
		foreach ( $pages as $page ) {
			if ( isset( $page->ID ) ) {
				$pages_by_page_id[ $page->ID ] = $page;
			}
		}
		return $pages_by_page_id;
	}

	/**
	 * Convert a list of pages to a list of pages by parent.
	 *
	 * @param array<WP_Post> $pages - array of pages.
	 * @return array<int,WP_Post> $pages_by_parent - indexed array of pages by parent where index is page ID.
	 */
	private static function to_pages_by_parent( $pages ) {
		$pages_by_parent = array();
		foreach ( $pages as $page ) {
			if ( empty( $page->post_parent ) ) {
				$pages_by_parent['root'][] = $page;
			} else {
				$pages_by_parent[ $page->post_parent ][] = $page;
			}
		}
		return $pages_by_parent;
	}

	/**
	 * Convert a list of pages to a list of dropdown pages.
	 *
	 * @return array<stdClass> $dropdown_pages - array of dropdown pages.
	 */
	private function create_dropdown_pages() {
		$dropdown_pages = array();

		if ( ! empty( $this->pages_by_parent['root'] ) ) {
			foreach ( $this->pages_by_parent['root'] as $root_page ) {
				$dropdown_pages[] = $this->to_dropdown_page( $root_page );
			}
		}

		if ( ! empty( $this->pages_by_id ) ) {
			// In case there were some orphans
			// phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			foreach ( $this->pages_by_id as $_page_id => $page ) {
				$dropdown_pages[] = $this->to_dropdown_page( $page );
			}
		}

		return $dropdown_pages;
	}

	/**
	 * Convert a page to a dropdown page.
	 *
	 * @param WP_Post $page - the page.
	 * @return stdClass|false $dropdown_page - the dropdown page.
	 */
	private function to_dropdown_page( $page ) {
		if ( ! isset( $page->ID ) ) {
			return false;
		}

		$title = $this->get_page_title( $page );

		if ( ! isset( $this->pages_by_parent[ $page->ID ] ) ) {
			unset( $this->pages_by_id[ $page->ID ] );
			return (object) array(
				'ID'    => $page->ID,
				'title' => $title,
			);
		}

		$children = array();
		foreach ( $this->pages_by_parent[ $page->ID ] as $child_page ) {
			$children[] = $this->to_dropdown_page( $child_page );
		}

		unset( $this->pages_by_id[ $page->ID ] );
		unset( $this->pages_by_parent[ $page->ID ] );
		return (object) array(
			'ID'       => $page->ID,
			'title'    => $title,
			'children' => $children,
		);
	}

	/**
	 * Get the page title.
	 *
	 * @param WP_Post $page - the page.
	 * @return string $page_title - the page title.
	 */
	private function get_page_title( $page ) {
		$title = $page->post_title;
		if ( '' === $title ) {
			/* translators: %d: ID of a post. */
			$title = sprintf( __( '#%d (no title)', 'jetpack' ), $page->ID );
		}

		/**
		 * Filters the page title when creating an HTML drop-down list of pages.
		 *
		 * @since 3.1.0
		 *
		 * @param string  $title Page title.
		 * @param WP_Post $page  Page data object.
		 */
		$title = apply_filters( 'list_pages', $title, $page );
		return $title;
	}
}
