<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Tiled gallery layout class.
 */
abstract class Jetpack_Tiled_Gallery_Layout {
	/**
	 * Template allow list.
	 *
	 * @var array
	 */
	private static $templates = array( 'carousel-container', 'circle-layout', 'rectangular-layout', 'square-layout' );

	/**
	 * Partial list.
	 *
	 * @var array
	 */
	private static $partials = array( 'carousel-image-args', 'item' );

	/**
	 * Type of gallery - defined in parent class.
	 *
	 * @var string
	 */
	protected $type;

	/**
	 * The attachments.
	 *
	 * @var object
	 */
	public $attachments;

	/**
	 * The attachment link.
	 *
	 * @var string
	 */
	public $link;

	/**
	 * If the image is in grayscale.
	 *
	 * @var bool
	 */
	public $grayscale;

	/**
	 * How many columns.
	 *
	 * @var int
	 */
	public $columns;

	/**
	 * Constructor function.
	 *
	 * @param object $attachments - the attachmed image.
	 * @param string $link - the attachment link.
	 * @param bool   $grayscale - if the image is in grayscale.
	 * @param int    $columns - how many columns.
	 */
	public function __construct( $attachments, $link, $grayscale, $columns ) {
		$this->attachments           = $attachments;
		$this->link                  = $link;
		$this->needs_attachment_link = $link !== 'file';
		$this->grayscale             = $grayscale;
		$this->columns               = $columns;
	}

	/**
	 * Render carousel container template.
	 *
	 * @param array $context - the context.
	 * @return string HTML
	 */
	public function HTML( $context = array() ) { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		// Render the carousel container template, which will take the
		// appropriate strategy to fill it
		ob_start();
		$this->template(
			'carousel-container',
			array_merge(
				$context,
				array(
					'attachments'           => $this->attachments,
					'link'                  => $this->link,
					'needs_attachment_link' => $this->needs_attachment_link,
					'grayscale'             => $this->grayscale,
				)
			)
		);
		$html = ob_get_clean();

		return $html;
	}

	/**
	 * Handle tiled gallery template path.
	 *
	 * @param string $name Template name.
	 * @param array  $context Context array passed to the template.
	 */
	private function template( $name, $context = null ) {
		if ( ! in_array( $name, self::$templates, true ) ) {
			return;
		}

		/**
		 * Filters the Tiled Gallery template path
		 *
		 * @module tiled-gallery
		 * @since 4.4.0
		 *
		 * @param string $path Template path.
		 * @param string $path Template name.
		 * @param array $context Context array passed to the template.
		 */
		require apply_filters( 'jetpack_tiled_gallery_template', __DIR__ . "/templates/$name.php", $name, $context );
	}

	/**
	 * Handle tiled gallery partial path.
	 *
	 * @param string $name - the name.
	 * @param array  $context Context array passed to the partial.
	 */
	private function partial( $name, $context = null ) {
		if ( ! in_array( $name, self::$partials, true ) ) {
			return;
		}

		/**
		 * Filters the Tiled Gallery partial path
		 *
		 * @module tiled-gallery
		 * @since 4.4.0
		 *
		 * @param string $path Partial path.
		 * @param string $path Partial name.
		 * @param array $context Context array passed to the partial.
		 */
		require apply_filters( 'jetpack_tiled_gallery_partial', __DIR__ . "/templates/partials/$name.php", $name, $context );
	}

	/**
	 * Get extra container data.
	 */
	protected function get_container_extra_data() {
		global $post;

		$blog_id = (int) get_current_blog_id();

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$likes_blog_id = $blog_id;
		} else {
			$likes_blog_id = Jetpack_Options::get_option( 'id' );
		}

		if ( class_exists( 'Jetpack_Carousel' ) || in_array( 'carousel', Jetpack::get_active_modules(), true ) || 'carousel' === $this->link ) {
			$extra_data = array(
				'blog_id'       => $blog_id,
				'permalink'     => get_permalink( isset( $post->ID ) ? $post->ID : 0 ),
				'likes_blog_id' => $likes_blog_id,
			);
		} else {
			$extra_data = null;
		}

		return $extra_data;
	}
}

