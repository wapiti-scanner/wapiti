<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
require_once __DIR__ . '/tiled-gallery-layout.php';
require_once __DIR__ . '/tiled-gallery-shape.php';
require_once __DIR__ . '/tiled-gallery-item.php';

// phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound
/**
 * Tiled gallery rectangular layout.
 */
class Jetpack_Tiled_Gallery_Layout_Rectangular extends Jetpack_Tiled_Gallery_Layout {

	/**
	 * The layout type.
	 *
	 * @var string
	 */
	protected $type = 'rectangular';

	/**
	 * The HTML function.
	 *
	 * @param array $context - the context array, unused.
	 * @return string HTML
	 */
	public function HTML( $context = array() ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$grouper = new Jetpack_Tiled_Gallery_Grouper( $this->attachments );
		Jetpack_Tiled_Gallery_Shape::reset_last_shape();

		return parent::HTML( array( 'rows' => $grouper->grouped_images ) );
	}
}

/**
 * Tiled gallery layout columns class.
 */
class Jetpack_Tiled_Gallery_Layout_Columns extends Jetpack_Tiled_Gallery_Layout {

	/**
	 * The layout type.
	 *
	 * @var string
	 */
	protected $type = 'rectangular'; // It doesn't need separate template for now

	/**
	 * The HTML function.
	 *
	 * @param array $context - the context array, unused.
	 * @return string HTML
	 */
	public function HTML( $context = array() ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$grouper = new Jetpack_Tiled_Gallery_Grouper( $this->attachments, array( 'Three_Columns', 'Two' ) );

		return parent::HTML( array( 'rows' => $grouper->grouped_images ) );
	}
}

/**
 * Gallery layout rectangle alis.
 */
class Jetpack_Tiled_Gallery_Layout_Rectangle extends Jetpack_Tiled_Gallery_Layout_Rectangular {}

/**
 * Image grouping and HTML generation logic class.
 */
class Jetpack_Tiled_Gallery_Grouper {

	/**
	 * The margin.
	 *
	 * @var int
	 */
	public $margin = 4;

	/**
	 * Shapes array.
	 * This list is ordered. If you put a shape that's likely to occur on top, it will happen all the time.
	 *
	 * @var array
	 */
	public $shapes = array(
		'Reverse_Symmetric_Row',
		'Long_Symmetric_Row',
		'Symmetric_Row',
		'One_Three',
		'Three_One',
		'One_Two',
		'Five',
		'Four',
		'Three',
		'Two_One',
		'Panoramic',
	);

	/**
	 * Constructor function.
	 *
	 * @param object $attachments - the attachments.
	 * @param array  $shapes - the shapes.
	 */
	public function __construct( $attachments, $shapes = array() ) {
		$content_width = Jetpack_Tiled_Gallery::get_content_width();

		$this->overwrite_shapes( $shapes );
		$this->last_shape     = '';
		$this->images         = $this->get_images_with_sizes( $attachments );
		$this->grouped_images = $this->get_grouped_images();
		$this->apply_content_width( $content_width );
	}

	/**
	 * Overwrite the shapes.
	 *
	 * @param array $shapes - the shapes.
	 */
	public function overwrite_shapes( $shapes ) {
		if ( ! empty( $shapes ) ) {
			$this->shapes = $shapes;
		}
	}

	/**
	 * Get the current row size.
	 *
	 * @return array
	 */
	public function get_current_row_size() {
		$images_left = count( $this->images );
		if ( $images_left < 3 ) {
			return array_fill( 0, $images_left, 1 );
		}

		foreach ( $this->shapes as $shape_name ) {
			$class_name = "Jetpack_Tiled_Gallery_$shape_name";
			$shape      = new $class_name( $this->images );
			if ( $shape->is_possible() ) {
				Jetpack_Tiled_Gallery_Shape::set_last_shape( $class_name );
				return $shape->shape;
			}
		}

		Jetpack_Tiled_Gallery_Shape::set_last_shape( 'Two' );
		return array( 1, 1 );
	}

	/**
	 * Get images with sizes.
	 *
	 * @param object $attachments - the attachments.
	 *
	 * @return array
	 */
	public function get_images_with_sizes( $attachments ) {
		$images_with_sizes = array();

		foreach ( $attachments as $image ) {
			$meta                = wp_get_attachment_metadata( $image->ID );
			$image->width_orig   = ( isset( $meta['width'] ) && $meta['width'] > 0 ) ? $meta['width'] : 1;
			$image->height_orig  = ( isset( $meta['height'] ) && $meta['height'] > 0 ) ? $meta['height'] : 1;
			$image->ratio        = $image->width_orig / $image->height_orig;
			$image->ratio        = $image->ratio ? $image->ratio : 1;
			$images_with_sizes[] = $image;
		}

		return $images_with_sizes;
	}

	/**
	 * Get the current row size.
	 *
	 * @return array
	 */
	public function read_row() {
		$vector = $this->get_current_row_size();

		$row = array();
		foreach ( $vector as $group_size ) {
			$row[] = new Jetpack_Tiled_Gallery_Group( array_splice( $this->images, 0, $group_size ) );
		}

		return $row;
	}

	/**
	 * Get grouped images.
	 *
	 * @return array
	 */
	public function get_grouped_images() {
		$grouped_images = array();

		while ( ! empty( $this->images ) ) {
			$grouped_images[] = new Jetpack_Tiled_Gallery_Row( $this->read_row() );
		}

		return $grouped_images;
	}

	/**
	 * Apply content width.
	 *
	 * @param int $width - the width.
	 *
	 * @todo split in functions
	 * @todo do not stretch images
	 */
	public function apply_content_width( $width ) {
		foreach ( $this->grouped_images as $row ) {
			$row->width      = $width;
			$row->raw_height = 1 / $row->ratio * ( $width - $this->margin * ( count( $row->groups ) - $row->weighted_ratio ) );
			$row->height     = round( $row->raw_height );

			$this->calculate_group_sizes( $row );
		}
	}

	/**
	 * Calculate group sizes.
	 *
	 * @param object $row - the row.
	 */
	public function calculate_group_sizes( $row ) {
		// Storing the calculated group heights in an array for rounding them later while preserving their sum
		// This fixes the rounding error that can lead to a few ugly pixels sticking out in the gallery
		$group_widths_array = array();
		foreach ( $row->groups as $group ) {
			$group->height = $row->height;
			// Storing the raw calculations in a separate property to prevent rounding errors from cascading down and for diagnostics
			$group->raw_width     = ( $row->raw_height - $this->margin * count( $group->images ) ) * $group->ratio + $this->margin;
			$group_widths_array[] = $group->raw_width;
		}
		$rounded_group_widths_array = Jetpack_Constrained_Array_Rounding::get_rounded_constrained_array( $group_widths_array, $row->width );

		foreach ( $row->groups as $group ) {
			$group->width = array_shift( $rounded_group_widths_array );
			$this->calculate_image_sizes( $group );
		}
	}

	/**
	 * Calculate image sizes.
	 *
	 * @param object $group - the group of images.
	 */
	public function calculate_image_sizes( $group ) {
		// Storing the calculated image heights in an array for rounding them later while preserving their sum
		// This fixes the rounding error that can lead to a few ugly pixels sticking out in the gallery
		$image_heights_array = array();
		foreach ( $group->images as $image ) {
			$image->width = $group->width - $this->margin;
			// Storing the raw calculations in a separate property for diagnostics
			$image->raw_height     = ( $group->raw_width - $this->margin ) / $image->ratio;
			$image_heights_array[] = $image->raw_height;
		}

		$image_height_sum            = $group->height - count( $image_heights_array ) * $this->margin;
		$rounded_image_heights_array = Jetpack_Constrained_Array_Rounding::get_rounded_constrained_array( $image_heights_array, $image_height_sum );

		foreach ( $group->images as $image ) {
			$image->height = array_shift( $rounded_image_heights_array );
		}
	}
}

/**
 * Jetpack tiled row class.
 */
class Jetpack_Tiled_Gallery_Row {

	/**
	 * Constructor class.
	 *
	 * @param object $groups - the group of images.
	 */
	public function __construct( $groups ) {
		$this->groups         = $groups;
		$this->ratio          = $this->get_ratio();
		$this->weighted_ratio = $this->get_weighted_ratio();
	}

	/**
	 * Get the ratio.
	 *
	 * @return int
	 */
	public function get_ratio() {
		$ratio = 0;
		foreach ( $this->groups as $group ) {
			$ratio += $group->ratio;
		}
		return $ratio > 0 ? $ratio : 1;
	}

	/**
	 * Get weighted ratio.
	 *
	 * @return int
	 */
	public function get_weighted_ratio() {
		$weighted_ratio = 0;
		foreach ( $this->groups as $group ) {
			$weighted_ratio += $group->ratio * count( $group->images );
		}
		return $weighted_ratio > 0 ? $weighted_ratio : 1;
	}
}

/**
 * Tiled gallery group class.
 */
class Jetpack_Tiled_Gallery_Group {
	/**
	 * Constructor class.
	 *
	 * @param object $images - the images.
	 */
	public function __construct( $images ) {
		$this->images = $images;
		$this->ratio  = $this->get_ratio();
	}

	/**
	 * Get the ratio.
	 *
	 * @return int
	 */
	public function get_ratio() {
		$ratio = 0;
		foreach ( $this->images as $image ) {
			if ( $image->ratio ) {
				$ratio += 1 / $image->ratio;
			}
		}
		if ( ! $ratio ) {
			return 1;
		}

		return 1 / $ratio;
	}

	/**
	 * The items.
	 *
	 * @param string $needs_attachment_link - the attachment link.
	 * @param bool   $grayscale - if the image is in grayscale.
	 *
	 * @return array
	 */
	public function items( $needs_attachment_link, $grayscale ) {
		$items = array();
		foreach ( $this->images as $image ) {
			$items[] = new Jetpack_Tiled_Gallery_Rectangular_Item( $image, $needs_attachment_link, $grayscale );
		}

		return $items;
	}
}

