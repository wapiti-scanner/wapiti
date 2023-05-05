<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
require_once __DIR__ . '/tiled-gallery-layout.php';
require_once __DIR__ . '/tiled-gallery-item.php';

/**
 * Jetpack tiled gallery square layout class.
 */
class Jetpack_Tiled_Gallery_Layout_Square extends Jetpack_Tiled_Gallery_Layout {

	/**
	 * Layout type.
	 *
	 * @var string
	 */
	protected $type = 'square';

	/**
	 * Compute the items.
	 */
	private function compute_items() {
		$content_width  = Jetpack_Tiled_Gallery::get_content_width();
		$images_per_row = ( $this->columns > 1 ? $this->columns : 1 );
		$margin         = 2;

		$margin_space   = ( $images_per_row * $margin ) * 2;
		$size           = floor( ( $content_width - $margin_space ) / $images_per_row );
		$remainder_size = $size;
		$img_size       = $remainder_size;
		$remainder      = count( $this->attachments ) % $images_per_row;
		if ( $remainder > 0 ) {
			$remainder_space = ( $remainder * $margin ) * 2;
			$remainder_size  = floor( ( $content_width - $remainder_space ) / $remainder );
		}

		$c            = 1;
		$items_in_row = 0;
		$rows         = array();
		$row          = new stdClass();
		$row->images  = array();
		foreach ( $this->attachments as $image ) {
			if ( $remainder > 0 && $c <= $remainder ) {
				$img_size = $remainder_size;
			} else {
				$img_size = $size;
			}

			$image->width  = $img_size;
			$image->height = $image->width;

			$item = new Jetpack_Tiled_Gallery_Square_Item( $image, $this->needs_attachment_link, $this->grayscale );

			$row->images[] = $item;
			++$c;
			++$items_in_row;

			if ( $images_per_row === $items_in_row || $remainder + 1 === $c ) {
				$rows[]       = $row;
				$items_in_row = 0;

				$row->height     = $img_size + $margin * 2;
				$row->width      = $content_width;
				$row->group_size = $img_size + 2 * $margin;

				$row         = new stdClass();
				$row->images = array();
			}
		}

		if ( ! empty( $row->images ) ) {
			$row->height     = $img_size + $margin * 2;
			$row->width      = $content_width;
			$row->group_size = $img_size + 2 * $margin;

			$rows[] = $row;
		}

		return $rows;
	}

	/**
	 * The html.
	 *
	 * @param array $context - the context, unused.
	 * @return string HTML
	 */
	public function HTML( $context = array() ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return parent::HTML( array( 'rows' => $this->compute_items() ) );
	}
}

