<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Jetpack Tiled Gallery Item class.
 */
abstract class Jetpack_Tiled_Gallery_Item {

	/**
	 * The image data.
	 *
	 * @var object
	 */
	public $image;

	/**
	 * Constructor function.
	 *
	 * @param object $attachment_image - the attachment image.
	 * @param string $needs_attachment_link - the attachment link.
	 * @param bool   $grayscale - if the image is in grayscale.
	 */
	public function __construct( $attachment_image, $needs_attachment_link, $grayscale ) {
		$this->image     = $attachment_image;
		$this->grayscale = $grayscale;

		$this->image_title = $this->image->post_title;

		$this->image_alt = get_post_meta( $this->image->ID, '_wp_attachment_image_alt', true );
		// If no Alt value, use the caption
		if ( empty( $this->image_alt ) && ! empty( $this->image->post_excerpt ) ) {
			$this->image_alt = trim( wp_strip_all_tags( $this->image->post_excerpt ) );
		}
		// If still no Alt value, use the title
		if ( empty( $this->image_alt ) && ! empty( $this->image->post_title ) ) {
			$this->image_alt = trim( wp_strip_all_tags( $this->image->post_title ) );
		}

		$this->orig_file = wp_get_attachment_url( $this->image->ID );
		$this->link      = $needs_attachment_link
			? get_attachment_link( $this->image->ID )
			// The filter will photonize the URL if and only if Photon is active
			: apply_filters( 'jetpack_photon_url', $this->orig_file );

		$img_args = array(
			'w' => $this->image->width,
			'h' => $this->image->height,
		);
		// If h and w are the same, there's a reasonably good chance the image will need cropping to avoid being stretched.
		if ( $this->image->height === $this->image->width ) {
			$img_args['crop'] = true;
		}
		// The function will always photonoize the URL (even if Photon is
		// not active). We need to photonize the URL to set the width/height.
		$this->img_src = jetpack_photon_url( $this->orig_file, $img_args );
	}

	/**
	 * Handle the fuzzy image meta.
	 *
	 * @return array
	 */
	public function fuzzy_image_meta() {
		$meta     = wp_get_attachment_metadata( $this->image->ID );
		$img_meta = ( ! empty( $meta['image_meta'] ) ) ? (array) $meta['image_meta'] : array();
		if ( ! empty( $img_meta ) ) {
			foreach ( $img_meta as $k => $v ) {
				if ( 'latitude' === $k || 'longitude' === $k ) {
					unset( $img_meta[ $k ] );
				}
			}
		}

		return $img_meta;
	}

	/**
	 * Return the meta width.
	 *
	 * @return int|string
	 */
	public function meta_width() {
		$meta = wp_get_attachment_metadata( $this->image->ID );
		return isset( $meta['width'] ) ? (int) $meta['width'] : '';
	}

	/**
	 * Return the meta height.
	 *
	 * @return int|string
	 */
	public function meta_height() {
		$meta = wp_get_attachment_metadata( $this->image->ID );
		return isset( $meta['height'] ) ? (int) $meta['height'] : '';
	}

	/**
	 * Return the medium file info.
	 *
	 * @return array|string
	 */
	public function medium_file() {
		$medium_file_info = wp_get_attachment_image_src( $this->image->ID, 'medium' );
		$medium_file      = isset( $medium_file_info[0] ) ? $medium_file_info[0] : '';
		return $medium_file;
	}

	/**
	 * Return large file info.
	 *
	 * @return array|string
	 */
	public function large_file() {
		$large_file_info = wp_get_attachment_image_src( $this->image->ID, 'large' );
		$large_file      = isset( $large_file_info[0] ) ? $large_file_info[0] : '';
		return $large_file;
	}
}

/**
 * Tiled gallery rectangular item class.
 */
class Jetpack_Tiled_Gallery_Rectangular_Item extends Jetpack_Tiled_Gallery_Item { // phpcs:ignore Generic.Files.OneObjectStructurePerFile.MultipleFound, Generic.Classes.OpeningBraceSameLine.ContentAfterBrace
	/**
	 * Constructor function.
	 *
	 * @param object $attachment_image - the attachment image.
	 * @param string $needs_attachment_link - the attachment link.
	 * @param bool   $grayscale - if the image is in grayscale.
	 */
	public function __construct( $attachment_image, $needs_attachment_link, $grayscale ) {
		parent::__construct( $attachment_image, $needs_attachment_link, $grayscale );
		$this->img_src_grayscale = jetpack_photon_url( $this->img_src, array( 'filter' => 'grayscale' ) );

		$this->size = 'large';

		if ( $this->image->width < 250 ) {
			$this->size = 'small';
		}
	}
}

/**
 * Tiled gallery square item class.
 */
class Jetpack_Tiled_Gallery_Square_Item extends Jetpack_Tiled_Gallery_Item { // phpcs:ignore Generic.Files.OneObjectStructurePerFile.MultipleFound, Generic.Classes.OpeningBraceSameLine.ContentAfterBrace
	/**
	 * Constructor function.
	 *
	 * @param object $attachment_image - the attachment image.
	 * @param string $needs_attachment_link - the attachment link.
	 * @param bool   $grayscale - if the image is in grayscale.
	 */
	public function __construct( $attachment_image, $needs_attachment_link, $grayscale ) {
		parent::__construct( $attachment_image, $needs_attachment_link, $grayscale );
		$this->img_src_grayscale = jetpack_photon_url(
			$this->img_src,
			array(
				'filter' => 'grayscale',
				'resize' => array(
					$this->image->width,
					$this->image->height,
				),
			)
		);
	}
}

/**
 * Tiled gallery circle item class.
 */
class Jetpack_Tiled_Gallery_Circle_Item extends Jetpack_Tiled_Gallery_Square_Item { // phpcs:ignore Generic.Files.OneObjectStructurePerFile.MultipleFound, Generic.Classes.OpeningBraceSameLine.ContentAfterBrace
}
