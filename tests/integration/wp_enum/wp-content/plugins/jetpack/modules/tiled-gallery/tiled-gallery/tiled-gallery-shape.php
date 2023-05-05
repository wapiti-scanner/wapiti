<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
// phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound
/**
 * Jetpack tiled gallery shape class.
 */
class Jetpack_Tiled_Gallery_Shape {

	/**
	 * Shapes used.
	 *
	 * @var array
	 */
	public static $shapes_used = array();

	/**
	 * Constructor class.
	 *
	 * @param object $images - the images.
	 */
	public function __construct( $images ) {
		$this->images      = $images;
		$this->images_left = count( $images );
	}

	/**
	 * Return the sum of ratio images.
	 *
	 * @param int $number_of_images - the number of images.
	 *
	 * @return int
	 */
	public function sum_ratios( $number_of_images = 3 ) {
		return array_sum( array_slice( wp_list_pluck( $this->images, 'ratio' ), 0, $number_of_images ) );
	}

	/**
	 * Check that the next images are symmetric
	 *
	 * @return bool
	 */
	public function next_images_are_symmetric() {
		return $this->images_left > 2 && $this->images[0]->ratio === $this->images[2]->ratio;
	}

	/**
	 * Is not as previous.
	 *
	 * @param int $n - the previous image.
	 *
	 * @return bool
	 */
	public function is_not_as_previous( $n = 1 ) {
		return ! in_array( get_class( $this ), array_slice( self::$shapes_used, -$n ), true );
	}

	/**
	 * Check if the theme is wide.
	 *
	 * @return bool
	 */
	public function is_wide_theme() {
		return Jetpack::get_content_width() > 1000;
	}

	/**
	 * Check if the image is landscape.
	 *
	 * @param object $image - the image.
	 *
	 * @return bool
	 */
	public function image_is_landscape( $image ) {
		return $image->ratio >= 1 && $image->ratio < 2;
	}

	/**
	 * Check if the image is portrait.
	 *
	 * @param object $image - the image.
	 *
	 * @return bool
	 */
	public function image_is_portrait( $image ) {
		return $image->ratio < 1;
	}

	/**
	 * Check if the image is panoramic.
	 *
	 * @param object $image - the image.
	 *
	 * @return bool
	 */
	public function image_is_panoramic( $image ) {
		return $image->ratio >= 2;
	}

	/**
	 * Set the last shape.
	 *
	 * @param string $last_shape - the last shape.
	 */
	public static function set_last_shape( $last_shape ) {
		self::$shapes_used[] = $last_shape;
	}

	/**
	 * Reset the last shape.
	 */
	public static function reset_last_shape() {
		self::$shapes_used = array();
	}
}

/**
 * Jetpack tiled gallery three class.
 */
class Jetpack_Tiled_Gallery_Three extends Jetpack_Tiled_Gallery_Shape {

	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 1, 1, 1 );

	/**
	 * Checks if there's enough images.
	 *
	 * @return array
	 */
	public function is_possible() {
		$ratio             = $this->sum_ratios( 3 );
		$has_enough_images = $this->images_left >= 3 && ! in_array( $this->images_left, array( 4, 6 ), true );
		return $has_enough_images && $this->is_not_as_previous( 3 ) &&
			( ( $ratio < 2.5 ) || ( $ratio < 5 && $this->next_images_are_symmetric() ) || $this->is_wide_theme() );
	}
}

/**
 * Jetpack tiled gallery four class.
 */
class Jetpack_Tiled_Gallery_Four extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 1, 1, 1, 1 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->is_not_as_previous() &&
			(
				( $this->sum_ratios( 4 ) < 3.5 && $this->images_left > 5 ) ||
				( $this->sum_ratios( 4 ) < 7 && $this->images_left === 4 )
			);
	}
}

/**
 * Jetpack tiled gallery five class.
 */
class Jetpack_Tiled_Gallery_Five extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 1, 1, 1, 1, 1 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->is_wide_theme() && $this->is_not_as_previous() && $this->sum_ratios( 5 ) < 5 &&
			( $this->images_left === 5 || ( $this->images_left !== 10 && $this->images_left > 6 ) );
	}
}

/**
 * Jetpack tiled gallery two one class.
 */
class Jetpack_Tiled_Gallery_Two_One extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 2, 1 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->is_not_as_previous( 3 ) && $this->images_left >= 2 &&
			$this->images[2]->ratio < 1.6 && $this->images[0]->ratio >= 0.9 && $this->images[0]->ratio < 2.0 && $this->images[1]->ratio >= 0.9 && $this->images[1]->ratio < 2.0;
	}
}

/**
 * Jetpack tiled gallery one two class.
 */
class Jetpack_Tiled_Gallery_One_Two extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 1, 2 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->is_not_as_previous( 3 ) && $this->images_left >= 2 &&
			$this->images[0]->ratio < 1.6 && $this->images[1]->ratio >= 0.9 && $this->images[1]->ratio < 2.0 && $this->images[2]->ratio >= 0.9 && $this->images[2]->ratio < 2.0;
	}
}

/**
 * Jetpack tiled gallery one three class.
 */
class Jetpack_Tiled_Gallery_One_Three extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 1, 3 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->is_not_as_previous( 3 ) && $this->images_left > 3 &&
			$this->image_is_portrait( $this->images[0] ) &&
			$this->image_is_landscape( $this->images[1] ) &&
			$this->image_is_landscape( $this->images[2] ) &&
			$this->image_is_landscape( $this->images[3] );
	}
}

/**
 * Jetpack tiled gallery three one class.
 */
class Jetpack_Tiled_Gallery_Three_One extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 3, 1 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->is_not_as_previous( 3 ) && $this->images_left > 3 &&
			$this->image_is_portrait( $this->images[3] ) &&
			$this->image_is_landscape( $this->images[0] ) &&
			$this->image_is_landscape( $this->images[1] ) &&
			$this->image_is_landscape( $this->images[2] );
	}
}

/**
 * Jetpack tiled gallery panoramic class.
 */
class Jetpack_Tiled_Gallery_Panoramic extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 1 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->image_is_panoramic( $this->images[0] );
	}
}

/**
 * Jetpack tiled gallery symmetric class.
 */
class Jetpack_Tiled_Gallery_Symmetric_Row extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 1, 2, 1 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->is_not_as_previous( 5 ) &&
			$this->images_left > 3 &&
			$this->images_left !== 5 &&
			$this->image_is_portrait( $this->images[0] ) &&
			$this->image_is_landscape( $this->images[1] ) &&
			$this->image_is_landscape( $this->images[2] ) &&
			$this->image_is_portrait( $this->images[3] );
	}
}

/**
 * Jetpack tiled gallery reverse symmetric row class.
 */
class Jetpack_Tiled_Gallery_Reverse_Symmetric_Row extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 2, 1, 2 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->is_not_as_previous( 5 ) && $this->images_left > 15 &&
			$this->image_is_landscape( $this->images[0] ) &&
			$this->image_is_landscape( $this->images[1] ) &&
			$this->image_is_portrait( $this->images[2] ) &&
			$this->image_is_landscape( $this->images[3] ) &&
			$this->image_is_landscape( $this->images[4] );
	}
}

/**
 * Jetpack tiled gallery long symmetric row class.
 */
class Jetpack_Tiled_Gallery_Long_Symmetric_Row extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array( 3, 1, 3 );

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return $this->is_not_as_previous( 5 ) && $this->images_left > 15 &&
			$this->image_is_landscape( $this->images[0] ) &&
			$this->image_is_landscape( $this->images[1] ) &&
			$this->image_is_landscape( $this->images[2] ) &&
			$this->image_is_portrait( $this->images[3] ) &&
			$this->image_is_landscape( $this->images[4] ) &&
			$this->image_is_landscape( $this->images[5] ) &&
			$this->image_is_landscape( $this->images[6] );
	}
}

/**
 * Jetpack tiled gallery three columns class.
 */
class Jetpack_Tiled_Gallery_Three_Columns extends Jetpack_Tiled_Gallery_Shape {
	/**
	 * The shape.
	 *
	 * @var array
	 */
	public $shape = array();

	/**
	 * Constructor class.
	 *
	 * @param object $images - the images.
	 */
	public function __construct( $images ) {
		parent::__construct( $images );

		$total_ratio              = $this->sum_ratios( $this->images_left );
		$approximate_column_ratio = $total_ratio / 3;
		$column_one_images        = 0;
		$column_two_images        = 0;
		$column_three_images      = 0;
		$sum                      = 0;

		foreach ( $this->images as $image ) {
			if ( $sum <= $approximate_column_ratio ) {
				++$column_one_images;
			}

			if ( $sum > $approximate_column_ratio && $sum <= 2 * $approximate_column_ratio ) {
				++$column_two_images;
			}
			$sum += $image->ratio;
		}

		$column_three_images = $this->images_left - $column_two_images - $column_one_images;

		if ( $column_one_images ) {
			$this->shape[] = $column_one_images;
		}

		if ( $column_two_images ) {
			$this->shape[] = $column_two_images;
		}

		if ( $column_three_images ) {
			$this->shape[] = $column_three_images;
		}
	}

	/**
	 * Check if it's possible.
	 *
	 * @return bool
	 */
	public function is_possible() {
		return ! empty( $this->shape );
	}
}
