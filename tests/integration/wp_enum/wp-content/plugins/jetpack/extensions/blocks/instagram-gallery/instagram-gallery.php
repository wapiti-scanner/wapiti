<?php
/**
 * Instagram Gallery Block.
 *
 * @since 8.5.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Instagram_Gallery;

use Automattic\Jetpack\Blocks;
use Jetpack;
use Jetpack_Gutenberg;
use Jetpack_Instagram_Gallery_Helper;

const FEATURE_NAME = 'instagram-gallery';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	if ( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) || Jetpack::is_connection_ready() ) {
		Blocks::jetpack_register_block(
			BLOCK_NAME,
			array( 'render_callback' => __NAMESPACE__ . '\render_block' )
		);
	}
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Instagram Gallery block render callback.
 *
 * @param array  $attributes Array containing the Instagram Gallery block attributes.
 * @param string $content The Instagram Gallery block content.
 *
 * @return string
 */
function render_block( $attributes, $content ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
	if ( ! array_key_exists( 'accessToken', $attributes ) ) {
		return '';
	}

	$access_token         = $attributes['accessToken'];
	$columns              = get_instagram_gallery_attribute( 'columns', $attributes );
	$count                = get_instagram_gallery_attribute( 'count', $attributes );
	$is_stacked_on_mobile = get_instagram_gallery_attribute( 'isStackedOnMobile', $attributes );
	$spacing              = get_instagram_gallery_attribute( 'spacing', $attributes );

	$grid_classes = Blocks::classes(
		FEATURE_NAME,
		$attributes,
		array(
			'wp-block-jetpack-instagram-gallery__grid',
			'wp-block-jetpack-instagram-gallery__grid-columns-' . $columns,
			( $is_stacked_on_mobile ? 'is-stacked-on-mobile' : null ),
		)
	);

	$grid_style = sprintf(
		'grid-gap: %1$spx; --latest-instagram-posts-spacing: %1$spx;',
		$spacing
	);

	if ( ! class_exists( 'Jetpack_Instagram_Gallery_Helper' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/_inc/lib/class-jetpack-instagram-gallery-helper.php';
	}
	$gallery = Jetpack_Instagram_Gallery_Helper::get_instagram_gallery( $access_token, $count );

	if ( is_wp_error( $gallery ) || ! property_exists( $gallery, 'images' ) || 'ERROR' === $gallery->images ) {
		if ( ! current_user_can( 'edit_post', get_the_ID() ) ) {
			return '';
		}

		$connection_unavailable = is_wp_error( $gallery ) && 'instagram_connection_unavailable' === $gallery->get_error_code();

		$error_message = $connection_unavailable
			? $gallery->get_error_message()
			: esc_html__( 'An error occurred in the Latest Instagram Posts block. Please try again later.', 'jetpack' );

		$message = $error_message
			. '<br />'
			. esc_html__( '(Only administrators and the post author will see this message.)', 'jetpack' );
		return Jetpack_Gutenberg::notice( $message, 'error', Blocks::classes( FEATURE_NAME, $attributes ) );
	}

	if ( empty( $gallery->images ) ) {
		return '';
	}

	$images = array_slice( $gallery->images, 0, $count );

	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	ob_start();
	?>
	<?php if ( Blocks::is_amp_request() ) : ?>
		<style>
			.wp-block-jetpack-instagram-gallery__grid .wp-block-jetpack-instagram-gallery__grid-post amp-img img {
				object-fit: cover;
			}
		</style>
	<?php endif; ?>
	<div class="<?php echo esc_attr( $grid_classes ); ?>" style="<?php echo esc_attr( $grid_style ); ?>">
		<?php foreach ( $images as $image ) : ?>
			<a
				class="wp-block-jetpack-instagram-gallery__grid-post"
				href="<?php echo esc_url( $image->link ); ?>"
				rel="noopener noreferrer"
				target="_blank"
			>
				<img
					alt="<?php echo esc_attr( $image->title ? $image->title : $image->link ); ?>"
					src="<?php echo esc_url( $image->url ); ?>"
					loading="lazy"
				/>
			</a>
		<?php endforeach; ?>
	</div>

	<?php
	return ob_get_clean();
}

/**
 * Get Instagram Gallery block attribute.
 *
 * @param string $attribute  String containing the attribute name to get.
 * @param array  $attributes Array containing the Instagram Gallery block attributes.
 *
 * @return mixed
 */
function get_instagram_gallery_attribute( $attribute, $attributes ) {
	if ( array_key_exists( $attribute, $attributes ) ) {
		return $attributes[ $attribute ];
	}

	$default_attributes = array(
		'columns'           => 3,
		'count'             => 9,
		'isStackedOnMobile' => true,
		'spacing'           => 10,
	);

	if ( array_key_exists( $attribute, $default_attributes ) ) {
		return $default_attributes[ $attribute ];
	}
}
