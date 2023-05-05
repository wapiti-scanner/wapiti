<?php
/**
 * GIF Block.
 *
 * @since 7.0.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Gif;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'gif';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array( 'render_callback' => __NAMESPACE__ . '\render_block' )
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Gif block registration/dependency declaration.
 *
 * @param array $attr - Array containing the gif block attributes.
 *
 * @return string
 */
function render_block( $attr ) {
	$padding_top = isset( $attr['paddingTop'] ) ? $attr['paddingTop'] : 0;
	$style       = 'padding-top:' . $padding_top;
	$giphy_url   = isset( $attr['giphyUrl'] )
		? Jetpack_Gutenberg::validate_block_embed_url( $attr['giphyUrl'], array( 'giphy.com' ) )
		: null;
	$search_text = isset( $attr['searchText'] ) ? $attr['searchText'] : '';
	$caption     = isset( $attr['caption'] ) ? $attr['caption'] : null;

	if ( ! $giphy_url ) {
		return null;
	}

	$classes = Blocks::classes( FEATURE_NAME, $attr );

	$placeholder = sprintf( '<a href="%s">%s</a>', esc_url( $giphy_url ), esc_attr( $search_text ) );

	ob_start();
	?>
	<div class="<?php echo esc_attr( $classes ); ?>">
		<figure>
			<?php if ( Blocks::is_amp_request() ) : ?>
				<amp-iframe src="<?php echo esc_url( $giphy_url ); ?>" width="100" height="<?php echo absint( $padding_top ); ?>" sandbox="allow-scripts allow-same-origin" layout="responsive">
					<div placeholder>
						<?php echo wp_kses_post( $placeholder ); ?>
					</div>
				</amp-iframe>
			<?php else : ?>
				<div class="wp-block-jetpack-gif-wrapper" style="<?php echo esc_attr( $style ); ?>">
					<iframe src="<?php echo esc_url( $giphy_url ); ?>" title="<?php echo esc_attr( $search_text ); ?>"></iframe>
				</div>
			<?php endif; ?>
			<?php if ( $caption ) : ?>
				<figcaption class="wp-block-jetpack-gif-caption gallery-caption"><?php echo wp_kses_post( $caption ); ?></figcaption>
			<?php endif; ?>
		</figure>
	</div>
	<?php
	$html = ob_get_clean();

	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	return $html;
}
