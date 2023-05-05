<?php
/**
 * Handles more photo metadata.
 *
 * @package jetpack
 */

$item     = $context['item']; // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
$add_link = 'none' !== $this->link; // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable

// We do this for accessibility.  Titles without alt's break screen readers.
if ( empty( $item->image_alt ) && ! empty( $item->image_title ) ) {
	$item->image_alt = $item->image_title;
}
?>
<div class="tiled-gallery-item
<?php
if ( isset( $item->size ) ) {
	echo esc_attr( " tiled-gallery-item-$item->size" );}
?>
" itemprop="associatedMedia" itemscope itemtype="http://schema.org/ImageObject">
	<?php if ( $add_link ) : ?>
	<a href="<?php echo esc_url( $item->link ); ?>" border="0" itemprop="url">
	<?php endif; ?>
		<meta itemprop="width" content="<?php echo esc_attr( $item->image->width ); ?>">
		<meta itemprop="height" content="<?php echo esc_attr( $item->image->height ); ?>">
		<img
			<?php $this->partial( 'carousel-image-args', array( 'item' => $item ) ); // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable ?>
			src="<?php echo esc_url( $item->img_src ); ?>"
			width="<?php echo esc_attr( $item->image->width ); ?>"
			height="<?php echo esc_attr( $item->image->height ); ?>"
			data-original-width="<?php echo esc_attr( $item->image->width ); ?>"
			data-original-height="<?php echo esc_attr( $item->image->height ); ?>"
			itemprop="http://schema.org/image"
			title="<?php echo esc_attr( $item->image_title ); ?>"
			alt="<?php echo esc_attr( $item->image_alt ); ?>"
			style="width: <?php echo esc_attr( $item->image->width ); ?>px; height: <?php echo esc_attr( $item->image->height ); ?>px;"
		/>
	<?php if ( $add_link ) : ?>
	</a>
	<?php endif; ?>

	<?php if ( ! empty( $this->grayscale ) ) : ?>
		<?php if ( $add_link ) : ?>
		<a href="<?php echo esc_url( $item->link ); ?>" border="0" itemprop="url">
		<?php endif; ?>
			<meta itemprop="width" content="<?php echo esc_attr( $item->image->width ); ?>">
			<meta itemprop="height" content="<?php echo esc_attr( $item->image->height ); ?>">
			<img
				class="grayscale"
				src="<?php echo esc_url( $item->img_src_grayscale ); ?>"
				width="<?php echo esc_attr( $item->image->width ); ?>"
				height="<?php echo esc_attr( $item->image->height ); ?>"
				data-original-width="<?php echo esc_attr( $item->image->width ); ?>"
				data-original-height="<?php echo esc_attr( $item->image->height ); ?>"
				itemprop="http://schema.org/image"
				title="<?php echo esc_attr( $item->image_title ); ?>"
				align="left"
				alt="<?php echo esc_attr( $item->image_alt ); ?>"
				style="width: <?php echo esc_attr( $item->image->width ); ?>px; height: <?php echo esc_attr( $item->image->height ); ?>px;"
			/>
		<?php if ( $add_link ) : ?>
		</a>
		<?php endif; ?>
	<?php endif; ?>

	<?php if ( trim( $item->image->post_excerpt ) ) : ?>
		<div class="tiled-gallery-caption" itemprop="caption description">
			<?php echo wptexturize( $item->image->post_excerpt ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</div>
	<?php endif; ?>
</div>
