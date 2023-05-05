<?php
/**
 * Jetpack_Flickr_Widget frontend widget output.
 *
 * @package automattic/jetpack
 */

//phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
?>
<!-- Start of Flickr Widget -->
<div class="flickr-wrapper flickr-size-<?php echo esc_attr( $instance['flickr_image_size'] ); ?>">
	<div class="flickr-images">
		<?php echo $photos; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaping handled in Jetpack_Flickr_Widget class. ?>
	</div>

	<?php if ( isset( $flickr_home ) ) { ?>
		<a class="flickr-more" href="<?php echo esc_url( $flickr_home, array( 'http', 'https' ) ); ?>">
			<?php esc_html_e( 'More Photos', 'jetpack' ); ?>
		</a>
	<?php } ?>
</div>
<!-- End of Flickr Widget -->
