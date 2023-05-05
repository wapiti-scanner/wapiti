<?php
/**
 * Also Available block.
 *
 * @since 1.7.8
 *
 * @var array $blocks All educational content blocks.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wpforms-panel-content-also-available">
	<?php
	foreach ( $blocks as $key => $block ) :

		if ( empty( $block['show'] ) ) {
			continue;
		}

		$slug  = strtolower( $key );
		$class = ! empty( $block['class'] ) ? $block['class'] : '';
		?>

		<div class="wpforms-panel-content-also-available-item <?php echo sanitize_html_class( "wpforms-panel-content-also-available-item-{$slug}" ); ?>">
			<div class='wpforms-panel-content-also-available-item-logo'>
				<img src="<?php echo esc_url( $block['logo'] ); ?>" alt="<?php echo esc_attr( $block['title'] ); ?>">
			</div>

			<div class='wpforms-panel-content-also-available-item-info'>
				<h3><?php echo esc_html( $block['title'] ); ?></h3>
				<p><?php echo esc_html( $block['description'] ); ?></p>
				<a class="<?php echo sanitize_html_class( $class ); ?>"
				   href="<?php echo esc_url( $block['link'] ); ?>"
				   target="_blank"
				   rel="noopener noreferrer">
					<?php echo esc_html( $block['link_text'] ); ?>
				</a>
			</div>
		</div>

	<?php endforeach; ?>
</div>
