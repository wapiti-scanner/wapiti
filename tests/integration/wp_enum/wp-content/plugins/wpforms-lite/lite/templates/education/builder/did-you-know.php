<?php
/**
 * Builder/DidYouKnow Education template for Lite.
 *
 * @since 1.6.6
 *
 * @var string $desc    Message body.
 * @var string $more    Learn More button URL.
 * @var string $link    Upgrade to Pro page URL.
 * @var string $section The slug of the dismissible section.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<section class="wpforms-dyk wpforms-dismiss-container">
	<div class="wpforms-dyk-fbox wpforms-dismiss-out">
		<div class="wpforms-dyk-message">
			<b><?php esc_html_e( 'Did You Know?', 'wpforms-lite' ); ?></b><br>
			<?php echo esc_html( $desc ); ?>
		</div>
		<div class="wpforms-dyk-buttons">
			<?php
			if ( ! empty( $more ) ) {
				echo '<a href="' . esc_url( $more ) . '" class="learn-more">' . esc_html__( 'Learn More', 'wpforms-lite' ) . '</a>';
			}
			?>
			<a href="<?php echo esc_url( $link ); ?>" target="_blank" rel="noopener noreferrer" class="wpforms-btn wpforms-btn-md wpforms-btn-light-grey"><?php esc_html_e( 'Upgrade to Pro', 'wpforms-lite' ); ?></a>
			<button type="button" class="wpforms-dismiss-button" title="<?php esc_attr_e( 'Dismiss this message.', 'wpforms-lite' ); ?>" data-section="builder-did-you-know-<?php echo esc_attr( $section ); ?>"></button>
		</div>
	</div>
</section>
