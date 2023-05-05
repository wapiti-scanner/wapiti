<?php
/**
 * Gutenberg Editor notice for Edit Post Education template for Lite.
 *
 * @since 1.8.1
 *
 * @var string $message Notice message.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="wpforms-edit-post-education-notice-body">
	<p>
		<strong><?php esc_html_e( 'Oh hey, it looks like you\'re working on a Contact page.', 'wpforms-lite' ); ?></strong>
	</p>
	<p>
		<?php
		echo wp_kses(
			$message,
			[
				'a' => [
					'href'   => [],
					'target' => [],
					'rel'    => [],
				],
			]
		);
		?>
	</p>
</div>
