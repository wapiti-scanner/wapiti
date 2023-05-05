<?php
/**
 * Classic Editor notice for Edit Post Education template for Lite.
 *
 * @since 1.8.1
 *
 * @var string $message Notice message.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="wpforms-edit-post-education-notice wpforms-hidden">
	<?php
	// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	echo wpforms_render(
		'education/admin/edit-post/notice',
		[
			'message' => $message,
		],
		true
	)
	?>
	<button type="button" class="wpforms-edit-post-education-notice-close notice-dismiss">
		<span class="screen-reader-text"><?php esc_html_e( 'Dismiss this notice.', 'wpforms-lite' ); ?></span>
	</button>
</div>
