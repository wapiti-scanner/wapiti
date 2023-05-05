<?php
/**
 * "Revisions are limited" notice in the Form Builder Revisions panel.
 *
 * @since 1.7.3
 *
 * @var int $revisions_to_keep How many revisions are kept.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class='wpforms-revisions-notice wpforms-revisions-notice-warning'>
	<h2><?php esc_html_e( 'Form Revisions Are Limited', 'wpforms-lite' ); ?></h2>
	<p>
		<?php
		printf( /* translators: %d Maximum number of revisions to keep. */
			esc_html__( 'Revisions are enabled, but they’re limited to %d. You can increase this by making a simple change to your WordPress configuration.', 'wpforms-lite' ),
			absint( $revisions_to_keep )
		);
		?>
	</p>

	<a href="https://wpforms.com/docs/how-to-use-form-revisions-in-wpforms/#enable-post-revisions" target="_blank" rel="noopener noreferrer" class='button button-primary button-large'>
		<?php esc_html_e( 'Learn How', 'wpforms-lite' ); ?>
	</a>
</div>
