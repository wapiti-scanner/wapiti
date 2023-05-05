<?php
/**
 * "Revisions are disabled" notice in the Form Builder Revisions panel.
 *
 * @since 1.7.3
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class='wpforms-revisions-notice wpforms-revisions-notice-error'>
	<h2><?php esc_html_e( 'Form Revisions Are Disabled', 'wpforms-lite' ); ?></h2>
	<p><?php esc_html_e( 'It appears that revisions are disabled on your WordPress installation. You can enable revisions for WPForms while leaving posts revisions disabled.', 'wpforms-lite' ); ?></p>

	<a href="https://wpforms.com/docs/how-to-use-form-revisions-in-wpforms/#enable-post-revisions" target='_blank' rel='noopener noreferrer' class='button button-primary button-large'>
		<?php esc_html_e( 'Learn How', 'wpforms-lite' ); ?>
	</a>
</div>
