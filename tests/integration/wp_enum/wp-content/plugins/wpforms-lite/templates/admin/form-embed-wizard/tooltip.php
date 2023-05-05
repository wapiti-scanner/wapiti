<?php
/**
 * Form Embed Wizard.
 * Embed page tooltip HTML template.
 *
 * @since 1.6.2
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="wpforms-admin-form-embed-wizard-tooltip">
	<div id="wpforms-admin-form-embed-wizard-tooltip-content">
		<?php if ( wpforms_is_gutenberg_active() ) : // Gutenberg content. ?>
			<h3><?php esc_html_e( 'Add a Block', 'wpforms-lite' ); ?></h3>
			<p>
				<?php
				printf(
					wp_kses( /* translators: %s - Link to the WPForms documentation page. */
						__( 'Click the plus button, search for WPForms, click the block to<br>embed it. <a href="%s" target="_blank" rel="noopener noreferrer">Learn More</a>.', 'wpforms-lite' ),
						[
							'a'  => [
								'href'   => [],
								'rel'    => [],
								'target' => [],
							],
							'br' => [],
						]
					),
					'https://wpforms.com/docs/creating-first-form/#display-form'
				);
				?>
			</p>
			<i class="wpforms-admin-form-embed-wizard-tooltips-red-arrow"></i>
		<?php else : ?>
			<h3><?php esc_html_e( 'Embed in a Page', 'wpforms-lite' ); ?></h3>
			<p><?php esc_html_e( 'Click the “Add Form” button, select your form, then add the embed code.', 'wpforms-lite' ); ?></p>
		<?php endif; ?>
		<button type="button" class="wpforms-admin-form-embed-wizard-done-btn"><?php esc_html_e( 'Done', 'wpforms-lite' ); ?></button>
	</div>
</div>
