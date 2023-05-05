<?php
/**
 * Challenge HTML template specific to Form Builder.
 *
 * @since 1.6.2
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="wpforms-challenge-tooltips">
	<div id="tooltip-content1">
		<h3><?php esc_html_e( 'Name Your Form', 'wpforms-lite' ); ?></h3>
		<p><?php esc_html_e( 'Give your form a name so you can easily identify it.', 'wpforms-lite' ); ?></p>
		<button type="button" class="wpforms-challenge-step1-done wpforms-challenge-done-btn"><?php esc_html_e( 'Done', 'wpforms-lite' ); ?></button>
	</div>

	<div id="tooltip-content2">
		<h3><?php esc_html_e( 'Select a Template', 'wpforms-lite' ); ?></h3>
		<p><?php esc_html_e( 'Build your form from scratch or use one of our pre-made templates.', 'wpforms-lite' ); ?></p>
	</div>

	<div id="tooltip-content3">
		<p><?php esc_html_e( 'You can add additional fields to your form, if you need them.', 'wpforms-lite' ); ?></p>
		<button type="button" class="wpforms-challenge-step3-done wpforms-challenge-done-btn"><?php esc_html_e( 'Done', 'wpforms-lite' ); ?></button>
	</div>

	<div id="tooltip-content4">
		<h3><?php esc_html_e( 'Check Notification Settings', 'wpforms-lite' ); ?></h3>
		<p><?php esc_html_e( 'The default notification settings might be sufficient, but double&#8209;check to be sure.', 'wpforms-lite' ); ?></p>
		<button type="button" class="wpforms-challenge-step4-done wpforms-challenge-done-btn"><?php esc_html_e( 'Done', 'wpforms-lite' ); ?></button>
	</div>
</div>

<div class="wpforms-challenge-popup-container">
	<div id="wpforms-challenge-welcome-builder-popup" class="wpforms-challenge-popup wpforms-challenge-popup-plain">
		<div class="wpforms-challenge-popup-content">
			<h3><?php esc_html_e( 'Welcome to the Form Builder', 'wpforms-lite' ); ?></h3>
			<p><?php esc_html_e( 'Our form builder is a full-screen, distraction-free experience where you manage your forms. The following steps will walk you through essential areas.', 'wpforms-lite' ); ?></p>
			<button type="button" class="wpforms-challenge-popup-btn"><?php esc_html_e( 'Let’s Go!', 'wpforms-lite' ); ?></button>
		</div>
	</div>
</div>
