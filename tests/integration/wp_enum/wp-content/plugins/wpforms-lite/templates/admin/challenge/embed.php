<?php
/**
 * Challenge HTML template specific to form embed page.
 *
 * @since 1.6.2
 *
 * @var int    $minutes
 * @var string $congrats_popup_footer Congrats popup footer HTML.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="wpforms-challenge-tooltips">
	<div id="tooltip-content5">
		<?php if ( wpforms_is_gutenberg_active() ) : // Gutenberg content. ?>
			<h3><?php esc_html_e( 'Add a Block', 'wpforms-lite' ); ?></h3>
			<p>
				<?php
				printf(
					wp_kses(
						/* translators: %s - Link to the WPForms documentation page. */
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
					esc_url( wpforms_utm_link( 'https://wpforms.com/docs/creating-first-form/#display-form', 'WPForms Challenge Block', 'Add A Block' ) )
				);
				?>
			</p>
			<i class="wpforms-challenge-tooltips-red-arrow"></i>
		<?php else : ?>
			<h3><?php esc_html_e( 'Embed in a Page', 'wpforms-lite' ); ?></h3>
			<p><?php esc_html_e( 'Click the “Add Form” button, select your form, then add the embed code.', 'wpforms-lite' ); ?></p>
		<?php endif; ?>
		<button type="button" class="wpforms-challenge-step5-done wpforms-challenge-done-btn"><?php esc_html_e( 'Done', 'wpforms-lite' ); ?></button>
	</div>
</div>

<div class="wpforms-challenge-popup-container">
	<div id="wpforms-challenge-congrats-popup" class="wpforms-challenge-popup wpforms-challenge-popup-congrats">
		<i class="wpforms-challenge-popup-close fa fa-times-circle fa-lg"></i>
		<div class="wpforms-challenge-popup-content">
			<h3>
				<?php esc_html_e( 'Congrats, You Did It!', 'wpforms-lite' ); ?>
				<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/challenge/party-popper.png' ); ?>" alt="">
			</h3>
			<p>
				<?php
				echo wp_kses(
					sprintf(
						/* translators: %1$s - Number of minutes in HTML container; %2$s - Single or plural word 'minute'; %3$s - Number of seconds in HTML container; %4$s - Single or plural word 'second'; %5$s - 5 rating star symbols HTML. */
						__( 'You completed the WPForms Challenge in <b>%1$s %2$s %3$s %4$s</b>. Share your success story with other WPForms users and help us spread the word <b>by giving WPForms a 5-star rating (%5$s) on WordPress.org</b>. Thanks for your support and we look forward to bringing you more awesome features.', 'wpforms-lite' ),
						'<span id="wpforms-challenge-congrats-minutes"></span>',
						_n( 'minute', 'minutes', absint( $minutes ), 'wpforms-lite' ),
						'<span id="wpforms-challenge-congrats-seconds"></span>',
						_n( 'second', 'seconds', absint( $minutes ), 'wpforms-lite' ),
						'<span class="rating-stars"><i class="fa fa-star"></i><i class="fa fa-star"></i><i class="fa fa-star"></i><i class="fa fa-star"></i><i class="fa fa-star"></i></span>'
					),
					[
						'span' => [
							'id'    => [],
							'class' => [],
						],
						'b'    => [],
						'i'    => [
							'class' => [],
						],
					]
				);
				?>
			</p>
			<a href="https://wordpress.org/support/plugin/wpforms-lite/reviews/?filter=5#new-post" class="wpforms-challenge-popup-btn wpforms-challenge-popup-rate-btn" target="_blank" rel="noopener"><?php esc_html_e( 'Rate WPForms on WordPress.org', 'wpforms-lite' ); ?>
				<span class="dashicons dashicons-external"></span></a>
		</div>
		<?php echo $congrats_popup_footer; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
	</div>

	<div id="wpforms-challenge-contact-popup" class="wpforms-challenge-popup">
		<div class="wpforms-challenge-popup-header wpforms-challenge-popup-header-contact">
			<i class="wpforms-challenge-popup-close fa fa-times-circle fa-lg"></i>
		</div>
		<div class="wpforms-challenge-popup-content">
			<form id="wpforms-challenge-contact-form">
				<h3><?php esc_html_e( 'Help us improve WPForms', 'wpforms-lite' ); ?></h3>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %1$d - Number of minutes; %2$s - Single or plural word 'minute'. */
							__( 'We\'re sorry that it took longer than %1$d %2$s to create a form. Our goal is to create the most beginner friendly WordPress form plugin. Please take a moment to let us know how we can improve WPForms.', 'wpforms-lite' ),
							absint( $minutes ),
							_n( 'minute', 'minutes', absint( $minutes ), 'wpforms-lite' )
						)
					);
					?>
				</p>
				<textarea class="wpforms-challenge-contact-message"></textarea>
				<?php if ( ! wpforms()->is_pro() ) { ?>
					<label>
						<input type="checkbox" class="wpforms-challenge-contact-permission"><?php esc_html_e( 'Yes, I give WPForms permission to contact me for any follow up questions.', 'wpforms-lite' ); ?>
					</label>
				<?php } ?>
				<button type="submit" class="wpforms-challenge-popup-btn wpforms-challenge-popup-contact-btn"><?php esc_html_e( 'Submit Feedback', 'wpforms-lite' ); ?></button>
			</form>
		</div>
	</div>
</div>
