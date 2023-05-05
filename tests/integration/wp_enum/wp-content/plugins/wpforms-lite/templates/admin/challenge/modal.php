<?php
/**
 * Challenge main modal window template.
 *
 * @since 1.6.2
 *
 * @var string  $state
 * @var integer $step
 * @var integer $minutes
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="wpforms-challenge <?php echo 'start' === $state ? 'wpforms-challenge-start' : ''; ?>"
	data-wpforms-challenge-saved-step="<?php echo absint( $step ); ?>">

	<div class="wpforms-challenge-list-block">
		<i class="list-block-button toggle-list" title="<?php esc_attr_e( 'Toggle list', 'wpforms-lite' ); ?>"></i>
		<i class="list-block-button challenge-skip" title="<?php esc_attr_e( 'Skip challenge', 'wpforms-lite' ); ?>"
			data-cancel-title="<?php esc_attr_e( 'Cancel challenge', 'wpforms-lite' ); ?>"></i>
		<p>
			<?php
			echo wp_kses(
				sprintf(
					/* translators: %1$d - Number of minutes; %2$s - Single or plural word 'minute'. */
					__( 'Complete the <b>WPForms Challenge</b> and get up and running within %1$d&nbsp;%2$s.', 'wpforms-lite' ),
					absint( $minutes ),
					_n( 'minute', 'minutes', absint( $minutes ), 'wpforms-lite' )
				),
				[ 'b' => [] ]
			);
			?>
		</p>
		<ul class="wpforms-challenge-list">
			<li class="wpforms-challenge-step1-item"><?php esc_html_e( 'Name Your Form', 'wpforms-lite' ); ?></li>
			<li class="wpforms-challenge-step2-item"><?php esc_html_e( 'Select a Template', 'wpforms-lite' ); ?></li>
			<li class="wpforms-challenge-step3-item"><?php esc_html_e( 'Add Fields to Your Form', 'wpforms-lite' ); ?></li>
			<li class="wpforms-challenge-step4-item"><?php esc_html_e( 'Check Notifications', 'wpforms-lite' ); ?></li>
			<li class="wpforms-challenge-step5-item"><?php esc_html_e( 'Embed in a Page', 'wpforms-lite' ); ?></li>
			<li class="wpforms-challenge-completed"><?php esc_html_e( 'Challenge Complete', 'wpforms-lite' ); ?></li>
		</ul>
	</div>

	<div class="wpforms-challenge-bar" style="display:none">
		<div></div>
	</div>

	<div class="wpforms-challenge-block-timer">
		<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/challenge/sullie-circle.png' ); ?>" alt="<?php esc_html_e( 'Sullie the WPForms mascot', 'wpforms-lite' ); ?>">
		<div>
			<h3><?php esc_html_e( 'WPForms Challenge', 'wpforms-lite' ); ?></h3>
			<p>
				<?php
				printf(
					/* translators: %s - minutes in 2:00 format. */
					esc_html__( '%s remaining', 'wpforms-lite' ),
					'<span id="wpforms-challenge-timer">' . absint( $minutes ) . ':00</span>'
				);
				?>
			</p>
		</div>
	</div>

	<div class="wpforms-challenge-block-under-timer">
		<?php if ( 'start' === $state ) : ?>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpforms-builder' ) ); ?>" class="wpforms-btn wpforms-btn-md wpforms-btn-orange wpforms-challenge-start">
				<?php esc_html_e( 'Start Challenge', 'wpforms-lite' ); ?>
			</a>
		<?php elseif ( 'progress' === $state ) : ?>
			<button type="button" class="wpforms-btn wpforms-btn-md wpforms-btn-grey wpforms-challenge-pause"><?php esc_html_e( 'Pause', 'wpforms-lite' ); ?></button>
			<button type="button" class="wpforms-btn wpforms-btn-md wpforms-btn-orange wpforms-challenge-resume" style="display: none;"><?php esc_html_e( 'Continue', 'wpforms-lite' ); ?></button>
			<button type="button" class="wpforms-btn wpforms-btn-md wpforms-btn-orange wpforms-challenge-end" style="display: none;"><?php esc_html_e( 'End Challenge', 'wpforms-lite' ); ?></button>
		<?php endif; ?>
	</div>
</div>
