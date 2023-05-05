<?php
/**
 * No forms template.
 *
 * @since 1.6.2
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="wpforms-admin-empty-state-container wpforms-elementor-no-forms">

	<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/empty-states/no-forms.svg' ); ?>" alt=""/>

	<p>
		<?php
		echo wp_kses(
			__( 'You can use <b>WPForms</b> to build contact forms, surveys, payment forms, and more with just a few clicks.', 'wpforms-lite' ),
			[ 'b' => [] ]
		);
		?>
	</p>

	<button type="button" class="wpforms-btn"><?php esc_html_e( 'Create a form', 'wpforms-lite' ); ?></button>

	<p class="wpforms-admin-no-forms-footer">
		<?php
		printf(
			wp_kses( /* translators: %s - URL to the documentation article. */
				__( 'Need some help? Check out our <a href="%s" target="_blank" rel="noopener noreferrer">comprehensive guide</a>.', 'wpforms-lite' ),
				[
					'a' => [
						'href'   => [],
						'target' => [],
						'rel'    => [],
					],
				]
			),
			'https://wpforms.com/docs/creating-first-form/'
		);
		?>
	</p>

</div>
