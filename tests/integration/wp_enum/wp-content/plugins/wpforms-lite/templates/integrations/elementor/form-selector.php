<?php
/**
 * Forms selector for Elementor page builder.
 *
 * @since 1.6.2
 *
 * @var string $forms Rendered <option>s for the select tag.
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wpforms-elementor wpforms-elementor-form-selector">

	<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/integrations/elementor/wpforms-logo.svg' ); ?>" alt="WPForms Logo"/>

	<div class="select-wrapper">
		<select>
			<?php echo $forms; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</select>
	</div>

</div>

