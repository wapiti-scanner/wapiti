<div class="wpforms-input-row">
	<div class="minimum">
		<?php echo $input_min; // phpcs:ignore ?>
		<label for="wpforms-field-option-<?php echo (int) $field_id; ?>-min" class="sub-label"><?php esc_html_e( 'Minimum', 'wpforms-lite' ); ?></label>
	</div>
	<div class="maximum">
		<?php echo $input_max; // phpcs:ignore ?>
		<label for="wpforms-field-option-<?php echo (int) $field_id; ?>-max" class="sub-label"><?php esc_html_e( 'Maximum', 'wpforms-lite' ); ?></label>
	</div>
</div>
