<input type="range" readonly
	class="wpforms-number-slider"
	id="wpforms-number-slider-<?php echo (int) $field_id; ?>"
	value="<?php echo (float) $default_value; ?>"
	min="<?php echo (float) $min; ?>"
	max="<?php echo (float) $max; ?>"
	step="<?php echo (float) $step; ?>">

<div
	id="wpforms-number-slider-hint-<?php echo (int) $field_id; ?>"
	data-hint="<?php echo esc_attr( wp_kses_post( $value_display ) ); ?>"
	class="wpforms-number-slider-hint">
	<?php echo wp_kses_post( $value_hint ); ?>
</div>
