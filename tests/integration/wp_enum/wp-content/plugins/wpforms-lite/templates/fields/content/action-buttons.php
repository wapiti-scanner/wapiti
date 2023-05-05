<?php
/**
 * Content field preview and extend buttons template.
 *
 * @since 1.7.8
 *
 * @var int    $id      Field id.
 * @var string $preview Preview button label.
 * @var string $expand  Expand button label.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="wpforms-field-content-action-buttons">
	<button type="button" id="wpforms-field-option-<?php echo absint( $id ); ?>-update-preview" class="button wpforms-content-button-update-preview update-preview">
		<?php echo esc_html( $preview ); ?>
	</button>
	<button type="button" id="wpforms-field-option-<?php echo absint( $id ); ?>-expand-editor" class="button wpforms-content-button-expand-editor expand-editor">
		<svg class="expand" viewBox="0 0 14 14">
			<path d="M6.625 8.875C6.8125 8.6875 6.8125 8.34375 6.625 8.15625L5.84375 7.375C5.65625 7.1875 5.3125 7.1875 5.125 7.375L2.25 10.25L1.25 9.25C0.78125 8.75 0 9.09375 0 9.75V13.25C0 13.6875 0.3125 14 0.71875 14H4.21875C4.90625 14 5.25 13.2188 4.75 12.75L3.75 11.75L6.625 8.875ZM7.34375 5.15625C7.15625 5.34375 7.15625 5.6875 7.34375 5.875L8.125 6.65625C8.3125 6.84375 8.65625 6.84375 8.84375 6.65625L11.75 3.75L12.7188 4.78125C13.1875 5.28125 14 4.9375 14 4.25V0.75C14 0.34375 13.6562 0 13.25 0H9.75C9.0625 0 8.71875 0.8125 9.21875 1.28125L10.25 2.25L7.34375 5.15625Z"/>
		</svg>
		<svg class="collapse" viewBox="0 0 14 14">
			<path d="M0.140625 12.3594C-0.046875 12.5469 -0.046875 12.8594 0.140625 13.0469L0.953125 13.8594C1.14062 14.0469 1.45312 14.0469 1.64062 13.8594L4.76562 10.7344L5.73438 11.7656C6.20312 12.2656 7.01562 11.9219 7.01562 11.2344V7.73438C7.01562 7.32812 6.67188 6.98438 6.26562 6.98438H2.76562C2.07812 6.98438 1.73438 7.79688 2.23438 8.26562L3.26562 9.23438L0.140625 12.3594ZM13.8594 1.64062C14.0469 1.45312 14.0469 1.14062 13.8594 0.953125L13.0469 0.140625C12.8594 -0.046875 12.5469 -0.046875 12.3594 0.140625L9.26562 3.23438L8.26562 2.23438C7.79688 1.73438 7.01562 2.07812 7.01562 2.73438V6.23438C7.01562 6.67188 7.32812 6.98438 7.73438 6.98438H11.2344C11.9219 6.98438 12.2656 6.20312 11.7656 5.73438L10.7656 4.73438L13.8594 1.64062Z"/>
		</svg>
		<span clas="wpforms-expand-button-label">
			<?php echo esc_html( $expand ); ?>
		</span>
	</button>
</div>
