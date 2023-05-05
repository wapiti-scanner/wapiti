<?php
/**
 * Bulk Edit Tags on forms overview page.
 *
 * @since 1.7.5
 *
 * @var int    $columns       Columns count.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<tr class="wpforms-bulk-edit-tags wpforms-row-form wpforms-hidden">
	<td colspan="<?php echo absint( $columns ); ?>">
		<div class="wpforms-fbox">
			<div class="wpforms-edit-forms">
				<select multiple size="6"></select>
			</div>
			<div class="wpforms-edit-tags">
				<select multiple size="1"></select>
			</div>
		</div>
	</td>
</tr>
<tr class="wpforms-bulk-edit-tags wpforms-row-buttons wpforms-hidden">
	<td colspan="<?php echo absint( $columns ); ?>">
		<button type="button" class="button wpforms-bulk-edit-tags-cancel">
			<?php esc_html_e( 'Cancel', 'wpforms-lite' ); ?>
		</button>
		<button type="button" class="button button-primary wpforms-bulk-edit-tags-save">
			<i class="wpforms-loading-spinner wpforms-loading-white wpforms-loading-inline wpforms-hidden"></i>
			<?php esc_html_e( 'Update', 'wpforms-lite' ); ?>
		</button>
	</td>
</tr>
<tr class="wpforms-bulk-edit-tags wpforms-row-message wpforms-hidden">
	<td colspan="<?php echo absint( $columns ); ?>">
		<div class="wpforms-message"></div>
	</td>
</tr>
