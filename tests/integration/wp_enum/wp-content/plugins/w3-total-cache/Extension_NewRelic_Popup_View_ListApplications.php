<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form style="padding: 20px" class="w3tcnr_form">
	<?php
	Util_Ui::hidden( '', 'api_key', $details['api_key'] );
	?>

	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Select Application', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td>
					<label>
						<input name="monitoring_type" type="radio" value="apm"
							<?php checked( $details['monitoring_type'], 'apm' ); ?> />
						APM application (uses NewRelic PHP module)
					</label><br />
					<select name="apm_application_name" class="w3tcnr_apm">
						<?php
						foreach ( $details['apm_applications'] as $a ) {
							echo '<option ';
							selected( $a, $details['apm.application_name'] );
							echo '>' . esc_html( $a ) . '</option>';
						}
						?>
					</select>
				</td>
			</tr>
			<tr>
				<td>
					<label>
						<input name="monitoring_type" type="radio" value="browser"
							<?php checked( $details['monitoring_type'], 'browser' ); ?>
							<?php disabled( $details['browser_disabled'] ); ?> />
						Standalone Browser
						<?php
						if ( $details['browser_disabled'] ) {
							echo ' (W3TC Pro Only)';
						}
						?>
					</label><br />
					<select name="browser_application_id" class="w3tcnr_browser">
						<?php
						foreach ( $details['browser_applications'] as $a ) {
							echo '<option value="' . esc_attr( $a['id'] ) . '" ';
							selected( $a['id'], $details['browser.application_id'] );
							echo '>' . esc_html( $a['name'] ) . '</option>';
						}
						?>
					</select>
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tcnr_apply_configuration w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Apply', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
