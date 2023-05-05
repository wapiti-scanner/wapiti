<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_popup_form">
	<?php
	if ( isset( $details['error_message'] ) ) {
		echo '<div class="error">' . esc_html( $details['error_message'] ) . '</div>';
	}
	?>
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Your LimeLight Account credentials', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td>Account Short Name:</td>
				<td>
					<input name="short_name" type="text" class="w3tc-ignore-change"
						style="width: 550px"
						value="<?php echo esc_attr( $config->get_string( 'cdnfsd.limelight.short_name' ) ); ?>" />
				</td>
			</tr>
			<tr>
				<td>Username:</td>
				<td>
					<input name="username" type="text" class="w3tc-ignore-change"
						style="width: 550px"
						value="<?php echo esc_attr( $config->get_string( 'cdnfsd.limelight.username' ) ); ?>" />
				</td>
			</tr>
			<tr>
				<td>API Key:</td>
				<td>
					<input name="api_key" type="text" class="w3tc-ignore-change"
						style="width: 550px"
						value="<?php echo esc_attr( $config->get_string( 'cdnfsd.limelight.api_key' ) ); ?>" />
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdnfsd_limelight_save w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Next', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
