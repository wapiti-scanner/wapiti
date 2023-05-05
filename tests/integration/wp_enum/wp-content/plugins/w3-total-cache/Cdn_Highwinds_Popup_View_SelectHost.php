<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form action="admin.php?page=w3tc_cdn" method="post" style="padding: 20px"
	class="w3tc_cdn_highwinds_form">
	<?php
	Util_Ui::hidden( '', 'account_hash', $details['account_hash'] );
	Util_Ui::hidden( '', 'api_token', $details['api_token'] );

	echo wp_kses(
		Util_Ui::nonce_field( 'w3tc' ),
		array(
			'input' => array(
				'type'  => array(),
				'name'  => array(),
				'value' => array(),
			),
		)
	);

	if ( isset( $details['error_message'] ) ) {
		echo '<div class="error">' . esc_html( $details['error_message'] ) . '</div>';
	}
	?>
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Select host to use', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td>Host:</td>
				<td>
					<?php foreach ( $details['hosts'] as $host ) : ?>
						<label>
							<input name="host" type="radio" class="w3tc-ignore-change"
								value="<?php echo esc_attr( $host['hashCode'] ); ?>" />
							<?php echo esc_html( $host['name'] ); ?>
							(<?php echo esc_html( $host['hashCode'] ); ?>)
						</label><br />	
					<?php endforeach; ?>

					<label>
						<input name="host" type="radio" class="w3tc-ignore-change" value="" />
						Add new host:
					</label>
					<input name="host_new" type="text" class="w3tc-ignore-change" />
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_highwinds_configure_host w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Apply', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
