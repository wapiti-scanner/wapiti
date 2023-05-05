<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form action="admin.php?page=w3tc_cdn" method="post" style="padding: 20px" class="w3tc_cdn_rackspace_form">
	<?php
	Util_Ui::hidden( '', 'w3tc_action', 'cdn_rackspace_service_actualize_done' );
	Util_Ui::hidden( '', 'user_name', $details['user_name'] );
	Util_Ui::hidden( '', 'api_key', $details['api_key'] );
	Util_Ui::hidden( '', 'access_token', $details['access_token'] );
	Util_Ui::hidden( '', 'access_region_descriptor', $details['access_region_descriptor_serialized'] );
	Util_Ui::hidden( '', 'region', $details['region'] );
	Util_Ui::hidden( '', 'service_id', $details['service_id'] );
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
		<?php Util_Ui::postbox_header( esc_html__( 'Configure service', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Name:', 'w3-total-cache' ); ?></th>
				<td><?php echo esc_html( $details['name'] ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Origin host:', 'w3-total-cache' ); ?></th>
				<td><?php $this->render_service_value_change( $details, 'origin' ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Origin protocol:', 'w3-total-cache' ); ?></th>
				<td><?php echo esc_html( $details['protocol'] ); ?><br />
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_popup_submit w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Apply', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
