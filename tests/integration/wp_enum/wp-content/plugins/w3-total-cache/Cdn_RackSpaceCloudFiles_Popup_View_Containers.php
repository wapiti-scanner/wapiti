<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form action="admin.php?page=w3tc_cdn" method="post" style="padding: 20px" class="w3tc_cdn_rackspace_form">
	<?php
	Util_Ui::hidden( '', 'w3tc_action', 'cdn_rackspace_containers_done' );
	Util_Ui::hidden( '', 'user_name', $details['user_name'] );
	Util_Ui::hidden( '', 'api_key', $details['api_key'] );
	Util_Ui::hidden( '', 'access_token', $details['access_token'] );
	Util_Ui::hidden( '', 'access_region_descriptor', $details['access_region_descriptor_serialized'] );
	Util_Ui::hidden( '', 'region', $details['region'] );
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
		<?php Util_Ui::postbox_header( esc_html__( 'Select container to use', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td>Container:</td>
				<td>
					<?php foreach ( $details['containers'] as $container ) : ?>
						<label>
							<input name="container" type="radio" class="w3tc-ignore-change"
								value="<?php echo esc_attr( $container['name'] ); ?>" />
							<?php echo esc_html( $container['name'] ); ?>
						</label><br />
					<?php endforeach; ?>
					<label>
						<input name="container" type="radio" class="w3tc-ignore-change" value="" />
						Add new container:
					</label>
					<input name="container_new" type="text" class="w3tc-ignore-change" />
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
