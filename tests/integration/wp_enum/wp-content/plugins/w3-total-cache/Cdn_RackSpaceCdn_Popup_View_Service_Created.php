<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form action="admin.php?page=w3tc_cdn" method="post" style="padding: 20px" class="w3tc_cdn_rackspace_form">
	<?php
	Util_Ui::hidden( '', 'w3tc_action', 'cdn_rackspace_service_created_done' );
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
	?>
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Succeeded', 'w3-total-cache' ) ); ?>

		<div style="text-align: center" class="w3tc_rackspace_created_in_progress">
			<div class="spinner" style="float: right; display: block"></div>
			<div style="text-align: left">
				Service <?php echo esc_html( $details['name'] ); ?> was successfully created.<br />
				Waiting for RackSpace to finish the provisioning process.<br />
				<br />

				Actual state is:
				<strong><span class="w3tc_rackspace_created_status">Initiated</span></strong>
			</div>
		</div>

		<div style="display: none" class="w3tc_rackspace_created_done">
			<div style="text-align: center">
				<div style="text-align: left">
					Service <?php echo esc_html( $details['name'] ); ?> was successfully configured.<br />
					<?php if ( ! $is_https ) : ?>
						<br />
						Next, update the domain's <acronym title="Domain Name System">DNS</acronym> records
						<strong><?php echo esc_html( $details['cname'] ); ?></strong> and add <acronym title="Canonical Name">CNAME</acronym> alias to<br />
						<strong class="w3tc_rackspace_access_url"></strong> to enable caching.
					<?php endif; ?>
				</div>
			</div>

			<p class="submit">
				<input type="button"
					class="w3tc_popup_submit w3tc-button-save button-primary"
					value="<?php esc_attr_e( 'Done', 'w3-total-cache' ); ?>" />
			</p>
		</div>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
