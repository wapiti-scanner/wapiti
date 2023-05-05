<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_cdn_stackpath_form" method="post">
	<?php
	Util_Ui::hidden( '', 'api_key', $details['api_key'] );
	?>
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Select zone to use', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td>Zone:</td>
				<td>
					<?php
					if ( count( $details['zones'] ) > 15 ) {
						echo '<div style="width: 100%; height: 300px; overflow-y: scroll">';
					}
					?>

					<?php foreach ( $details['zones'] as $zone ) : ?>
						<label>
							<input name="zone_id" type="radio" class="w3tc-ignore-change"
								value="<?php echo esc_attr( $zone['id'] ); ?>" />
							<?php echo esc_html( $zone['name'] ); ?>
							(<?php echo esc_html( $zone['cdn_url'] ); ?>)
						</label><br />
					<?php endforeach ?>

					<label>
						<input name="zone_id" type="radio" class="w3tc-ignore-change" value="" />
						Add new zone:
					</label>
					<input name="zone_new_name" type="text" class="w3tc-ignore-change" />

					<?php
					if ( count( $details['zones'] ) > 15 ) {
						echo '</div>';
					}
					?>
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_stackpath_view_zone w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Apply', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
