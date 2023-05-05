<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_cdn_stackpath2_form" method="post">
	<?php
	Util_Ui::hidden( '', 'api_config', $details['api_config'] );
	?>
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Select stack to use', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<td>Site:</td>
				<td>
					<?php
					if ( count( $details['stacks'] ) > 15 ) {
						echo '<div style="width: 100%; height: 300px; overflow-y: scroll">';
					}
					?>

					<?php foreach ( $details['stacks'] as $i ) : ?>
						<label>
							<input name="stack_id" type="radio" class="w3tc-ignore-change"
								value="<?php echo esc_attr( $i['id'] ); ?>" />
							<?php echo esc_html( $i['name'] ); ?>
							<?php if ( 'ACTIVE' !== $i['status'] ) : ?>
								(<?php echo esc_html( $i['status'] ); ?>)
							<?php endif ?>
						</label><br />
					<?php endforeach ?>

					<?php
					if ( count( $details['stacks'] ) > 15 ) {
						echo '</div>';
					}
					?>
				</td>
			</tr>
		</table>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_stackpath2_list_sites w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Apply', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
