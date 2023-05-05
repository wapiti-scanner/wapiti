<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form action="admin.php" xmlns="http://www.w3.org/1999/html" method="get">
	<input type="hidden" name="page" value="w3tc_support" />
	<ul>
		<?php
		$cnt = is_array( $items ) ? count( $items ) : 0;
		for ( $n = 0; $n < $cnt; $n++ ) :
			?>
			<li>
				<div class="w3tc_generic_widgetservice_radio_outer">
					<input id="service<?php echo esc_attr( $n ); ?>"
						type="radio"
						class="w3tc_generic_widgetservice_radio w3tc-ignore-change"
						name="service_item"
						value="<?php echo esc_attr( $n ); ?>" />
				</div>
				<label for="service<?php echo esc_attr( $n ); ?>" class="w3tc_generic_widgetservice_label">
					<?php echo esc_html( $items[ $n ]['name'] ); ?>
				</label>
			</li>
			<?php
		endfor;
		?>
	</ul>
	<div id="buy-w3-service-area"></div>
	<p>
		<input id="buy-w3-service" name="buy-w3-service" type="submit"
			class="button button-primary button-large"
			value="<?php esc_attr_e( 'Buy now', 'w3-total-cache' ); ?>" />
	</p>
</form>
