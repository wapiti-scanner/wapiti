<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>
<?php if ( Util_Request::get_boolean( 'payment' ) ) : ?>
	<div class="error">
		<p>To complete your support request fill out the form below!</p>
	</div>
<?php else : ?>
	<p>
		<?php esc_html_e( 'Request premium services, suggest a feature or submit a bug using the form below:', 'w3-total-cache' ); ?>
	</p>
<?php endif; ?>
<div id="support_container">
	<?php
	if ( ! $request_type || ! isset( $this->_request_types[ $request_type ] ) ) {
		$this->w3tc_support_select();
	} else {
		if ( isset( $this->_request_prices[ $request_type ] ) && ! $payment ) {
			$this->w3tc_support_payment();
		} else {
			$this->w3tc_support_form();
		}
	}
	?>
</div>

<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>
