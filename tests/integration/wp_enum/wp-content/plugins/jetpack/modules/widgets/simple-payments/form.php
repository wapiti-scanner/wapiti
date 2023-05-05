<?php
/**
 * Display the Pay with PayPal Form.
 *
 * @package automattic/jetpack
 * @phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
 */

?>
<p>
	<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>">
		<?php esc_html_e( 'Widget Title', 'jetpack' ); ?>
	</label>
	<input
		type="text"
		class="widefat jetpack-simple-payments-widget-title"
		id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"
		name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>"
		value="<?php echo esc_attr( $instance['title'] ); ?>" />
</p>
<p class="jetpack-simple-payments-products-fieldset" 
<?php
if ( empty( $product_posts ) ) {
	echo 'style="display:none;"';
}
?>
>
	<label for="<?php echo esc_attr( $this->get_field_id( 'product_post_id' ) ); ?>">
		<?php esc_html_e( 'Select a Pay with PayPal button:', 'jetpack' ); ?>
	</label>
	<select
		class="widefat jetpack-simple-payments-products"
		id="<?php echo esc_attr( $this->get_field_id( 'product_post_id' ) ); ?>"
		name="<?php echo esc_attr( $this->get_field_name( 'product_post_id' ) ); ?>">
		<?php foreach ( $product_posts as $product_post ) { ?>
			<option value="<?php echo esc_attr( $product_post->ID ); ?>" <?php selected( (int) $instance['product_post_id'], $product_post->ID ); ?>>
				<?php echo esc_attr( get_the_title( $product_post ) ); ?>
			</option>
		<?php } ?>
	</select>
</p>
<?php if ( is_customize_preview() ) { ?>
<p class="jetpack-simple-payments-products-warning" 
	<?php
	if ( ! empty( $product_posts ) ) {
		echo 'style="display:none;"';
	}
	?>
>
	<?php esc_html_e( "Looks like you don't have any products. You can create one using the Add New button below.", 'jetpack' ); ?>
</p>
<p>
	<div class="alignleft">
		<button class="button jetpack-simple-payments-edit-product" <?php disabled( empty( $product_posts ), true ); ?>>
			<?php esc_html_e( 'Edit Selected', 'jetpack' ); ?>
		</button>
	</div>
	<div class="alignright">
		<button class="button jetpack-simple-payments-add-product"><?php esc_html_e( 'Add New', 'jetpack' ); ?></button>
	</div>
	<br class="clear">
</p>
<hr />
<div class="jetpack-simple-payments-form" style="display: none;">
	<input
		type="hidden"
		id="<?php echo esc_attr( $this->get_field_id( 'form_action' ) ); ?>"
		name="<?php echo esc_attr( $this->get_field_name( 'form_action' ) ); ?>"
		value="<?php echo esc_attr( $instance['form_action'] ); ?>"
		class="jetpack-simple-payments-form-action" />
	<input
		type="hidden"
		id="<?php echo esc_attr( $this->get_field_id( 'form_product_id' ) ); ?>"
		name="<?php echo esc_attr( $this->get_field_name( 'form_product_id' ) ); ?>"
		value="<?php echo esc_attr( $instance['form_product_id'] ); ?>"
		class="jetpack-simple-payments-form-product-id" />
	<input
		type="hidden"
		id="<?php echo esc_attr( $this->get_field_id( 'form_product_image_id' ) ); ?>"
		name="<?php echo esc_attr( $this->get_field_name( 'form_product_image_id' ) ); ?>"
		value="<?php echo esc_attr( $instance['form_product_image_id'] ); ?>"
		class="jetpack-simple-payments-form-image-id" />
	<input
		type="hidden"
		id="<?php echo esc_attr( $this->get_field_id( 'form_product_image_src' ) ); ?>"
		name="<?php echo esc_attr( $this->get_field_name( 'form_product_image_src' ) ); ?>"
		value="<?php echo esc_attr( $instance['form_product_image_src'] ); ?>"
		class="jetpack-simple-payments-form-image-src" />
	<p>
		<label for="<?php echo esc_attr( $this->get_field_id( 'form_product_title' ) ); ?>">
			<?php esc_html_e( 'What is this payment for?', 'jetpack' ); ?>
		</label>
		<input
			type="text"
			class="widefat field-title jetpack-simple-payments-form-product-title"
			id="<?php echo esc_attr( $this->get_field_id( 'form_product_title' ) ); ?>"
			name="<?php echo esc_attr( $this->get_field_name( 'form_product_title' ) ); ?>"
			value="<?php echo esc_attr( $instance['form_product_title'] ); ?>" />
		<br />
		<small>
			<?php esc_html_e( 'For example: event tickets, charitable donations, training courses, coaching fees, etc.', 'jetpack' ); ?>
		</small>
	</p>
	<div class="jetpack-simple-payments-image-fieldset">
		<label><?php esc_html_e( 'Product image', 'jetpack' ); ?></label>
		<div class="placeholder" 
		<?php
		if ( ! empty( $instance['form_product_image_id'] ) ) {
			echo 'style="display:none;"';
		}
		?>
		>
			<?php esc_html_e( 'Select an image', 'jetpack' ); ?>
		</div>
		<div class="jetpack-simple-payments-image" 
		<?php
		if ( empty( $instance['form_product_image_id'] ) ) {
			echo 'style="display:none;"';
		}
		?>
		>
			<img src="<?php echo esc_url( $instance['form_product_image_src'] ); ?>" />
			<button class="button jetpack-simple-payments-remove-image"><?php esc_html_e( 'Remove image', 'jetpack' ); ?></button>
		</div>
	</div>
	<p>
		<label for="<?php echo esc_attr( $this->get_field_id( 'form_product_description' ) ); ?>">
			<?php esc_html_e( 'Description', 'jetpack' ); ?>
		</label>
		<textarea
			class="field-description widefat jetpack-simple-payments-form-product-description"
			rows=5
			id="<?php echo esc_attr( $this->get_field_id( 'form_product_description' ) ); ?>"
			name="<?php echo esc_attr( $this->get_field_name( 'form_product_description' ) ); ?>"><?php echo esc_textarea( $instance['form_product_description'] ); ?></textarea>
	</p>
	<p class="cost">
		<label for="<?php echo esc_attr( $this->get_field_id( 'form_product_price' ) ); ?>">
			<?php esc_html_e( 'Price', 'jetpack' ); ?>
		</label>
		<select
			class="field-currency widefat jetpack-simple-payments-form-product-currency"
			id="<?php echo esc_attr( $this->get_field_id( 'form_product_currency' ) ); ?>"
			name="<?php echo esc_attr( $this->get_field_name( 'form_product_currency' ) ); ?>">
			<?php foreach ( Jetpack_Simple_Payments_Widget::$supported_currency_list as $code => $currency ) { ?>
				<option value="<?php echo esc_attr( $code ); ?>"<?php selected( $instance['form_product_currency'], $code ); ?>>
					<?php echo esc_html( "$code $currency" ); ?>
				</option>
			<?php } ?>
		</select>
		<input
			type="text"
			class="field-price widefat jetpack-simple-payments-form-product-price"
			id="<?php echo esc_attr( $this->get_field_id( 'form_product_price' ) ); ?>"
			name="<?php echo esc_attr( $this->get_field_name( 'form_product_price' ) ); ?>"
			value="<?php echo esc_attr( $instance['form_product_price'] ); ?>"
			placeholder="1.00" />
	</p>
	<p>
		<input
			class="field-multiple jetpack-simple-payments-form-product-multiple"
			id="<?php echo esc_attr( $this->get_field_id( 'form_product_multiple' ) ); ?>"
			name="<?php echo esc_attr( $this->get_field_name( 'form_product_multiple' ) ); ?>"
			type="checkbox"
			value="1"
			<?php checked( $instance['form_product_multiple'], '1' ); ?> />
		<label for="<?php echo esc_attr( $this->get_field_id( 'form_product_multiple' ) ); ?>">
			<?php esc_html_e( 'Allow people to buy more than one item at a time.', 'jetpack' ); ?>
		</label>
	</p>
	<p>
		<label for="<?php echo esc_attr( $this->get_field_id( 'form_product_email' ) ); ?>">
			<?php esc_html_e( 'Email', 'jetpack' ); ?>
		</label>
		<input
			class="field-email widefat jetpack-simple-payments-form-product-email"
			id="<?php echo esc_attr( $this->get_field_id( 'form_product_email' ) ); ?>"
			name="<?php echo esc_attr( $this->get_field_name( 'form_product_email' ) ); ?>"
			type="email"
			value="<?php echo esc_attr( $instance['form_product_email'] ); ?>" />
		<small>
			<?php
			printf(
				wp_kses(
					/* Translators: placeholders are a link to Paypal website and a target attribute. */
					__( 'This is where PayPal will send your money. To claim a payment, you\'ll need a <a href="%1$s" %2$s>PayPal account</a> connected to a bank account.', 'jetpack' ),
					array(
						'a' => array(
							'href'   => array(),
							'target' => array(),
						),
					)
				),
				'https://paypal.com',
				'target="_blank"'
			);
			?>
		</small>
	</p>
	<p>
		<div class="alignleft">
			<button type="button" class="button-link button-link-delete jetpack-simple-payments-delete-product">
				<?php esc_html_e( 'Delete Product', 'jetpack' ); ?>
			</button>
		</div>
		<div class="alignright">
			<button name="<?php echo esc_attr( $this->get_field_name( 'save' ) ); ?>" class="button jetpack-simple-payments-save-product"><?php esc_html_e( 'Save', 'jetpack' ); ?></button>
			<span> | <button type="button" class="button-link jetpack-simple-payments-cancel-form"><?php esc_html_e( 'Cancel', 'jetpack' ); ?></button></span>
		</div>
		<br class="clear">
	</p>
	<hr />
</div>
<?php } else { ?>
<p class="jetpack-simple-payments-products-warning">
	<?php
		printf(
			wp_kses(
				/* Translators: placeholder is a link to the customizer. */
				__( 'This widget adds a payment button of your choice to your sidebar. To create or edit the payment buttons themselves, <a href="%s">use the Customizer</a>.', 'jetpack' ),
				array(
					'a' => array(
						'href' => array(),
					),
				)
			),
			esc_url( add_query_arg( array( 'autofocus[panel]' => 'widgets' ), admin_url( 'customize.php' ) ) )
		);
	?>
</p>
<?php } ?>
