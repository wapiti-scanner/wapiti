<?php
namespace W3TC;

if ( !defined( 'W3TC' ) )
	die();
?>

<p>
	<?php echo wp_kses(
		sprintf(
			__( 'You\'re using the Community Edition of W3 Total Cache. Maximize your website\'s speed even more by upgrading to %1$sW3 Total Cache Pro%2$s to unlock:', 'w3-total-cache' ),
			'<strong>',
			'</strong>'
		),
		array( 'strong' => array() )
	); ?>
</p>

<ul class="w3tc-visible-ul">
	<li><?php esc_html_e( 'Advanced Analytics', 'w3-total-cache' ); ?></li>
	<li><?php esc_html_e( 'Fragment Caching', 'w3-total-cache' ); ?></li>
	<li><?php esc_html_e( 'Full Site Delivery', 'w3-total-cache' ); ?></li>
	<li><?php esc_html_e( 'Extension Support', 'w3-total-cache' ); ?></li>
</ul>

<p>
	<?php echo wp_kses(
		sprintf(
			__( 'Plus, there\'s even more that allow you to completely fine tune your website\'s performance.', 'w3-total-cache' ),
			'<strong>',
			'</strong>'
		),
		array( 'strong' => array() )
	); ?>
</p>

<p>
	<input
		type="button"
		class="button-primary button-buy-plugin"
		data-src="community_widget" value="<?php esc_attr_e( 'Learn more about Pro', 'w3-total-cache' ) ?>" />
</p>