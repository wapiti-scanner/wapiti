<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<p>
	<?php
	echo wp_kses(
		sprintf(
			Util_Ui::button_link(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
				__(
					'Purge %1$sCDN%2$s completely',
					'w3-total-cache'
				),
				Util_Ui::url( array( 'w3tc_cdn_flush' => 'y' ) )
			),
			'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
			'</acronym>'
		),
		array(
			'input'   => array(
				'type'    => array(),
				'name'    => array(),
				'class'   => array(),
				'value'   => array(),
				'onclick' => array(),
			),
			'acronym' => array(
				'title' => array(),
			),
		)
	);
	?>
</p>
