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
			// translators: 1 HTML strong tag containing CDNFSD engine name, 2 HTML span tag containing CDNFSD engine enabled/disabled.
			__(
				'Content Delivery Network support via %1$s is currently %2$s.',
				'w3-total-cache'
			),
			'<strong>' . Cdnfsd_Util::engine_name( $config->get_string( 'cdnfsd.engine' ) ) . '</strong>',
			'<span class="w3tc-' . ( $config->get_boolean( 'cdnfsd.enabled' ) ? 'enabled">' . __( 'enabled', 'w3-total-cache' ) : 'disabled">' . __( 'disabled', 'w3-total-cache' ) ) . '</span>'
		),
		array(
			'strong' => array(),
			'span'   => array(
				'class' => array(),
			),
		)
	);
	?>
</p>
