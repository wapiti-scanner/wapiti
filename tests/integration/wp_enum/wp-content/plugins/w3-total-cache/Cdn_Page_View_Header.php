<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>

<p>
	<?php
	echo wp_kses(
		sprintf(
			// translators: 1 HTML strong element with CDN engine content, 2 HTML span element with CDN enabled/disabled status.
			__(
				'Content Delivery Network support via %1$s is currently %2$s.',
				'w3-total-cache'
			),
			'<strong>' . esc_html( Cache::engine_name( $config->get_string( 'cdn.engine' ) ) ) . '</strong>',
			'<span class="w3tc-' . ( $config->get_boolean( 'cdn.enabled' ) ? 'enabled">' . __( 'enabled', 'w3-total-cache' ) : 'disabled">' . __( 'disabled', 'w3-total-cache' ) ) . '</span>'
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
