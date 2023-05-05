<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div id="w3tc-help">
	<p>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML a tag to W3TC support plugin page followed by opening HTML strong tag,
				// translators: 2 closing HTML strong tag followed by closing HTML a tag.
				__(
					'Request professional %1$ssupport%2$s or troubleshoot issues using the common questions below:',
					'w3-total-cache'
				),
				'<a href="admin.php?page=w3tc_support" style="color: red;"><strong>',
				'</strong></a>'
			),
			array(
				'a'      => array(
					'href'  => array(),
					'style' => array(),
				),
				'strong' => array(),
			)
		);
		?>
	</p>
	<ul>
		<?php foreach ( $entries as $entry ) : ?>
			<li>
				<a href="<?php echo esc_url( $entry['a'] ); ?>" target="_blank"><?php echo esc_html( $entry['q'] ); ?></a>
			</li>
		<?php endforeach; ?>
	</ul>
	<div style="clear: left;"></div>
</div>
