<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div id="w3tc_extensions">
	<?php
	if ( 'list' === $sub_view ) {
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML p tag, 2 opening HTML span tag, 3 closing HTML span tag, 4 closing HTML p tag.
				__(
					'%1$sExtension support is always %2$senabled%3$s%4$s'
				),
				'<p>',
				'<span class="w3tc-enabled">',
				'</span>',
				'</p>'
			),
			array(
				'p'    => array(),
				'span' => array(
					'class' => array(),
				),
			)
		);
	}
	?>
	<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?><?php echo $extension ? '&extension=' . esc_attr( $extension ) . '&action=view' : ''; ?>" method="post">
		<div class="metabox-holder <?php echo $extension ? 'extension-settings' : ''; ?>">
			<?php require W3TC_INC_OPTIONS_DIR . "/extensions/$sub_view.php"; ?>
		</div>
	</form>
</div>
