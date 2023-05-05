<?php
/**
 * Search reset block on forms overview page.
 *
 * @since 1.7.2
 *
 * @var string $message Message to display inside the Search reset block.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div id="wpforms-reset-filter">
	<?php
	echo wp_kses(
		$message,
		[
			'strong' => [],
			'em'     => [],
		]
	);
	?>
	<i class="reset fa fa-times-circle" title="<?php esc_html_e( 'Clear search and return to All Forms', 'wpforms-lite' ); ?>"></i>
</div>
