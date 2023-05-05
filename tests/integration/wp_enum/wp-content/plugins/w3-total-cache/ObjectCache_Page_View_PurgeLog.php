<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

require W3TC_INC_DIR . '/options/common/header.php';
?>
<style>
	<?php require_once __DIR__ . '/shared/purge_log.css'; ?>
</style>
<div class="metabox-holder">
	<?php Util_Ui::postbox_header( esc_html__( 'Object Cache Purges Log', 'w3-total-cache' ) ); ?>

	<h1><?php esc_html_e( 'Purges Log', 'w3-total-cache' ); ?></h1>

	<div class="w3tc_purge_log_table">
		<?php foreach ( $lines as $line ): ?>
			<div class="w3tc_purge_log_date"><?php echo esc_html( $line['date'] ); ?></div>
			<div class="w3tc_purge_log_message"><td><?php echo esc_html( $line['message'] ); ?></div>
			<div class="w3tc_purge_log_backtrace">
					<?php foreach ( $line['backtrace'] as $backtrace_line ) : ?>
						<div class="w3tc_purge_log_traceline">
							<?php echo esc_html( $backtrace_line ); ?>
						</div>
					<?php endforeach ?>
			</div>
		<?php endforeach ?>
	</div>

	<?php Util_Ui::postbox_footer(); ?>
</div>
