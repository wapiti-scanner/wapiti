<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

require W3TC_INC_DIR . '/options/common/header.php';
?>
<style>
.w3tc_purge_log_header {
	width: 100%;
	display: flex;
	align-items: center;
	justify-content: space-between;
}

.w3tc_purge_log_clear {
	text-align: right;
}

.w3tc_purge_log_table {
	display: grid;
	grid-template-columns: auto 1fr;
	grid-gap: 10px;
	background: #fff;
	padding: 11px;
	border: 1px solid #ccd0d4;
	margin-bottom: 11px;
}
.w3tc_purge_log_label {
	white-space: nowrap;
	font-weight: bold;
}

.w3tc_purge_log_urls {
	font-family: courier;
}

.w3tc_purge_log_backtrace {
	font-family: courier;
	border: 1px solid #ccd0d4;
	border-spacing: 0;
}

.w3tc_purge_log_backtrace td {
	padding: 5px 5px;
}

.w3tc_purge_log_backtrace tr:nth-child(odd){
	background-color: #f2f2f2;
}

</style>
<div class="w3tc_purge_log_header">
	<h1>Purges Log</h1>
	<div class="w3tc_purge_log_clear">
		<?php
		echo wp_kses(
			Util_Ui::button_link(
				__( 'Clear Log', 'w3-total-cache' ),
				Util_Ui::url(
					array(
						'w3tc_default_purgelog_clear' => 'y',
						'module'                      => $module,
					)
				)
			),
			array(
				'input' => array(
					'type'    => array(),
					'name'    => array(),
					'class'   => array(),
					'value'   => array(),
					'onclick' => array(),
				),
			)
		);
		?>
	</div>
</div>


<p>
	Available logs:
	<?php foreach ( $purgelog_modules as $module ) : ?>
		<a href="admin.php?page=w3tc_general&view=purge_log&module=<?php echo esc_attr( $module['label'] ); ?>"><?php echo esc_html( $module['name'] ); ?></a>
		<?php echo esc_html( $module['postfix'] ); ?>
	<?php endforeach ?>
</p>
<p>
	Filename: <?php echo esc_html( $log_filename ); ?> (<?php echo esc_html( $log_filefize ); ?>)
</p>

<?php foreach ( $lines as $line ) : ?>
	<div class="w3tc_purge_log_table">
		<div class="w3tc_purge_log_label">Date</div>
		<div><?php echo esc_html( $line['date'] ); ?></div>

		<div class="w3tc_purge_log_label">Action</div>
		<div class="w3tc_purge_log_message"><?php echo esc_html( $line['message'] ); ?></div>

		<div class="w3tc_purge_log_label">User</div>
		<div class="w3tc_purge_log_message"><?php echo esc_html( $line['username'] ); ?></div>

		<?php if ( ! empty( $line['urls'] ) ) : ?>
			<div class="w3tc_purge_log_label">Pages Flushed</div>
			<div class="w3tc_purge_log_urls">
				<?php foreach ( $line['urls'] as $url ) : ?>
					<div><?php echo esc_html( $url ); ?></div>
				<?php endforeach ?>
			</div>
		<?php endif ?>

		<div class="w3tc_purge_log_label">Stack Trace</div>
		<table class="w3tc_purge_log_backtrace">
			<?php foreach ( $line['backtrace'] as $backtrace_line ) : ?>
				<tr>
					<td><?php echo esc_html( $backtrace_line['number'] ); ?></td>
					<td><?php echo $this->esc_filename( $backtrace_line['filename'] ); // phpcs:ignore ?></td>
					<td><?php echo esc_html( $backtrace_line['function'] ); ?></td>
				</tr>
			<?php endforeach ?>
		</table>
	</div>
<?php endforeach ?>
