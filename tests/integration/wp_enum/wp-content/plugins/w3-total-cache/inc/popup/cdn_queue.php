<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/popup/common/header.php'; ?>

<p><?php esc_html_e( 'This tool lists the pending file uploads and deletions.', 'w3-total-cache' ); ?></p>
<p id="w3tc-options-menu">
	<a href="#cdn_queue_upload" rel="#cdn_queue_upload" class="tab<?php echo 'upload' === $cdn_queue_tab ? ' tab-selected' : ''; ?>"><?php esc_html_e( 'Upload queue', 'w3-total-cache' ); ?></a> |
	<a href="#cdn_queue_delete" rel="#cdn_queue_delete" class="tab<?php echo 'delete' === $cdn_queue_tab ? ' tab-selected' : ''; ?>"><?php esc_html_e( 'Delete queue', 'w3-total-cache' ); ?></a> |
	<a href="#cdn_queue_purge" rel="#cdn_queue_purge" class="tab<?php echo 'purge' === $cdn_queue_tab ? ' tab-selected' : ''; ?>"><?php esc_html_e( 'Purge queue', 'w3-total-cache' ); ?></a>
</p>

<div id="cdn_queue_upload" class="tab-content"<?php echo 'upload' !== $cdn_queue_tab ? ' style="display: none;"' : ''; ?>>
<?php if ( ! empty( $queue[ W3TC_CDN_COMMAND_UPLOAD ] ) ) : ?>
	<table class="table queue">
		<tr>
			<th><?php esc_html_e( 'Local Path', 'w3-total-cache' ); ?></th>
			<th><?php esc_html_e( 'Remote Path', 'w3-total-cache' ); ?></th>
			<th><?php esc_html_e( 'Last Error', 'w3-total-cache' ); ?></th>
			<th><?php esc_html_e( 'Date', 'w3-total-cache' ); ?></th>
			<th><?php esc_html_e( 'Delete', 'w3-total-cache' ); ?></th>
		</tr>
		<?php foreach ( (array) $queue[ W3TC_CDN_COMMAND_UPLOAD ] as $result ) : ?>
		<tr>
			<td><?php echo esc_html( $result->local_path ); ?></td>
			<td><?php echo esc_html( $result->remote_path ); ?></td>
			<td><?php echo esc_html( $result->last_error ); ?></td>
			<td align="center"><?php echo esc_html( $result->date ); ?></td>
			<td align="center">
				<a href="admin.php?page=w3tc_cdn&amp;w3tc_cdn_queue&amp;cdn_queue_tab=upload&amp;cdn_queue_action=delete&amp;cdn_queue_id=<?php echo esc_attr( $result->id ); ?>&amp;_wpnonce=<?php echo esc_attr( $nonce ); ?>" class="cdn_queue_delete"><?php esc_html_e( 'Delete', 'w3-total-cache' ); ?></a>
			</td>
		</tr>
		<?php endforeach; ?>
	</table>
	<p>
		<a href="admin.php?page=w3tc_cdn&amp;w3tc_cdn_queue&amp;cdn_queue_tab=upload&amp;cdn_queue_action=empty&amp;cdn_queue_type=<?php echo esc_attr( W3TC_CDN_COMMAND_UPLOAD ); ?>&amp;_wpnonce=<?php echo esc_attr( $nonce ); ?>" class="cdn_queue_empty"><?php esc_html_e( 'Empty upload queue', 'w3-total-cache' ); ?></a>
	</p>
	<p>
		<a href="admin.php?page=w3tc_cdn&amp;w3tc_cdn_queue&amp;cdn_queue_tab=upload&amp;cdn_queue_action=process&amp;_wpnonce=<?php echo esc_attr( $nonce ); ?>"><?php esc_html_e( 'Process CDN queue now', 'w3-total-cache' ); ?></a>
	</p>
<?php else : ?>
	<p class="empty"><?php esc_html_e( 'Upload queue is empty', 'w3-total-cache' ); ?></p>
<?php endif; ?>
</div>

<div id="cdn_queue_delete" class="tab-content"<?php 'delete' !== $cdn_queue_tab ? ' style="display: none;"' : ''; ?>>
<?php if ( ! empty( $queue [ W3TC_CDN_COMMAND_DELETE ] ) ) : ?>
	<table class="table queue">
		<tr>
			<th><?php esc_html_e( 'Local Path', 'w3-total-cache' ); ?></th>
			<th><?php esc_html_e( 'Remote Path', 'w3-total-cache' ); ?></th>
			<th><?php esc_html_e( 'Last Error', 'w3-total-cache' ); ?></th>
			<th width="25%"><?php esc_html_e( 'Date', 'w3-total-cache' ); ?></th>
			<th width="10%"><?php esc_html_e( 'Delete', 'w3-total-cache' ); ?></th>
		</tr>
		<?php foreach ( (array) $queue[ W3TC_CDN_COMMAND_DELETE ] as $result ) : ?>
		<tr>
			<td><?php echo esc_html( $result->local_path ); ?></td>
			<td><?php echo esc_html( $result->remote_path ); ?></td>
			<td><?php echo esc_html( $result->last_error ); ?></td>
			<td align="center"><?php echo esc_html( $result->date ); ?></td>
			<td align="center">
				<a href="admin.php?page=w3tc_cdn&amp;w3tc_cdn_queue&amp;cdn_queue_tab=delete&amp;cdn_queue_action=delete&amp;cdn_queue_id=<?php echo esc_attr( $result->id ); ?>&amp;_wpnonce=<?php echo esc_attr( $nonce ); ?>" class="cdn_queue_delete"><?php esc_html_e( 'Delete', 'w3-total-cache' ); ?></a>
			</td>
		</tr>
		<?php endforeach; ?>
	</table>
	<p>
		<a href="admin.php?page=w3tc_cdn&amp;w3tc_cdn_queue&amp;cdn_queue_tab=delete&amp;cdn_queue_action=empty&amp;cdn_queue_type=<?php echo esc_attr( W3TC_CDN_COMMAND_DELETE ); ?>&amp;_wpnonce=<?php echo esc_attr( $nonce ); ?>" class="cdn_queue_empty"><?php esc_html_e( 'Empty delete queue', 'w3-total-cache' ); ?></a>
	</p>
<?php else : ?>
	<p class="empty"><?php esc_html_e( 'Delete queue is empty', 'w3-total-cache' ); ?></p>
<?php endif; ?>
</div>

<div id="cdn_queue_purge" class="tab-content"<?php 'purge' !== $cdn_queue_tab ? ' style="display: none;"' : ''; ?>>
<?php if ( ! empty( $queue[ W3TC_CDN_COMMAND_PURGE ] ) ) : ?>
	<table class="table queue">
		<tr>
			<th><?php esc_html_e( 'Local Path', 'w3-total-cache' ); ?></th>
			<th><?php esc_html_e( 'Remote Path', 'w3-total-cache' ); ?></th>
			<th><?php esc_html_e( 'Last Error', 'w3-total-cache' ); ?></th>
			<th width="25%"><?php esc_html_e( 'Date', 'w3-total-cache' ); ?></th>
			<th width="10%"><?php esc_html_e( 'Delete', 'w3-total-cache' ); ?></th>
		</tr>
		<?php foreach ( (array) $queue[ W3TC_CDN_COMMAND_PURGE ] as $result ) : ?>
		<tr>
			<td><?php echo esc_html( $result->local_path ); ?></td>
			<td><?php echo esc_html( $result->remote_path ); ?></td>
			<td><?php echo esc_html( $result->last_error ); ?></td>
			<td align="center"><?php echo esc_html( $result->date ); ?></td>
			<td align="center">
				<a href="admin.php?page=w3tc_cdn&amp;w3tc_cdn_queue&amp;cdn_queue_tab=purge&amp;cdn_queue_action=delete&amp;cdn_queue_id=<?php echo esc_attr( $result->id ); ?>&amp;_wpnonce=<?php echo esc_attr( $nonce ); ?>" class="cdn_queue_delete"><?php esc_html_e( 'Delete', 'w3-total-cache' ); ?></a>
			</td>
		</tr>
		<?php endforeach; ?>
	</table>
	<p>
		<a href="admin.php?page=w3tc_cdn&amp;w3tc_cdn_queue&amp;cdn_queue_tab=purge&amp;cdn_queue_action=empty&amp;cdn_queue_type=<?php echo esc_attr( W3TC_CDN_COMMAND_PURGE ); ?>&amp;_wpnonce=<?php echo esc_attr( $nonce ); ?>" class="cdn_queue_empty"><?php esc_html_e( 'Empty purge queue', 'w3-total-cache' ); ?></a>
	</p>
<?php else : ?>
	<p class="empty"><?php esc_html_e( 'Purge queue is empty', 'w3-total-cache' ); ?></p>
<?php endif; ?>
</div>

<?php require W3TC_INC_DIR . '/popup/common/footer.php'; ?>
