<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

require W3TC_INC_DIR . '/options/common/header.php';
?>
<div class="metabox-holder">
	<?php Util_Ui::postbox_header( esc_html__( 'Usage Statistics', 'w3-total-cache' ) ); ?>

	<div style="float: right"><a href="admin.php?page=w3tc_stats"><?php esc_html_e( '&lt; Back To Statistics', 'w3-total-cache' ); ?></a></div>
	<h1><?php esc_html_e( 'Page Cache Reject Requests for ', 'w3-total-cache' ); ?><?php echo esc_html( isset( $_REQUEST['status_name'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['status_name'] ) ) : '' ); ?></h1>
	<p>
		<?php esc_html_e( 'Period', 'w3-total-cache' ); ?>
		<?php echo esc_html( $result['date_min'] ); ?>
		-
		<?php echo esc_html( $result['date_max'] ); ?>
	</p>

	<table style="width: 100%">
		<tr>
			<td><?php $this->sort_link( $result, 'URI', 'uri' ); ?></td>
			<td><?php $this->sort_link( $result, 'Count', 'count' ); ?></td>
			<td><?php $this->sort_link( $result, 'Total processed time (ms)', 'sum_time_ms' ); ?></td>
			<td><?php $this->sort_link( $result, 'Avg Processed time (ms)', 'avg_time_ms' ); ?></td>
			<td><?php $this->sort_link( $result, 'Avg Size', 'avg_size' ); ?></td>
		</tr>
	<?php foreach ( $result['items'] as $i ) : ?>
		<tr>
			<td title="<?php echo esc_attr__( 'Reject reasons: ', 'w3-total-cache' ) . esc_attr( implode( ',', $i['reasons'] ) ); ?>"><?php echo esc_html( $i['uri'] ); ?></td>
			<td><?php echo esc_html( $i['count'] ); ?></td>
			<td><?php echo esc_html( $i['sum_time_ms'] ); ?></td>
			<td><?php echo esc_html( $i['avg_time_ms'] ); ?></td>
			<td><?php echo 0 === $i['avg_size'] ? 'n/a' : esc_html( $i['avg_size'] ); ?></td>
		</tr>
	<?php endforeach ?>
	</table>

	<?php Util_Ui::postbox_footer(); ?>
</div>
