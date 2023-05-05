<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

if ( is_null( $stats ) ) :
	esc_html_e( 'You have not configured well email, API token / global key or domain', 'w3-total-cache' );
else :
	?>
	<p class="cloudflare_p">
		Period
		<?php
		if ( $stats['interval'] >= -1440 ) {
			echo esc_html( $this->date_time( $stats['since'] ) );
		} else {
			echo esc_html( $this->date( $stats['since'] ) );
		}

		echo ' - ';

		if ( $stats['interval'] >= -1440 ) {
			echo esc_html( $this->date_time( $stats['until'] ) );
		} else {
			echo esc_html( $this->date( $stats['until'] ) );
		}
		?>
	</p>
	<table class="cloudflare_table">
		<tr>
			<td></td>
			<td class="cloudflare_td_header">All</td>
			<td class="cloudflare_td_header">Cached</td>
		</tr>
		<tr>
			<td class="cloudflare_td">Bandwidth</td>
			<?php $this->value( $stats['bandwidth_all'] ); ?>
			<?php $this->value( $stats['bandwidth_cached'] ); ?>
		</tr>
		<tr>
			<td class="cloudflare_td">Requests</td>
			<?php $this->value( $stats['requests_all'] ); ?>
			<?php $this->value( $stats['requests_cached'] ); ?>
		</tr>
		<tr>
			<td class="cloudflare_td">Page Views</td>
			<?php $this->value( $stats['pageviews_all'] ); ?>
		</tr>
		<tr>
			<td class="cloudflare_td">Uniques</td>
			<?php $this->value( $stats['uniques_all'] ); ?>
		</tr>
		<tr>
			<td class="cloudflare_td">Threats</td>
			<?php $this->value( $stats['threats_all'] ); ?>
		</tr>
	</table>
	<p class="cloudflare_p"><small>Statistics cached for <?php $this->value( $stats['cached_tf'] ); ?> minutes on <?php $this->date_time( $stats['cached_ts'] ); ?></small></p>
<?php endif; ?>
