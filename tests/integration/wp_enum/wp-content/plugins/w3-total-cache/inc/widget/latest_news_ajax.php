<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php foreach ( $items as $item ) : ?>
<h4>
	<a href="<?php echo esc_url( $item['link'] ); ?>">
		<?php echo esc_html( wp_strip_all_tags( $item['title'] ) ); ?>
	</a>
</h4>
<?php endforeach ?>

<p style="text-align: center;">
	<a href="<?php echo esc_url( W3TC_NEWS_FEED_URL ); ?>" target="_blank">View Feed</a>
</p>
