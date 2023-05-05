<?php
namespace W3TC;

if ( !defined( 'W3TC' ) )
	die();

Util_Ui::postbox_header( 'Statistics', '', 'stats' );

$c = Dispatcher::config();
$is_pro = Util_Environment::is_w3tc_pro( $c );

?>

<table class="<?php echo esc_attr( Util_Ui::table_class() ); ?>">
	<?php
Util_Ui::config_item_pro( array(
		'key' => 'stats.enabled',
		'label' => esc_html__( 'Cache usage statistics', 'w3-total-cache' ),
		'control' => 'checkbox',
		'checkbox_label' => __( 'Enable', 'w3-total-cache' ),
		'disabled' => ( $is_pro ? null : true ),
		'excerpt' => __( 'Enable statistics collection. Note that this consumes additional resources and is not recommended to be run continuously.',
			'w3-total-cache' ),
		'description' => array(
			__( 'Statistics provides near-complete transparency into the behavior of your caching performance, allowing you to identify opportunities to further improve your website speed and ensure operations are working as expected. Includes metrics like cache sizes, object lifetimes, hit vs miss ratio, etc across every caching method configured in your settings.', 'w3-total-cache' ),
			__( 'Some statistics are available directly on your Performance Dashboard, however, the comprehensive suite of statistics are available on the Statistics screen. Web server logs created by Nginx or Apache can be analyzed if accessible.', 'w3-total-cache' ),
			wp_kses(
				sprintf(
					// translators: 1 The opening anchor tag linking to our support page, 2 its closing tag.
					__( 'Use the caching statistics to compare the performance of different configurations like caching methods, object lifetimes and so on. Did you know that we offer premium support, customization and audit services? %1$sClick here for more information%2$s.', 'w3-total-cache' ),
					'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_support' ) ) . '">',
					'</a>'
				),
				array( 'a' => array( 'href' => array() ) )
			),
		),
	) );
Util_Ui::config_item( array(
		'key' => 'stats.slot_seconds',
		'label' => __( 'Slot time (seconds):', 'w3-total-cache' ),
		'control' => 'textbox',
		'textbox_type' => 'number',
		'description' => __( 'The duration of time in seconds to collect statistics per interval.', 'w3-total-cache' ),
		'show_in_free' => false,
	) );
Util_Ui::config_item( array(
		'key' => 'stats.slots_count',
		'label' => __( 'Slots collected:', 'w3-total-cache' ),
		'control' => 'textbox',
		'textbox_type' => 'number',
		'description' => __( 'The number of intervals that are represented in the graph.', 'w3-total-cache' ),
		'show_in_free' => false,
	) );

Util_Ui::config_item( array(
		'key' => 'stats.cpu.enabled',
		'control' => 'checkbox',
		'checkbox_label' => __( 'Use the system reported averages of CPU resource usage.', 'w3-total-cache' ),
		'description' => __( 'Collect CPU usage', 'w3-total-cache' ),
		'show_in_free' => false,
	) );
Util_Ui::config_item( array(
		'key' => 'stats.access_log.enabled',
		'control' => 'checkbox',
		'checkbox_label' => __( 'Parse server access log', 'w3-total-cache' ),
		'disabled' => ( $is_pro ? null : true ),
		'description' => __( 'Enable collecting statistics from an Access Log.  This provides much more precise statistics.', 'w3-total-cache' ),
		'show_in_free' => false,
	) );
Util_Ui::config_item( array(
		'key' => 'stats.access_log.webserver',
		'label' => __( 'Webserver:', 'w3-total-cache' ),
		'control' => 'selectbox',
		'selectbox_values' => array(
			'apache' => 'Apache',
			'nginx' => 'Nginx'
		),
		'description' =>  __( 'Webserver type generating access logs.' ,'w3-total-cache' ),
		'show_in_free' => false,
	) );
Util_Ui::config_item( array(
		'key' => 'stats.access_log.filename',
		'label' => __( 'Access Log Filename:', 'w3-total-cache' ),
		'control' => 'textbox',
		'textbox_size' => 60,
		'description' => __( 'Where your access log is located.', 'w3-total-cache' ),
		'control_after' =>
			'<input type="button" class="button" id="ustats_access_log_test" value="Test" /><span id="ustats_access_log_test_result" style="padding-left: 20px"></span>',
		'show_in_free' => false,
	) );
Util_Ui::config_item( array(
		'key' => 'stats.access_log.format',
		'label' => __( 'Access Log Format:', 'w3-total-cache' ),
		'control' => 'textbox',
		'textbox_size' => 60,
		'description' =>  __( 'Format of your access log from webserver configuration.', 'w3-total-cache' ),
		'control_after' =>
			'<input type="button" class="button" id="ustats_access_log_format_reset" value="Reset to Default" />',
		'show_in_free' => false,
	) );
?>
</table>

<?php
Util_Ui::button_config_save( 'stats' );
?>
<?php Util_Ui::postbox_footer(); ?>

<script>
jQuery('#ustats_access_log_format_reset').click(function() {
	var webserver = jQuery('#stats__access_log__webserver').val();

	var v;
	if (webserver == 'nginx') {
		v = '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
	} else {
		v = '%h %l %u %t \\"%r\\" %>s %O \\"%{Referer}i\\" \\"%{User-Agent}i\\"';
	}
	jQuery('#stats__access_log__format').val(v);
});

jQuery('#ustats_access_log_test').click(function() {
	var params = {
		action: 'ustats_access_log_test',
		_wpnonce: w3tc_nonce,
		w3tc_action: 'ustats_access_log_test',
		filename: jQuery('#stats__access_log__filename').val()
	};

	jQuery.post(ajaxurl, params, function(data) {
		jQuery('#ustats_access_log_test_result').text(data);
	}).fail(function() {
		jQuery('#ustats_access_log_test_result').text('Check failed');
	});
});
</script>
