<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<p><?php esc_html_e( 'Enjoying W3TC? Please support us!', 'w3-total-cache' ); ?></p>
<ul>
	<li>
		<label><?php esc_html_e( 'Vote:', 'w3-total-cache' ); ?></label>
		<input type="button" class="button button-vote" value="Give us a 5 stars!" />
	</li>
</ul>

<p>
	<?php esc_html_e( 'Or please share', 'w3-total-cache' ); ?> 
	<a href="admin.php?page=w3tc_support&amp;request_type=new_feature">your feedback</a>
	so that we can improve!
</p>
