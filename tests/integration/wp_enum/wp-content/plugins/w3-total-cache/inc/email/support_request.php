<?php
if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<html>
	<head></head>
	<body>
		<p>
			<?php
			echo esc_html__( 'Date:', 'w3-total-cache' ) . esc_html( gmdate( 'm/d/Y H:i:s' ) ) . '<br />';
			echo esc_html__( 'Version: ', 'w3-total-cache' ) . esc_html( W3TC_VERSION ) . '<br />';
			echo esc_html__( 'URL: ', 'w3-total-cache' ) . '<a href="' . esc_url( $url ) . '">' . esc_html( $url ) . '</a><br />';
			echo esc_html__( 'Name: ', 'w3-total-cache' ) . esc_html( $name ) . '<br />';
			echo esc_html__( 'E-Mail: ', 'w3-total-cache' ) . '<a href="mailto:' . esc_attr( $email ) . '">' . esc_html( $email ) . '</a><br />';

			if ( $twitter ) {
				echo esc_html__( 'Twitter: ', 'w3-total-cache' ) . '<a href="http://twitter.com/' . esc_attr( $twitter ) . '">' . esc_html( $twitter ) . '</a><br />';
			}

			if ( $phone ) {
				echo esc_html__( 'Phone: ', 'w3-total-cache' ) . esc_html( $phone ) . '<br />';
			}

			if ( $forum_url ) {
				echo esc_html__( 'Forum Topic URL: ', 'w3-total-cache' ) . '<a href="' . esc_url( $forum_url ) . '">' . esc_url( $forum_url ) . '</a><br />';
			}

			if ( $request_data_url ) {
				echo esc_html__( 'Request data: ', 'w3-total-cache' ) . '<a href="' . esc_url( $request_data_url ) . '">' . esc_url( $request_data_url ) . '</a><br />';
			}

			echo esc_html__( 'Subject: ', 'w3-total-cache' ) . esc_html( $subject );
			?>
		</p>

		<p>
			<?php echo nl2br( esc_html( $description ) ); ?>
		</p>

		<hr />

		<font size="-1" color="#ccc">
			<?php
			echo esc_html__( 'E-mail sent from IP: ', 'w3-total-cache' ) . esc_html( $_SERVER['REMOTE_ADDR'] ) . '<br />';
			echo esc_html__( 'User Agent: ', 'w3-total-cache' ) . esc_html( $_SERVER['HTTP_USER_AGENT'] );
			?>
		</font>
	</body>
</html>
