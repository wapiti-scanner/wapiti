<?php
/**
 * General body template.
 *
 * This template can be overridden by copying it to yourtheme/wpforms/emails/general-body.php.
 *
 * @since 1.5.4
 *
 * @version 1.5.4
 *
 * @var string $message
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

?>

<table>
	<tbody>
	<tr>
		<td>
			<?php echo \wp_kses_post( $message ); ?>
		</td>
	</tr>
	</tbody>
</table>
