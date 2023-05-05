<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<ol id="cdn_cnames" style="margin: 0">
<?php
if ( ! count( $cnames ) ) {
	$cnames = array( '' );
}

$count = count( $cnames );
if ( isset( $cnames['http_default'] ) ) {
	$count--;
}
if ( isset( $cnames['https_default'] ) ) {
	$count--;
}

$real_index = 0;
foreach ( $cnames as $index => $cname ) :
	if ( 'http_default' === $index || 'https_default' === $index ) {
		continue;
	}

	$label = '';

	if ( $count > 1 ) :
		switch ( $real_index ) :
			case 0:
				$label = __( '(reserved for CSS)', 'w3-total-cache' );
				break;

			case 1:
				$label = __( '(reserved for JS in <head>)', 'w3-total-cache' );
				break;

			case 2:
				$label = __( '(reserved for JS after <body>)', 'w3-total-cache' );
				break;

			case 3:
				$label = __( '(reserved for JS before </body>)', 'w3-total-cache' );
				break;

			default:
				$label = '';
				break;
		endswitch;
	endif;
	?>
	<li>
		<input type="text" name="cdn_cnames[]" id="cdn_cnames_<?php echo esc_attr( $real_index ); ?>"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> value="<?php echo esc_attr( $cname ); ?>" size="60" />
		<input class="button cdn_cname_delete" type="button"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> value="<?php esc_attr_e( 'Delete', 'w3-total-cache' ); ?>"<?php echo ! $index ? ' style="display: none;"' : ''; ?> />
		<span><?php echo esc_html( $label ); ?></span>
	</li>
	<?php
	$real_index++;
	endforeach;
?>
</ol>
<input id="cdn_cname_add" class="button" type="button" value="<?php esc_attr_e( 'Add CNAME', 'w3-total-cache' ); ?>"
	<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> />
