<?php
/**
 * Email form field entry.
 *
 * This is used with the {all_fields} smart tag.
 *
 * @since 1.1.3
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<table align="left" border="0" cellpadding="0" cellspacing="0" width="100%" style="border-top:1px solid #dddddd; display:block;min-width: 100%;border-collapse: collapse;width:100%;"><tbody>
	<tr><td style="color:#333333;padding-top: 20px;padding-bottom: 3px;"><strong>{field_name}</strong></td></tr>
	<tr><td style="color:#555555;padding-top: 3px;padding-bottom: 20px;">{field_value}</td></tr>
</tbody></table>
