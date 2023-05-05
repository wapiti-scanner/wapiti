<?php
namespace W3TC;

if ( !defined( 'W3TC' ) )
	die();

?>
<tr>
	<th><label for="w3tc_dbcluster_config">Database cluster:</th>
	<td>
		<input type="submit" id="w3tc_dbcluster_config" name="w3tc_dbcluster_config" class="button"
			   value="<?php echo Util_Environment::is_dbcluster() ? 'Edit Database Cluster Configuration' : 'Enable database cluster'; ?>" />
		<p class="description">Create db-cluster-config.php file with your database cluster configuration to enable it.</p>
	</td>
</tr>
