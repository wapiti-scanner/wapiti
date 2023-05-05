<?php
namespace W3TC;



class Cdn_RackSpaceCdn_AdminActions {
	function w3tc_cdn_rackspace_cdn_domains_reload() {
		$c = Dispatcher::config();
		$core = Dispatcher::component( 'Cdn_Core' );
		$cdn = $core->get_cdn();

		try {
			// try to obtain CNAMEs
			$domains = $cdn->service_domains_get();
		} catch ( \Exception $ex ) {
			Util_Admin::redirect_with_custom_messages2( array(
					'errors' => array( 'Failed to obtain <acronym title="Canonical Name">CNAME</acronym>s: ' . $ex->getMessage() )
				), true );
			return;
		}

		$c->set( 'cdn.rackspace_cdn.domains', $domains );
		$c->save();

		Util_Admin::redirect_with_custom_messages2( array(
				'notes' => array( 'CNAMEs are reloaded successfully' )
			), true );
	}
}
